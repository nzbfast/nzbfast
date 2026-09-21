//! Fixture, regression and property tests for the RAR 1.5 codec.
//!
//! These replaced the differential tests against the old implementation
//! once that oracle was removed: every fixture member and 1,000,000 seeded
//! fuzz cases had matched it, and the encoder's output had been
//! byte-identical over 25 option sets. What they keep is what does not need
//! the oracle: fixture members through every entry point, the solid
//! repeat-counter fix, the fresh-decoder solid ruling, round trips and a
//! seeded no-panic fuzz.

use super::{decode_rar15, EncodeOptions, Rar15Decoder, Rar15Encoder};
use crate::crypto::rar13::Rar13Cipher;
use std::io::Read;
use std::path::PathBuf;

fn fixture(path: &str) -> Vec<u8> {
    let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path);
    std::fs::read(&full).unwrap_or_else(|error| panic!("{}: {error}", full.display()))
}

/// One member of a decode chain.
#[derive(Clone)]
struct Member {
    name: String,
    packed: Vec<u8>,
    size: usize,
    solid: bool,
}

/// The RAR 1.5 algorithm members of a RAR 1.3 archive, in extraction order,
/// with the container's solid rule.
fn rar13_chain(path: &str, password: Option<&[u8]>) -> Vec<Member> {
    let bytes = fixture(path);
    let archive = crate::rar13::Archive::parse(&bytes).unwrap();
    let solid_archive = archive.main.is_solid();
    let mut chain = Vec::new();
    let mut extracted = 0usize;
    if archive.main.has_packed_comment() {
        let extra = &archive.main.extra;
        let length = usize::from(u16::from_le_bytes([extra[0], extra[1]]));
        let size = usize::from(u16::from_le_bytes([extra[2], extra[3]]));
        let mut packed = extra[4..4 + length - 2].to_vec();
        Rar13Cipher::new_comment().decrypt_in_place(&mut packed);
        chain.push(Member {
            name: format!("{path}:comment"),
            packed,
            size,
            solid: false,
        });
    }
    for entry in &archive.entries {
        if entry.is_split_before() || entry.is_split_after() {
            continue;
        }
        if entry.is_stored() {
            extracted += 1;
            continue;
        }
        let mut packed = entry.packed_data(&archive).unwrap().to_vec();
        if entry.is_encrypted() {
            Rar13Cipher::new(password.expect("fixture password")).decrypt_in_place(&mut packed);
        }
        chain.push(Member {
            name: format!("{path}:{}", String::from_utf8_lossy(&entry.name)),
            packed,
            size: entry.header.unp_size as usize,
            solid: solid_archive && extracted != 0,
        });
        extracted += 1;
    }
    chain
}

/// A RAR 1.3 member split over volumes, joined.
fn rar13_joined(paths: &[&str]) -> Vec<Member> {
    let mut packed = Vec::new();
    let mut size = 0;
    for path in paths {
        let bytes = fixture(path);
        let archive = crate::rar13::Archive::parse(&bytes).unwrap();
        for entry in &archive.entries {
            if entry.is_split_before() || entry.is_split_after() {
                packed.extend_from_slice(entry.packed_data(&archive).unwrap());
                size = entry.header.unp_size as usize;
            }
        }
    }
    vec![Member {
        name: paths[0].to_string(),
        packed,
        size,
        solid: false,
    }]
}

/// The unpack-version-15 members of a RAR 1.5-4.x archive.
fn rar15_chain(path: &str, password: Option<&[u8]>) -> Vec<Member> {
    let bytes = fixture(path);
    let archive = crate::rar15_40::Archive::parse(&bytes).unwrap();
    let mut chain = Vec::new();
    for file in archive.files() {
        if file.is_directory()
            || file.is_stored()
            || file.is_split_before()
            || file.is_split_after()
            || file.unp_ver != 15
        {
            continue;
        }
        let packed = if file.is_encrypted() {
            let mut reader = file.packed_reader_for_decode(&archive, password).unwrap();
            let mut packed = Vec::new();
            reader.read_to_end(&mut packed).unwrap();
            packed
        } else {
            file.packed_data(&archive).unwrap()
        };
        chain.push(Member {
            name: format!("{path}:{}", String::from_utf8_lossy(&file.name)),
            packed,
            size: file.unp_size as usize,
            solid: file.is_solid(),
        });
    }
    chain
}

fn rar15_joined(paths: &[&str]) -> Vec<Member> {
    let mut packed = Vec::new();
    let mut size = 0;
    for path in paths {
        let bytes = fixture(path);
        let archive = crate::rar15_40::Archive::parse(&bytes).unwrap();
        let file = archive.files().next().unwrap();
        packed.extend_from_slice(&file.packed_data(&archive).unwrap());
        size = file.unp_size as usize;
    }
    vec![Member {
        name: paths[0].to_string(),
        packed,
        size,
        solid: false,
    }]
}

fn fixture_chains() -> Vec<Vec<Member>> {
    let mut chains = vec![
        rar13_chain("rar13/README.RAR", None),
        rar13_chain("rar13/README_password=password.rar", Some(b"password")),
        rar13_chain("rar13/BIG80K.RAR", None),
        rar13_chain("rar13/REPEATB.RAR", None),
        rar13_chain("rar13/SOLID.RAR", None),
        rar13_chain("rar13/COMMENT.RAR", None),
        rar13_joined(&[
            "rar13/CMULTIV.RAR",
            "rar13/CMULTIV.R00",
            "rar13/CMULTIV.R01",
            "rar13/CMULTIV.R02",
            "rar13/CMULTIV.R03",
            "rar13/CMULTIV.R04",
            "rar13/CMULTIV.R05",
            "rar13/CMULTIV.R06",
        ]),
        rar15_chain("rar15_40/rar154/readme_154_normal.rar", None),
        rar15_chain("rar15_40/rar154/readme_154_password.rar", Some(b"password")),
        rar15_chain("rar15_40/rar154/readme_154_store_solid.rar", None),
        rar15_chain("rar15_40/rar154/doc_154_best.rar", None),
        rar15_chain("rar15_40/rar154/audio_win_names_unpack15.rar", None),
        rar15_chain("rar15_40/rar154/audio_dos_names_unpack15.rar", None),
        rar15_joined(&[
            "rar15_40/rar154/random.rar",
            "rar15_40/rar154/random.r00",
            "rar15_40/rar154/random.r01",
        ]),
        rar15_chain("rar15_40/rars_generated/compressed.rar", None),
        rar15_chain("rar15_40/rars_generated/solid.rar", None),
        rar15_chain("rar15_40/rars_generated/comments.rar", None),
        rar15_chain("rar15_40/rars_generated/encrypted.rar", Some(b"pass")),
    ];
    chains.retain(|chain| !chain.is_empty());
    chains
}

/// Returns one to three bytes per call.
struct Dribble<'a> {
    data: &'a [u8],
    step: usize,
}

impl Read for Dribble<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.step = self.step % 3 + 1;
        let len = self.data.len().min(out.len()).min(self.step);
        out[..len].copy_from_slice(&self.data[..len]);
        self.data = &self.data[len..];
        Ok(len)
    }
}

/// Decodes one member through entry point 0 (slice to `Vec`), 1 (slice to
/// writer) or 2 (a reader handing out one to three bytes, to a writer).
fn run(
    decoder: &mut Rar15Decoder,
    entry: usize,
    packed: &[u8],
    size: usize,
    solid: bool,
) -> crate::codec::Result<Vec<u8>> {
    match entry {
        0 => decoder.decode_member(packed, size, solid),
        1 => {
            let mut out = Vec::new();
            decoder
                .decode_member_to(packed, size, solid, &mut out)
                .map(|()| out)
        }
        _ => {
            let mut out = Vec::new();
            let mut reader = Dribble {
                data: packed,
                step: size,
            };
            decoder
                .decode_member_from_reader(&mut reader, size, solid, &mut out)
                .map(|()| out)
        }
    }
}

#[test]
fn every_fixture_member_decodes_the_same_through_all_entry_points() {
    let mut members = 0;
    for chain in fixture_chains() {
        let mut decoders = [
            Rar15Decoder::new(),
            Rar15Decoder::new(),
            Rar15Decoder::new(),
        ];
        for member in &chain {
            let outputs: Vec<Vec<u8>> = decoders
                .iter_mut()
                .enumerate()
                .map(|(entry, decoder)| {
                    run(decoder, entry, &member.packed, member.size, member.solid)
                        .unwrap_or_else(|error| panic!("{} via {entry}: {error}", member.name))
                })
                .collect();
            assert_eq!(outputs[0].len(), member.size, "{}", member.name);
            assert!(
                outputs[1] == outputs[0] && outputs[2] == outputs[0],
                "{}: entry points disagree",
                member.name
            );
            members += 1;
        }
    }
    assert!(members >= 30, "only {members} fixture members decoded");
}

/// Owner ruling, 15 Sep 2026: a new decoder is in the full-reset state
/// (specification table 3.2), so a solid member handed to it decodes
/// exactly as a non-solid one. The old implementation's fresh state was not
/// its reset state and decoded this input to zeros and errors; neither
/// container reaches the case, because both decode their first member
/// non-solid.
#[test]
fn a_solid_member_on_a_fresh_decoder_decodes_as_non_solid() {
    for chain in fixture_chains() {
        let first = &chain[0];
        let non_solid = Rar15Decoder::new()
            .decode_member(&first.packed, first.size, false)
            .unwrap();
        let solid = Rar15Decoder::new()
            .decode_member(&first.packed, first.size, true)
            .unwrap();
        assert!(solid == non_solid, "{}", first.name);
    }
    let comment = &rar13_chain("rar13/COMMENT.RAR", None)[0];
    assert_eq!(
        Rar15Decoder::new()
            .decode_member(&comment.packed, comment.size, true)
            .unwrap(),
        b"This is the archive comment.\r\n"
    );
}

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn target(&mut self) -> usize {
        match self.below(10) {
            0..=6 => self.below(4097),
            7..=8 => self.below(32_769),
            _ => self.below(200_001),
        }
    }
}

/// Corrupt and random members through the slice and reader paths: no
/// panic, exactly `target` bytes on success, and the two paths agree.
fn fuzz_new_decoder(seed: u64, cases: usize) -> usize {
    let pool: Vec<Member> = fixture_chains()
        .into_iter()
        .flatten()
        .filter(|member| member.size <= 200_000)
        .collect();
    let mut rng = Rng(seed | 1);
    let mut decoded = 0;
    for _ in 0..cases {
        let chain_len = if rng.below(4) == 0 {
            2 + rng.below(4)
        } else {
            1
        };
        let mut by_slice = Rar15Decoder::new();
        let mut by_reader = Rar15Decoder::new();
        for position in 0..chain_len {
            let (packed, target) = match rng.below(4) {
                0 => {
                    let len = rng.below(4097);
                    (rng.bytes(len), rng.target())
                }
                1 => {
                    let fill = if rng.below(2) == 0 { 0xff } else { 0x00 };
                    let mut packed = vec![fill; 1 + rng.below(256)];
                    let tail = rng.below(257);
                    packed.extend(rng.bytes(tail));
                    (packed, rng.target())
                }
                _ => {
                    let member = &pool[rng.below(pool.len())];
                    let mut packed = member.packed.clone();
                    if !packed.is_empty() {
                        for _ in 0..1 + rng.below(8) {
                            let bit = rng.below(packed.len() * 8);
                            packed[bit / 8] ^= 1 << (bit % 8);
                        }
                        if rng.below(3) == 0 {
                            packed.truncate(rng.below(packed.len()));
                        }
                    }
                    (packed, member.size)
                }
            };
            let solid = position > 0 && rng.below(2) == 0;
            let sliced = run(&mut by_slice, 0, &packed, target, solid);
            let streamed = run(&mut by_reader, 2, &packed, target, solid);
            decoded += 1;
            match (sliced, streamed) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a.len(), target);
                    assert!(a == b, "slice and reader paths disagree");
                }
                (Err(_), Err(_)) => break,
                (a, b) => panic!(
                    "slice {:?} vs reader {:?}",
                    a.map(|v| v.len()),
                    b.map(|v| v.len())
                ),
            }
        }
    }
    decoded
}

#[test]
fn seeded_fuzz_never_panics_and_entry_points_agree() {
    assert!(fuzz_new_decoder(0x5eed_a15a, 2_000) >= 2_000);
}

/// Encodes `inputs` as one solid chain and decodes it back.
fn solid_round_trip(inputs: &[Vec<u8>], options: EncodeOptions) -> bool {
    let mut encoder = Rar15Encoder::with_options(options);
    let mut decoder = Rar15Decoder::new();
    inputs.iter().enumerate().all(|(index, input)| {
        let packed = encoder.encode_member(input).unwrap();
        decoder
            .decode_member(&packed, input.len(), index > 0)
            .ok()
            .as_ref()
            == Some(input)
    })
}

/// Specification 5.3.3: each solid member starts with the decoder's member
/// reset, so a first member ending on two repeats in a row no longer leaves
/// REPEATS at 2 for the next one (the old encoder then wrote an escape bit
/// the decoder does not read, and the chain desynchronised).
#[test]
fn solid_encoding_resets_the_repeat_counter_between_members() {
    let options = EncodeOptions::default();
    let mut reached = 0;
    for period in [3usize, 5, 8] {
        for extra in 0..24 {
            let pattern: Vec<u8> = (0..period).map(|i| b'a' + i as u8).collect();
            let first: Vec<u8> = pattern
                .iter()
                .copied()
                .cycle()
                .take(4 * period + extra)
                .collect();
            let mut probe = Rar15Encoder::with_options(options);
            probe.encode_member(&first).unwrap();
            if probe.model.repeats() != 2 {
                continue;
            }
            reached += 1;
            let second = b"qrstuvwxyz0123qrstuvw".to_vec();
            assert!(
                solid_round_trip(&[first, second], options),
                "period {period}, extra {extra}"
            );
        }
    }
    assert!(reached > 0, "no case ended its first member on two repeats");
}

#[test]
fn random_inputs_and_options_round_trip_including_solid_chains() {
    let mut rng = Rng(0xab5e);
    for _ in 0..40 {
        let options = EncodeOptions::new()
            .with_old_distance_tokens(rng.below(2) == 0)
            .with_lazy_matching(rng.below(2) == 0)
            .with_stmode_literal_runs(rng.below(2) == 0)
            .with_max_long_match_distance([0, 4096, 16_384, 0x7fff][rng.below(4)]);
        let inputs: Vec<Vec<u8>> = (0..1 + rng.below(3))
            .map(|_| {
                if rng.below(2) == 0 {
                    let len = 1 + rng.below(6000);
                    rng.bytes(len)
                } else {
                    let words: [&[u8]; 6] =
                        [b"member ", b"window ", b"the ", b"slot ", b"rank\n", b"of "];
                    let mut text = Vec::new();
                    for _ in 0..1 + rng.below(3000) {
                        text.extend_from_slice(words[rng.below(words.len())]);
                    }
                    text
                }
            })
            .collect();
        assert!(solid_round_trip(&inputs, options), "{options:?}");
    }
    let packed = super::encode_rar15(b"one-shot").unwrap();
    assert_eq!(decode_rar15(&packed, 8).unwrap(), b"one-shot");
}

/// Writes the fuzz seeds: each fixture chain, up to four members, in the
/// fuzz crate's input format (`fuzz/fuzz_targets/input.rs`).
/// `cargo test -p rars --lib --features parallel -- --ignored write_rar15_fuzz_seeds`
#[test]
#[ignore]
fn write_rar15_fuzz_seeds() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/rar15");
    std::fs::create_dir_all(&dir).unwrap();
    for (index, chain) in fixture_chains().into_iter().enumerate() {
        let members: Vec<&Member> = chain
            .iter()
            .take_while(|member| member.packed.len() <= 0xffff && member.size <= 1 << 20)
            .take(4)
            .collect();
        if members.is_empty() {
            continue;
        }
        let mut seed = vec![(members.len() - 1) as u8];
        for (position, member) in members.iter().enumerate() {
            if member.solid {
                seed[0] |= 0x10 << position;
            }
        }
        for (position, member) in members.iter().enumerate() {
            seed.extend_from_slice(&(member.size as u32).to_le_bytes()[..3]);
            if position + 1 < members.len() {
                seed.extend_from_slice(&(member.packed.len() as u16).to_le_bytes());
            }
            seed.extend_from_slice(&member.packed);
        }
        std::fs::write(dir.join(format!("chain{index:02}")), seed).unwrap();
    }
}

/// The decoded members of `doc_154_best.rar`: `RAR1~FHU.MD` and the member
/// after it.
fn fhu_and_next() -> [Vec<u8>; 2] {
    let chain = rar15_chain("rar15_40/rar154/doc_154_best.rar", None);
    let mut decoder = Rar15Decoder::new();
    let decoded: Vec<(String, Vec<u8>)> = chain
        .iter()
        .map(|member| {
            let data = decoder
                .decode_member(&member.packed, member.size, member.solid)
                .unwrap();
            (member.name.clone(), data)
        })
        .collect();
    let hard = decoded
        .iter()
        .position(|(name, _)| name.ends_with(":RAR1~FHU.MD"))
        .expect("fixture member");
    [
        decoded[hard].1.clone(),
        decoded[(hard + 1) % decoded.len()].1.clone(),
    ]
}

/// Encodes `first` on a fresh encoder, requires at least one literal whose
/// flag straddles two flag bytes (spec A 4.4), and returns the stream.
fn straddling_stream(first: &[u8], options: EncodeOptions) -> Vec<u8> {
    let mut encoder = Rar15Encoder::with_options(options);
    let packed = encoder.encode_member(first).unwrap();
    assert!(
        !encoder.straddle_positions.is_empty(),
        "no straddled flag in the {}-byte member: the check tests nothing",
        first.len()
    );
    eprintln!(
        "{} bytes, {} packed, straddled flags at input positions {:?}",
        first.len(),
        packed.len(),
        encoder.straddle_positions
    );
    packed
}

/// Runs `$RARS_REFERENCE_RAR t` over `archive`, which must pass.
fn reference_tests_ok(reference: &std::ffi::OsStr, name: &str, archive: &[u8]) {
    let dir = std::env::temp_dir().join(format!("rars-rar15-straddle-ref-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, archive).unwrap();
    let output = std::process::Command::new(reference)
        .arg("t")
        .arg(&path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "reference rejected {name}: status={:?}\nstdout={stdout}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!(
        "{name}: {}",
        stdout
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
    );
    if std::env::var_os("RARS_KEEP_REFERENCE_ARCHIVE").is_none() {
        let _ = std::fs::remove_file(&path);
    }
}

/// A reader we did not write must accept a literal whose two flag bits span
/// two flag bytes, which the encoder writes since the fix for a flag group
/// closed with bit 7 unused (nzbfast's 15 Sep 2026 note on the RAR 1.5
/// encoder's non-round-trip, follow-up 1). Two inputs that used to fail, each through the writer whose level 3
/// failed on it, solid and not; each archive's first member must be exactly
/// the stream a fresh encoder writes with at least one straddle, so a writer
/// that fell back or a planner that stopped straddling fails here rather
/// than passing on a stream without the shape. Passed with RAR 7.23
/// (`rar t`) on 15 Sep 2026; it reads real RAR 1.3 archives
/// (`tests/fixtures/rar13`) and fails a corrupted one. Re-run it after any
/// planner change:
/// `RARS_REFERENCE_RAR=$(which rar) cargo test -p rars --lib --features parallel -- --ignored reference_rar_accepts_straddled -- --nocapture`
#[test]
#[ignore = "requires RARS_REFERENCE_RAR pointing at a RAR or UnRAR binary"]
fn reference_rar_accepts_straddled_literal_flags() {
    let Some(reference) = std::env::var_os("RARS_REFERENCE_RAR") else {
        return;
    };
    use crate::{ArchiveVersion, FeatureSet};

    // RAR 1.3 writer, level 3 (`rar15_encode_options_for_level` in rar13.rs).
    let [fhu, next] = fhu_and_next();
    let rar13_level3 = EncodeOptions::new()
        .with_old_distance_tokens(false)
        .with_lazy_matching(false)
        .with_max_long_match_distance(16 * 1024);
    let expected = straddling_stream(&fhu, rar13_level3);
    for solid in [false, true] {
        let mut features = FeatureSet::store_only();
        features.solid = solid;
        let options = crate::rar13::WriterOptions {
            target: ArchiveVersion::Rar14,
            features,
            compression_level: Some(3),
            ..crate::rar13::WriterOptions::default()
        };
        let entries =
            [(b"a.md", &fhu), (b"b.md", &next)].map(|(name, data)| crate::rar13::FileEntry {
                name,
                data,
                file_time: 0x5a21_0000,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            });
        let bytes = crate::rar13::write_compressed_archive(&entries, options).unwrap();
        assert_eq!(&bytes[..4], b"RE~^", "solid {solid}");
        let archive = crate::rar13::Archive::parse(&bytes).unwrap();
        assert_eq!(archive.main.is_solid(), solid);
        assert!(
            archive.entries[0].packed_data(&archive).unwrap() == expected.as_slice(),
            "RAR 1.3 writer, solid {solid}: first member is not the straddling stream"
        );
        reference_tests_ok(
            &reference,
            &format!("rar13-fhu-l3-solid-{solid}.rar"),
            &bytes,
        );
    }

    // RAR 1.5-4.x writer, level 3 (`rar15_encode_options_for_level` in
    // rar15_40/write.rs).
    let text = super::tests::generated_text(1890, 2926);
    let rar15_level3 = EncodeOptions::new()
        .with_lazy_matching(false)
        .with_max_long_match_distance(16 * 1024);
    let expected = straddling_stream(&text, rar15_level3);
    for solid in [false, true] {
        let mut features = FeatureSet::store_only();
        features.solid = solid;
        let options = crate::rar15_40::WriterOptions::new(ArchiveVersion::Rar15, features)
            .with_compression_level(3);
        let entries =
            [(b"a.md", &text), (b"b.md", &next)].map(|(name, data)| crate::rar15_40::FileEntry {
                name,
                data,
                file_time: 0x5a21_0000,
                file_attr: 0x20,
                host_os: 3,
                password: None,
                file_comment: None,
            });
        let bytes = crate::rar15_40::write_compressed_archive(&entries, options).unwrap();
        let archive = crate::rar15_40::Archive::parse(&bytes).unwrap();
        let first = archive.files().next().unwrap();
        assert_eq!(first.unp_ver, 15, "solid {solid}");
        assert!(
            first.packed_data(&archive).unwrap() == expected,
            "RAR 1.5-4.x writer, solid {solid}: first member is not the straddling stream"
        );
        reference_tests_ok(
            &reference,
            &format!("rar15-text1890-l3-solid-{solid}.rar"),
            &bytes,
        );
    }
}
