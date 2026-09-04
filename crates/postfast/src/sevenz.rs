//! The 7z half of the container plane (H1), over the vendored
//! `sevenz-rust2` writer.
//!
//! **The archives are written by a library, exactly as the RAR half is,
//! and never by hand.** `crate::container`'s header states the rule and
//! the reason; this module is the second writer it reaches for rather
//! than an exception to it. `vendor/sevenz-rust2` was already in the
//! tree - four crates read it - and its writer is behind the crate's
//! own `compress` feature, which the two nzbkit crates already turn on
//! in their dev-dependencies. So the 7z arm cost a feature flip and no
//! dependency decision, which is where
//! `research/POSTFAST-VS-NESTED-CORPUS-2026-09-03.md`'s H1 section
//! ("a vendored 7z or zip writer is a dependency decision") is now
//! stale. The ZIP arm still is one: `nzbkit::zip` reads and nothing in
//! the tree writes.
//!
//! # C4 and C5 cost a patch to that crate, and the patch is the point
//!
//! The 7z format encrypts and its writer takes a password, so an
//! encrypted profile was never a format gap. What blocked it was
//! REPRODUCIBILITY: `AesEncoderOptions::new` drew its salt and its
//! initialisation vector from `getrandom::fill`, so one profile plus one
//! seed emitted a different archive on every run and a catalog walk over
//! it would have failed on bytes carrying no meaning. That is the
//! identical blocker `rars::Entropy` answered for the RAR writers, and
//! `vendor/sevenz-rust2/src/write_entropy.rs` answers it the same way -
//! a caller-installed scope, `Os` still the default in both crates.
//! [`write_archive`] installs one per archive from the seed
//! `container.rs` draws for that nesting level.
//!
//! Until 4 Sep 2026 an encrypted 7z profile was refused BY NAME instead,
//! and for a day before that it was not refused at all: the writer was
//! handed no password, so it emitted an archive that opened for ANYONE
//! while the profile claimed C4, and `extract_kind` dropped the password
//! on the way back, so the round trip agreed with itself. Every test
//! that existed passed over it. That is why the control arm here is
//! `an_encrypted_archive_does_not_open_unpassworded` and not "the writer
//! returned Ok".
//!
//! # A 7z split set is the archive's own bytes, cut
//!
//! Unlike RAR, whose volumes each carry a header of their own, a
//! multi-volume 7z is the finished archive file cut into fixed-size
//! pieces named `<name>.7z.001`, `<name>.7z.002`, ... Concatenating
//! them reproduces the archive byte for byte, and part 2 onwards
//! carries no signature at all. So [`split_parts`] is not this module
//! assembling a container format by hand - the cut IS the format, and
//! the client reads it the same way
//! (`nzbfast_unpack::rarfix::sevenz::collect_sevenz_archives`, whose
//! `SplitParts` reads the ordered parts in place as one byte space).
//!
//! # Why a "compressed" 7z is a real C3 where a compressed RAR is not
//!
//! The RAR writers fall back to STORE per entry whenever compression
//! would not shrink it, silently, which is why
//! `crate::container::refuse_a_compressed_archive_that_stored` exists:
//! `[source]` bytes come off the ChaCha stream and are incompressible,
//! so a `rar-compressed` catalog row would be a stored archive wearing
//! a C3 label. The 7z writer does not do that. Its content method is
//! chosen once for the archive and recorded in the header, so an
//! LZMA2 archive over incompressible bytes is still an LZMA2 archive:
//! the client has to run the LZMA2 decoder to get a byte out of it,
//! which is what C3 is for. The archive comes out slightly LARGER than
//! the payload, and that is the honest cost of the shape rather than a
//! defect. [`declared_method`] is what makes the claim checkable, and
//! `container.rs` asserts it for the same reason it asserts the RAR
//! half: a fixture whose plane was never applied is the failure the
//! whole crate exists to refuse.

use std::io::Cursor;

use sevenz_rust2::{
    ArchiveEntry, ArchiveReader, ArchiveWriter, EncoderConfiguration, EncoderMethod, Entropy,
    EntropyScope, Password, encoder_options::AesEncoderOptions,
};

/// Whether an archive is encrypted, and how far the encryption reaches.
///
/// The 7z spelling of `crate::profile::Encryption`, taken as a borrowed
/// password rather than read off the profile here, so this module keeps
/// knowing nothing about the profile tables. `container.rs` maps the
/// two.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Encrypt<'a> {
    /// No password, no AES coder, and a header anyone can read.
    #[default]
    None,
    /// C4: AES-256 over the member DATA. The header - the names, the
    /// sizes, the CRCs - stays readable without the password, which is
    /// the whole difference from [`Encrypt::Header`] and is what lets a
    /// client name the members before it can open them.
    Data(&'a str),
    /// C5: AES-256 over the member data AND over the archive header, so
    /// the file list itself needs the password. The end header is at the
    /// TAIL of a 7z, which is where the client answers the password
    /// question for this shape
    /// (`nzbfast_unpack::rarfix::sevenz::open_sevenz`).
    Header(&'a str),
}

impl<'a> Encrypt<'a> {
    /// The password this selection encrypts under, or `None`.
    pub fn password(self) -> Option<&'a str> {
        match self {
            Self::None => None,
            Self::Data(p) | Self::Header(p) => Some(p),
        }
    }
}

/// Write one 7z archive holding `members`, in the order given.
///
/// `compressed` picks the content method: LZMA2, which is what every
/// 7-Zip build writes by default and what the corpus's own 7z legs
/// carry, against COPY, which is the stored shape.
///
/// `seed` is this level's salt source, drawn by `container.rs` from its
/// own `ENTROPY_STREAM` and handed to whichever writer the level
/// selected - the same seed reaches `rars::Entropy` on a RAR level. It
/// is installed as a thread-scoped [`EntropyScope`] across the WHOLE
/// build rather than passed to `AesEncoderOptions`, because the salt and
/// the IV are two draws today and a later one would otherwise go back to
/// the OS in silence; `vendor/sevenz-rust2/src/write_entropy.rs` carries
/// the argument. An unencrypted archive draws nothing, so the scope
/// costs it a thread-local swap and changes not a byte.
///
/// Deterministic by construction, and it has to be: no entry carries a
/// timestamp (`ArchiveEntry::new_file` leaves all three date flags
/// off, so the writer emits no time property at all), no attribute is
/// set, and the one OS draw the crate has is the one the scope above
/// replaces. `container.rs`'s `wrapping_twice_is_byte_identical` is the
/// assertion, and this module's `writing_twice_is_byte_identical` is the
/// same claim one level down, over all three encryption selections.
///
/// # The header shares the data stream's IV, by the writer's design
///
/// `sevenz_rust2::ArchiveWriter::write_encoded_header` encrypts the
/// header by CLONING the AES configuration out of the content methods,
/// so a header-encrypted archive uses one IV under one key for two
/// streams. That is upstream's shape for every archive this library
/// writes and it is not something a caller can vary, so it is recorded
/// here rather than worked around: a catalog archive has no secrecy to
/// lose (the password travels in the profile), and a client reading one
/// cannot tell the difference.
pub fn write_archive(
    members: &[(String, Vec<u8>)],
    compressed: bool,
    encrypt: Encrypt<'_>,
    seed: [u8; 32],
) -> Result<Vec<u8>, String> {
    let method = if compressed {
        EncoderMethod::LZMA2
    } else {
        EncoderMethod::COPY
    };
    let _entropy = EntropyScope::install(Entropy::Seeded(seed));
    let mut w = ArchiveWriter::new(Cursor::new(Vec::new()))
        .map_err(|e| format!("the 7z writer would not start: {e}"))?;
    // The AES coder goes FIRST and the content method second, which is
    // the order `sevenz_rust2::util::compress_encrypted` writes and the
    // order the reader expects: `create_writer` wraps the list so the
    // LAST method sees the plaintext, giving compress-then-encrypt.
    // Reversing it would encrypt and then try to compress ciphertext.
    let mut methods = Vec::with_capacity(2);
    if let Some(pw) = encrypt.password() {
        // `Password::from(&str)` encodes UTF-16, which is the 7z
        // convention and is what the client's own reader does
        // (`nzbfast_unpack::rarfix::sevenz::open_sevenz`). Building the
        // options here and not before the scope: the constructor is
        // where the salt and the IV are drawn.
        methods.push(EncoderConfiguration::from(AesEncoderOptions::new(
            Password::from(pw),
        )));
    }
    methods.push(EncoderConfiguration::new(method));
    w.set_content_methods(methods);
    // Explicitly, in both directions: the writer's own default is TRUE,
    // so a data-encrypted profile that said nothing here would emit a
    // header-encrypted archive and a C4 row would be a C5.
    w.set_encrypt_header(matches!(encrypt, Encrypt::Header(_)));
    for (name, bytes) in members {
        // One entry per push rather than `push_archive_entries`, which
        // packs a SOLID block: a solid archive makes every member's
        // bytes depend on the members before it, and the shapes this
        // plane builds are one member at a level (or a member beside
        // its own recovery set), where non-solid is both what 7-Zip
        // writes for a small set and the shape a client can open a
        // member of without decoding the ones in front of it.
        w.push_archive_entry(ArchiveEntry::new_file(name), Some(Cursor::new(bytes)))
            .map_err(|e| format!("the 7z writer refused {name:?}: {e}"))?;
    }
    let out = w
        .finish()
        .map_err(|e| format!("the 7z writer could not finish: {e}"))?;
    Ok(out.into_inner())
}

/// Cut a finished archive into `part_bytes`-sized pieces, which is what
/// a multi-volume 7z IS.
///
/// A final short piece is kept; a cut that produces one piece is a
/// single-volume archive and is returned as such, because a `.7z.001`
/// with no `.002` beside it is a set of one that no splitter writes.
pub fn split_parts(bytes: &[u8], part_bytes: usize) -> Vec<Vec<u8>> {
    if part_bytes == 0 || bytes.len() <= part_bytes {
        return vec![bytes.to_vec()];
    }
    bytes.chunks(part_bytes).map(<[u8]>::to_vec).collect()
}

/// Extract a whole 7z set - one archive, or the ordered parts of a
/// split one - into (name, bytes) in archive order.
///
/// `password` is `None` for an unencrypted set. **A wrong or absent
/// password on a DATA-encrypted set does not fail here** - the header is
/// readable, so the walk starts and the member's decryption fails
/// underneath it, which is why the caller's round trip has to reach the
/// bytes rather than the names. A header-encrypted set fails at
/// `ArchiveReader::new` instead, because the end header is what the key
/// opens.
///
/// The parts are concatenated because that is the format's own
/// definition of a split set. It is a copy of the archive in memory,
/// which the client deliberately does NOT make (TODO 212 removed
/// exactly that join from the disk pass, measured at 2.000x of payload
/// in device I/O); here the payloads are kilobytes and the check runs
/// at generation, so the simple reading is the right one.
pub fn extract_set(
    set: &[Vec<u8>],
    password: Option<&str>,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let joined: Vec<u8> = set.concat();
    let mut r = ArchiveReader::new(Cursor::new(&joined), read_password(password))
        .map_err(|e| format!("the 7z set does not parse: {e}"))?;
    let mut out = Vec::new();
    r.for_each_entries(|entry, reader| {
        let mut bytes = Vec::with_capacity(entry.size as usize);
        std::io::copy(reader, &mut bytes)?;
        out.push((entry.name.clone(), bytes));
        Ok(true)
    })
    .map_err(|e| format!("the 7z set does not extract: {e}"))?;
    Ok(out)
}

/// Whether the archive's blocks declare a real compression method, or
/// COPY.
///
/// Read off the block coders rather than inferred from the emitted
/// size, because size is exactly the wrong question here: an LZMA2
/// archive over incompressible bytes is LARGER than its payload and is
/// still an archive the client must run the LZMA2 decoder over. `None`
/// means the archive declares no CONTENT block at all, which is an
/// archive of nothing.
///
/// **The AES coder is skipped, and that is load-bearing.** An encrypted
/// archive records its coders in the order the writer wrapped them, so
/// `coders[0]` is AES256_SHA256 and the content method is behind it.
/// Reading the first coder would report AES for every encrypted archive
/// - which is not COPY, so `refuse_a_compressed_archive_that_stored`
/// would wave through an encrypted C3 row whose writer had silently
/// stored, the exact rubber stamp that guard exists to refuse.
///
/// `password` is needed for a HEADER-encrypted archive, whose coder list
/// lives in the encrypted end header; a data-encrypted one answers with
/// no password at all.
pub fn declared_method(bytes: &[u8], password: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    let r = ArchiveReader::new(Cursor::new(bytes), read_password(password))
        .map_err(|e| format!("the 7z archive does not parse: {e}"))?;
    Ok(r.archive()
        .blocks
        .first()
        .and_then(|b| b.coders.iter().find(|c| c.encoder_method_id() != AES_ID))
        .map(|c| c.encoder_method_id().to_vec()))
}

/// The method id COPY is recorded under, for the guard's comparison.
pub const COPY_ID: &[u8] = EncoderMethod::ID_COPY;

/// The method id AES-256/SHA-256 is recorded under, which
/// [`declared_method`] steps over.
const AES_ID: &[u8] = EncoderMethod::ID_AES256_SHA256;

/// The reader's password for a set, which is `Password::empty()` when
/// there is none.
///
/// One spelling, and the SAME one the client uses
/// (`nzbfast_unpack::rarfix::sevenz::open_sevenz`): `Password::from` on
/// a `&str` encodes UTF-16, and a key derived from the raw bytes instead
/// would open nothing either side wrote.
fn read_password(password: Option<&str>) -> Password {
    match password {
        Some(p) if !p.is_empty() => Password::from(p),
        _ => Password::empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A seed for the arms that do not care which one.
    const SEED: [u8; 32] = [0x5e; 32];

    /// A password that is FURNITURE. Every password in this crate is:
    /// it travels in a public catalog beside the archive it opens.
    const PW: &str = "sevenz-fixture-pw";

    fn members() -> Vec<(String, Vec<u8>)> {
        vec![
            (
                "movie.bin".to_string(),
                (0u8..=255).cycle().take(9000).collect(),
            ),
            ("sample/s.bin".to_string(), vec![7u8; 3000]),
        ]
    }

    fn plain(members: &[(String, Vec<u8>)], compressed: bool) -> Vec<u8> {
        write_archive(members, compressed, Encrypt::None, SEED).expect("the writer builds it")
    }

    /// The stored arm writes an archive that reads back with the same
    /// names, the same order and the same bytes.
    #[test]
    fn a_stored_archive_round_trips() {
        let m = members();
        let bytes = plain(&m, false);
        assert_eq!(extract_set(&[bytes], None).expect("it reads back"), m);
    }

    /// ...and so does the compressed one, whose whole point is that the
    /// reader had to decompress to say so.
    #[test]
    fn a_compressed_archive_round_trips_and_declares_lzma2() {
        let m = members();
        let bytes = plain(&m, true);
        assert_eq!(
            extract_set(std::slice::from_ref(&bytes), None).expect("it reads back"),
            m
        );
        let method = declared_method(&bytes, None).expect("the archive parses");
        assert_ne!(
            method.as_deref(),
            Some(COPY_ID),
            "the compressed arm declared COPY, so nothing would decompress"
        );
    }

    /// The stored arm declares COPY, which is the control for the test
    /// above: without it, an assertion that "compressed is not COPY"
    /// would pass over a writer that never emitted COPY at all.
    #[test]
    fn the_stored_arm_declares_copy() {
        let bytes = plain(&members(), false);
        assert_eq!(
            declared_method(&bytes, None)
                .expect("the archive parses")
                .as_deref(),
            Some(COPY_ID)
        );
    }

    /// An LZMA2 archive over INCOMPRESSIBLE bytes is bigger than its
    /// payload and is still a real C3, which is the fact the module
    /// header rests on and the difference from the RAR writers.
    ///
    /// Written as a measurement rather than a comment: if a future
    /// bump made the 7z writer fall back to COPY the way the RAR
    /// writers do, this is what says so.
    #[test]
    fn lzma2_over_incompressible_bytes_still_declares_lzma2() {
        // `[source]`'s own bytes, drawn from this crate's stream rather
        // than approximated: a hand-made "noise" pattern is exactly the
        // thing LZMA2 is good at, and the first version of this test
        // measured a counter through a multiplicative hash that
        // compressed 40,000 bytes to 982.
        let mut noise = vec![0u8; 40_000];
        crate::rng::Rng::from_seed(0xC3_7A).fill(&mut noise);
        let m = vec![("noise.bin".to_string(), noise.clone())];
        let bytes = plain(&m, true);
        assert!(
            bytes.len() > noise.len(),
            "the payload compressed to {} bytes from {}, so it was not incompressible and \
             this test is measuring the wrong thing",
            bytes.len(),
            noise.len()
        );
        assert_ne!(
            declared_method(&bytes, None).expect("it parses").as_deref(),
            Some(COPY_ID),
            "the writer stored what it could not shrink, which is the RAR behaviour this \
             module's header says 7z does NOT have"
        );
        assert_eq!(extract_set(&[bytes], None).expect("it reads back"), m);
    }

    /// Two runs over one input produce one archive, byte for byte.
    ///
    /// Nothing here may draw from a clock or from the OS entropy.
    ///
    /// The ENCRYPTED arms are the reason this test takes a seed at all:
    /// AES draws a salt and an IV, and before
    /// `vendor/sevenz-rust2/src/write_entropy.rs` existed those came
    /// from the OS, so one profile emitted a different archive on every
    /// run and the catalog walk failed on bytes carrying no meaning.
    #[test]
    fn writing_twice_is_byte_identical() {
        for compressed in [false, true] {
            for enc in [Encrypt::None, Encrypt::Data(PW), Encrypt::Header(PW)] {
                let a = write_archive(&members(), compressed, enc, SEED).unwrap();
                let b = write_archive(&members(), compressed, enc, SEED).unwrap();
                assert_eq!(a, b, "compressed = {compressed}, {enc:?}");
            }
        }
    }

    /// ...and a DIFFERENT seed gives a different archive, which is the
    /// control for the test above: without it, a source that handed back
    /// one constant would pass byte-identity while destroying the
    /// property the seed exists for.
    #[test]
    fn a_different_seed_gives_a_different_encrypted_archive() {
        let a = write_archive(&members(), false, Encrypt::Data(PW), [0x11; 32]).unwrap();
        let b = write_archive(&members(), false, Encrypt::Data(PW), [0x12; 32]).unwrap();
        assert_ne!(a, b);
        // The salts differ and nothing else does, so both still open.
        assert_eq!(
            extract_set(&[a], Some(PW)).unwrap(),
            extract_set(&[b], Some(PW)).unwrap()
        );
    }

    /// A split set is the archive's own bytes cut up, so concatenating
    /// the parts gives the archive back and the set extracts.
    #[test]
    fn a_split_set_is_the_archive_cut_and_reads_back_joined() {
        let m = members();
        let whole = plain(&m, false);
        let parts = split_parts(&whole, 4096);
        assert!(parts.len() >= 3, "got {} parts", parts.len());
        assert_eq!(parts.concat(), whole);
        // Every part but the last is exactly the cut size, which is what
        // the client's numbered-run grammar checks (uniform part sizes).
        for p in &parts[..parts.len() - 1] {
            assert_eq!(p.len(), 4096);
        }
        // And only part one carries the signature: parts 2..n are raw
        // archive bytes, which is why an opaque 7z split set cannot be
        // reassembled from content and `container.rs` refuses one.
        assert!(parts[0].starts_with(b"7z\xbc\xaf\x27\x1c"));
        assert!(!parts[1].starts_with(b"7z\xbc\xaf\x27\x1c"));
        assert_eq!(extract_set(&parts, None).expect("the set reads back"), m);
    }

    /// A cut wider than the archive is a single volume, not a `.001`
    /// with nothing beside it.
    #[test]
    fn a_cut_wider_than_the_archive_is_one_volume() {
        let whole = plain(&members(), false);
        assert_eq!(split_parts(&whole, whole.len() + 1).len(), 1);
        assert_eq!(split_parts(&whole, 0).len(), 1);
    }

    /// C4 and C5, both storage modes: the archive opens with its
    /// password and gives the payload back byte for byte.
    #[test]
    fn an_encrypted_archive_round_trips_with_its_password() {
        let m = members();
        for compressed in [false, true] {
            for enc in [Encrypt::Data(PW), Encrypt::Header(PW)] {
                let bytes = write_archive(&m, compressed, enc, SEED)
                    .unwrap_or_else(|e| panic!("{enc:?} compressed={compressed}: {e}"));
                assert_eq!(
                    extract_set(&[bytes], Some(PW)).expect("it reads back with the password"),
                    m,
                    "{enc:?}, compressed = {compressed}"
                );
            }
        }
    }

    /// **THE CONTROL ARM.** An encrypted archive must NOT open without
    /// the password, and must not open with the wrong one.
    ///
    /// This is the test the whole item exists for. Before the refusal in
    /// `container.rs` landed, a `kind = "7z-stored"` profile with
    /// `encryption = "data"` and a password WRAPPED SUCCESSFULLY and the
    /// result extracted with no password at all - the writer was simply
    /// never handed one - and every test that existed at the time passed
    /// over it. A row like that reads as evidence that a client handles
    /// encrypted 7z, which is worse than having no row.
    ///
    /// Both failure shapes are asserted because they are different
    /// mechanisms: a header-encrypted archive cannot even be PARSED
    /// without the key, while a data-encrypted one parses, lists its
    /// members, and fails when the bytes are pulled. A test that only
    /// checked "the call returned Err" on the header arm would say
    /// nothing at all about the data arm.
    #[test]
    fn an_encrypted_archive_does_not_open_unpassworded() {
        for compressed in [false, true] {
            for enc in [Encrypt::Data(PW), Encrypt::Header(PW)] {
                let bytes = write_archive(&members(), compressed, enc, SEED).unwrap();
                for wrong in [None, Some(""), Some("not-the-fixture-pw")] {
                    let got = extract_set(std::slice::from_ref(&bytes), wrong);
                    assert!(
                        got.is_err(),
                        "{enc:?} compressed={compressed} opened with password {wrong:?}, so the \
                         archive is readable by anyone and a C4/C5 row over it would be green \
                         for a shape nobody asked for"
                    );
                }
            }
        }
    }

    /// A data-encrypted archive's HEADER is readable without the
    /// password and a header-encrypted one's is not, which is the whole
    /// difference between C4 and C5 and the only thing that makes them
    /// two rows.
    ///
    /// Read through `declared_method`, which parses the end header and
    /// nothing else. Without this the two selections could both be
    /// emitting the same archive - `set_encrypt_header` defaults to TRUE
    /// in the writer, so the failure to spell it out lands on C4.
    #[test]
    fn only_the_header_arm_seals_the_header() {
        let data = write_archive(&members(), false, Encrypt::Data(PW), SEED).unwrap();
        assert_eq!(
            declared_method(&data, None)
                .expect("a data-encrypted header parses unpassworded")
                .as_deref(),
            Some(COPY_ID)
        );
        let header = write_archive(&members(), false, Encrypt::Header(PW), SEED).unwrap();
        assert!(
            declared_method(&header, None).is_err(),
            "the header-encrypted archive listed its coders without a password"
        );
        assert_eq!(
            declared_method(&header, Some(PW))
                .expect("...and parses with one")
                .as_deref(),
            Some(COPY_ID)
        );
    }

    /// `declared_method` reports the CONTENT method of an encrypted
    /// archive rather than AES, which is what
    /// `container::refuse_a_compressed_archive_that_stored` reads.
    ///
    /// The stored arm is the one that matters: it is the arm that must
    /// still say COPY, and an implementation returning the first coder
    /// would say AES256_SHA256 for both modes - so the guard would pass
    /// an encrypted archive that stored what it claimed to compress.
    #[test]
    fn the_content_method_is_read_past_the_aes_coder() {
        for enc in [Encrypt::Data(PW), Encrypt::Header(PW)] {
            let stored = write_archive(&members(), false, enc, SEED).unwrap();
            assert_eq!(
                declared_method(&stored, Some(PW)).unwrap().as_deref(),
                Some(COPY_ID),
                "{enc:?}"
            );
            let packed = write_archive(&members(), true, enc, SEED).unwrap();
            let method = declared_method(&packed, Some(PW)).unwrap();
            assert_ne!(method.as_deref(), Some(COPY_ID), "{enc:?}");
            assert!(method.is_some(), "{enc:?}");
        }
    }

    /// The entropy contract of `vendor/sevenz-rust2/src/write_entropy.rs`,
    /// pinned HERE because that crate is a `[patch.crates-io]` path
    /// dependency and not a workspace member, so `cargo test -p
    /// sevenz-rust2` runs nowhere in this repo and a test module inside
    /// it would never execute. See that module's header.
    ///
    /// EVERY TEST BELOW CARRIES A `test-global-gate` WAIVER, and the
    /// reason is one reason, checked once. The state they move is
    /// `write_entropy`'s `INSTALLED`, which is a `thread_local!` and not
    /// a process-global: two tests on two threads never see each other's
    /// writes, and on ONE thread every scope is RAII-bound, so a test
    /// leaves the thread exactly as it found it. That is asserted rather
    /// than asserted-about - `the_default_still_varies_per_run` fails if
    /// a neighbour leaked a seeded scope - and measured: `cargo test -p
    /// postfast --lib -- --test-threads=1`, which is one process on one
    /// thread, ran 288/288 green on 4 Sep 2026.
    ///
    /// What the gate actually saw is a NAME COLLISION, and it is worth
    /// knowing before waiving anything else the same way. Its
    /// cross-unit resolver treats `EntropyScope::install(` as a bare
    /// `install(` - its CALL pattern excludes a leading `.` but not a
    /// leading `::` - and `install` has exactly one definition under
    /// `crates/`, `nzbkit_base::logtee::install`, which moves `DRAIN`
    /// and `RING`. So the gate is over-reporting, which is its safe
    /// direction, and these four tests reach nothing in logtee at all.
    mod entropy {
        use sevenz_rust2::{Entropy, EntropyScope, Password, encoder_options::AesEncoderOptions};

        /// One draw of the two 16-byte values `AesEncoderOptions::new`
        /// takes, through the public API rather than through a helper of
        /// our own: it is the constructor a caller reaches, so it is the
        /// one worth pinning.
        fn draw() -> ([u8; 16], [u8; 16]) {
            let o = AesEncoderOptions::new(Password::from("entropy-probe"));
            (o.iv, o.salt)
        }

        /// A seeded source ADVANCES: the salt and the IV are two draws
        /// and a source handing back one constant would still make an
        /// archive reproducible, so the end-to-end byte-identity tests
        /// cannot see this. A repeated IV under one key is the real cost.
        // test-global-gate: `EntropyScope::install` is sevenz-rust2's own
        // associated fn over a thread_local, not `logtee::install`; the
        // module doc above carries the check.
        #[test]
        fn a_seeded_source_advances_between_draws() {
            let _scope = EntropyScope::install(Entropy::Seeded([0x5a; 32]));
            let (iv, salt) = draw();
            assert_ne!(iv, salt);
            let (iv2, salt2) = draw();
            assert_ne!(iv, iv2);
            assert_ne!(salt, salt2);
        }

        /// One seed gives one sequence, and a different seed a different
        /// one. This is the property the whole catalog rests on.
        // test-global-gate: `EntropyScope::install` is sevenz-rust2's own
        // associated fn over a thread_local, not `logtee::install`; the
        // module doc above carries the check.
        #[test]
        fn one_seed_gives_one_sequence() {
            let take = |seed: [u8; 32]| {
                let _scope = EntropyScope::install(Entropy::Seeded(seed));
                (draw(), draw())
            };
            assert_eq!(take([0x11; 32]), take([0x11; 32]));
            assert_ne!(take([0x11; 32]), take([0x12; 32]));
        }

        /// A scope puts back what it replaced, so a nested build gives
        /// the outer sequence back where it left off rather than
        /// restarting it or inheriting the inner seed.
        // test-global-gate: `EntropyScope::install` is sevenz-rust2's own
        // associated fn over a thread_local, not `logtee::install`; the
        // module doc above carries the check.
        #[test]
        fn a_scope_puts_back_what_it_replaced() {
            let outer = EntropyScope::install(Entropy::Seeded([0x77; 32]));
            let before = draw();
            {
                let _inner = EntropyScope::install(Entropy::Seeded([0x88; 32]));
                let _ = draw();
            }
            let after = draw();
            drop(outer);

            let expected = {
                let _scope = EntropyScope::install(Entropy::Seeded([0x77; 32]));
                assert_eq!(draw(), before);
                draw()
            };
            assert_eq!(after, expected);
        }

        /// **THE CONTROL ARM for the seeded source.** With no scope
        /// installed the draws still come from the OS and still vary per
        /// run, which is what stops the seeded path becoming the default
        /// by accident - in a crate whose other callers are the client's
        /// own tests and, one day, anything that writes a real archive.
        ///
        /// Two OS draws of 16 bytes colliding has probability 2^-128.
        // test-global-gate: `EntropyScope::install` is sevenz-rust2's own
        // associated fn over a thread_local, not `logtee::install`; the
        // module doc above carries the check.
        #[test]
        fn the_default_still_varies_per_run() {
            {
                let _scope = EntropyScope::install(Entropy::Seeded([0x99; 32]));
                let _ = draw();
            }
            assert_ne!(draw(), draw());
            assert_eq!(Entropy::default(), Entropy::Os);
        }
    }
}
