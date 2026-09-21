//! The ONE place this crate's tests reach the RAR engine's WRITER
//! directly.
//!
//! Named for the archive SHAPE and never for the engine call, so that
//! the engine swap (cutover plan
//! `research/RARKIT-CUTOVER-PLAN-2026-09-18.md`, preparation item P3)
//! moves this file and no test site. The counterpart modules are
//! `nzbkit::extract::testutil`, `nzbkit_base::rar::rarfixtures`,
//! `nzbfast_unpack::rarfixtures` and `crates/nzbfast/tests/rarfixtures`
//! - deliberate duplicates, since a dev-dependency edge between these
//! crates would move the workspace's feature resolution for the engine.
//!
//! # Why this one takes a `Container`
//!
//! postfast IS an archive writer, so unlike the other four this crate's
//! tests are not building a fixture to feed to something else: they are
//! DIFFERENTIALS, asserting that the streamed route through
//! `write_one_archive` / `write_volume_set` emits the same bytes as the
//! in-memory route under the options PRODUCTION passes. That is why
//! every builder below takes the same `(&Container, seed, Packing)` the
//! production site does and derives the options through
//! [`super::rar50_opts`] rather than spelling a second copy of them -
//! a copy that can drift is precisely what the differential is meant to
//! rule out.
//!
//! So "in memory" in the names below is the ROUTE, which is the thing
//! under test. The SHAPE is the rest of the name: a stored archive or a
//! stored volume set, encrypted and record-carrying exactly as the
//! container says.

use super::{Container, Encryption, Packing, rar50_opts};

/// The writer options production would pass for `c` under `seed` and
/// `packing` - the value the routing tests hand to
/// `streamed_stored_opts`.
pub(super) fn options_for(
    c: &Container,
    seed: [u8; 32],
    packing: Packing,
) -> rars::rar50::WriterOptions {
    rar50_opts(c, rars::Entropy::Seeded(seed), packing)
}

fn recovery_of(c: &Container) -> Option<u64> {
    (c.recovery_record_pct > 0).then_some(u64::from(c.recovery_record_pct))
}

/// One STORE-mode RAR 5 archive over `members`, built the IN-MEMORY way
/// - encrypted under the container's password when it asks for
/// encryption, carrying the container's recovery record when it asks
/// for one.
pub(super) fn in_memory_stored_archive(
    c: &Container,
    seed: [u8; 32],
    packing: Packing,
    members: &[(String, Vec<u8>)],
) -> Vec<u8> {
    let w = rars::rar50::Rar50Writer::new(options_for(c, seed, packing))
        .recovery_percent(recovery_of(c));
    if c.encryption == Encryption::None {
        let e: Vec<_> = members
            .iter()
            .map(|(n, d)| rars::rar50::StoredEntry {
                name: n.as_bytes(),
                data: d.as_slice(),
                mtime: None,
                attributes: 0,
                host_os: 0,
            })
            .collect();
        w.stored_entries(&e)
            .finish()
            .expect("the in-memory writer builds it")
    } else {
        let pw = c.password.as_bytes();
        let e: Vec<_> = members
            .iter()
            .map(|(n, d)| rars::rar50::EncryptedStoredEntry {
                name: n.as_bytes(),
                data: d.as_slice(),
                mtime: None,
                attributes: 0,
                host_os: 0,
                password: pw,
            })
            .collect();
        w.encrypted_stored_entries(&e)
            .finish()
            .expect("the in-memory writer builds it")
    }
}

/// A STORE-mode RAR 5 multivolume set over `members` at the container's
/// `volume_bytes`, built the IN-MEMORY way, with the same encryption
/// and recovery-record rules as [`in_memory_stored_archive`].
pub(super) fn in_memory_stored_volume_set(
    c: &Container,
    seed: [u8; 32],
    packing: Packing,
    members: &[(String, Vec<u8>)],
) -> Vec<Vec<u8>> {
    let per_volume = usize::try_from(c.volume_bytes).unwrap();
    let w = rars::rar50::Rar50VolumeWriter::new(options_for(c, seed, packing))
        .max_payload_per_volume(per_volume)
        .recovery_percent(recovery_of(c));
    if c.encryption == Encryption::None {
        let e: Vec<_> = members
            .iter()
            .map(|(n, d)| rars::rar50::StoredEntry {
                name: n.as_bytes(),
                data: d.as_slice(),
                mtime: None,
                attributes: 0,
                host_os: 0,
            })
            .collect();
        w.stored_entries(&e)
            .finish()
            .expect("the in-memory set writer builds it")
    } else {
        let pw = c.password.as_bytes();
        let e: Vec<_> = members
            .iter()
            .map(|(n, d)| rars::rar50::EncryptedStoredEntry {
                name: n.as_bytes(),
                data: d.as_slice(),
                mtime: None,
                attributes: 0,
                host_os: 0,
                password: pw,
            })
            .collect();
        w.encrypted_stored_entries(&e)
            .finish()
            .expect("the in-memory set writer builds it")
    }
}

/// [`in_memory_stored_archive`] with the recovery-record FEATURE FLAG
/// forced on or off independently of the percent, which is the one
/// thing the container cannot express.
///
/// Its test's whole claim is that the flag moves no byte, so the two
/// arms must differ in nothing else.
pub(super) fn in_memory_stored_archive_with_record_flag(
    c: &Container,
    seed: [u8; 32],
    packing: Packing,
    members: &[(String, Vec<u8>)],
    percent: u64,
    flag: bool,
) -> Vec<u8> {
    let mut opts = options_for(c, seed, packing);
    opts.features.recovery_record = flag;
    let e: Vec<_> = members
        .iter()
        .map(|(n, d)| rars::rar50::StoredEntry {
            name: n.as_bytes(),
            data: d.as_slice(),
            mtime: None,
            attributes: 0,
            host_os: 0,
        })
        .collect();
    rars::rar50::Rar50Writer::new(opts)
        .recovery_percent(Some(percent))
        .stored_entries(&e)
        .finish()
        .expect("the in-memory writer builds it")
}

/// One ENCRYPTED store-mode RAR 5 archive built at the library's OWN
/// DEFAULT entropy - deliberately NOT through [`options_for`], which
/// seeds it.
///
/// This is the arm that pins the default salt source: it must draw
/// fresh from the operating system every run, so two calls must differ.
/// Nothing else in this crate may use it.
pub(super) fn encrypted_stored_archive_at_default_entropy(
    name: &[u8],
    data: &[u8],
    password: &[u8],
) -> Vec<u8> {
    let mut f = rars::FeatureSet::store_only();
    f.file_encryption = true;
    rars::rar50::Rar50Writer::new(rars::rar50::WriterOptions::new(
        rars::ArchiveVersion::Rar50,
        f,
    ))
    .encrypted_stored_entries(&[rars::rar50::EncryptedStoredEntry {
        name,
        data,
        mtime: None,
        attributes: 0,
        host_os: 0,
        password,
    }])
    .finish()
    .expect("the encrypted writer builds an archive")
}

/// The library default this crate asserts on: the OPERATING SYSTEM, not
/// a seed. Named here so no test site has to spell the engine's enum.
pub(super) fn default_entropy_is_the_os() -> bool {
    rars::Entropy::default() == rars::Entropy::Os
}
