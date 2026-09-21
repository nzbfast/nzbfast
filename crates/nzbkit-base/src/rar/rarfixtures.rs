//! The ONE place this crate's tests reach the RAR engine's WRITER.
//!
//! Named for the archive SHAPE and never for the engine call, so that
//! the engine swap (cutover plan
//! `research/RARKIT-CUTOVER-PLAN-2026-09-18.md`, preparation item P3)
//! moves this file and no test site. The counterpart modules are
//! `nzbkit::extract::testutil`, `nzbfast_unpack::rarfixtures`,
//! `crates/nzbfast/tests/rarfixtures` and
//! `postfast::container::rarfixtures` - deliberate duplicates, since a
//! dev-dependency edge between these crates would move the workspace's
//! feature resolution for the engine.
//!
//! This is the SMALL one: `rar/fixtures.rs` beside it hand-builds RAR
//! bytes and is the module almost everything here reaches for. Only a
//! claim about what a REAL archiver emits - header lengths, an
//! explicitly numbered head, the member CRC that rides the last
//! fragment alone - needs the engine, and that is what this covers.

/// A STORE-mode RAR 5 multivolume set over one member, `per_volume`
/// payload bytes each, returned in set order.
///
/// Unix host (`host_os = 1`) with the mode in the attribute field
/// (`0o100644`), which is what a real `rar` run on this box writes.
/// The volume-number field is stamped on EVERY volume including the
/// first, where the RAR 5 specification makes it optional - that is
/// itself the subject of the one test here.
pub(super) fn stored_volume_set(name: &[u8], data: &[u8], per_volume: usize) -> Vec<Vec<u8>> {
    rars::rar50::Rar50VolumeWriter::new(rars::rar50::WriterOptions::default())
        .stored_entry(rars::rar50::StoredEntry {
            name,
            data,
            mtime: None,
            attributes: 0o100644,
            host_os: 1,
        })
        .max_payload_per_volume(per_volume)
        .finish()
        .expect("the stored volume writer builds the set")
}
