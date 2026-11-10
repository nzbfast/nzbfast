//! The PAR2 engine residue of the 9 Nov 2026 Fable whole-codebase sweep
//! (its "PAR2 verify/repair" leads), verified and fixed 10 Nov 2026.
//! One test per confirmed lead, each run red against the code before
//! its fix.
//!
//! A CHILD of `unit_tests` for `padded_windows`' two reasons: the
//! fixture helpers live there, and that file has a size-gate entry.

use super::*;

/// A FileDesc packet body spelled out field by field, so a test can put
/// any reading it likes under any file id - including one that does not
/// BIND the id (`par2::filedesc_id`), which `par2_index` cannot make.
fn desc_packet(set: [u8; 16], fid: [u8; 16], d: &par2::Desc) -> Vec<u8> {
    let mut body = fid.to_vec();
    body.extend_from_slice(&d.md5);
    body.extend_from_slice(&d.md5_16k);
    body.extend_from_slice(&d.length.to_le_bytes());
    let mut nb = d.name.as_bytes().to_vec();
    while !nb.len().is_multiple_of(4) {
        nb.push(0);
    }
    body.extend_from_slice(&nb);
    pkt(set, par2::TYPE_FILEDESC, &body)
}

fn honest_desc(name: &str, data: &[u8]) -> par2::Desc {
    par2::Desc {
        name: name.into(),
        length: data.len() as u64,
        md5: Md5::digest(data).into(),
        md5_16k: Md5::digest(&data[..data.len().min(16384)]).into(),
    }
}

fn main_packet(set: [u8; 16], bs: usize, ids: &[[u8; 16]]) -> Vec<u8> {
    let mut main = (bs as u64).to_le_bytes().to_vec();
    main.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    for id in ids {
        main.extend_from_slice(id);
    }
    pkt(set, par2::TYPE_MAIN, &main)
}

fn ifsc_packet(set: [u8; 16], fid: [u8; 16], data: &[u8], bs: usize) -> Vec<u8> {
    let mut body = fid.to_vec();
    for chunk in data.chunks(bs) {
        let mut padded = chunk.to_vec();
        padded.resize(bs, 0);
        body.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&padded)));
        body.extend_from_slice(&crc32fast::hash(&padded).to_le_bytes());
    }
    pkt(set, par2::TYPE_IFSC, &body)
}

/// Lead 2 (verify.rs, the fast tier's pass). The FileDesc's 16 KiB head
/// hash is an IDENTIFICATION aid; the integrity proof is the whole-file
/// MD5 (the chain tier) or the IFSC block hashes over every byte (the
/// fast tier). A member whose every block verifies but whose head hash
/// disagrees with the FileDesc was a hard "damaged" on the fast tier -
/// a byte-exact file, and a repair that then has nothing to write fails
/// its own self-prove with `VerifyFailed` - while the chain tier calls
/// the same bytes intact. `crate::par2`'s `ifsc_only_attempt` already
/// declines this shape to the full path; the repair's pass now does the
/// same, so the two tiers answer alike on it and the H7 divergence stays
/// the only one (`the_fast_tier_diverges_only_on_h7`).
#[test]
fn a_byte_exact_member_with_a_wrong_head_hash_is_not_failed_by_the_fast_tier() {
    let dir = tmpdir("head16k");
    let bs = 4096usize;
    for (tag, len) in [
        ("under the 16 KiB head", 1000usize),
        (
            "past the parallel floor",
            (HASH_PAR_MIN_BYTES as usize) + bs * 3 + 91,
        ),
    ] {
        let data = payload(len, 91);
        let mut meta = meta_for("h.bin", &data, bs);
        meta.md5_16k = [0xEE; 16];
        let p = dir.join("h.bin");
        std::fs::write(&p, &data).unwrap();
        for threads in [1usize, 8] {
            let chain = verify_pass1_tiered(&p, &meta, bs, threads, false).unwrap();
            assert!(
                chain.intact,
                "{tag}: control - the whole-file MD5 proves these bytes (threads={threads})"
            );
            let fast = verify_pass1_tiered(&p, &meta, bs, threads, true).unwrap();
            assert_eq!(fast.clean, chain.clean, "{tag}: clean (threads={threads})");
            assert_eq!(
                fast.intact, chain.intact,
                "{tag}: intact (threads={threads})"
            );
            assert_eq!(
                fast.present, chain.present,
                "{tag}: presence (threads={threads})"
            );
        }
        assert!(
            blocks_match_fast(&p, &meta, bs).unwrap(),
            "{tag}: the fast self-prove must not fail a byte-exact member on its head hash"
        );
        // The decline must not turn into acceptance of a REAL fault: the
        // same wrong head over a damaged member is still damaged on both.
        let mut bad = data.clone();
        bad[len / 2] ^= 0x41;
        std::fs::write(&p, &bad).unwrap();
        let fast = verify_pass1_tiered(&p, &meta, bs, 8, true).unwrap();
        assert!(!fast.clean && !fast.intact, "{tag}: damage still found");
        assert!(!blocks_match_fast(&p, &meta, bs).unwrap(), "{tag}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lead 3 (catalog.rs, `SetReplay::feed`). A directory-scoped repair
/// (`want = None`) bound itself to the set id of the FIRST packet the
/// sorted walk met, so a stray packet of another set sorting first - a
/// leftover recovery volume of a deleted set, an extensionless hex
/// volume of a neighbour - made a complete, repairable set answer
/// `NoMainPacket`. The set picked is now the first one that carries a
/// Main packet.
#[test]
fn a_stray_foreign_packet_sorting_first_does_not_hide_the_set() {
    let dir = tmpdir("stray-first");
    let a = payload(200, 3);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let mut damaged = a.clone();
    damaged[70] ^= 0x33;
    std::fs::write(dir.join("a.bin"), &damaged).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+2.par2"),
        par2_volume(SET, BS, files, &[0, 1]),
    )
    .unwrap();
    // One recovery packet of a set with no Main anywhere, sorting first.
    let other = [0x42u8; 16];
    std::fs::write(
        dir.join("0-leftover.par2"),
        par2_volume(other, BS, files, &[7]),
    )
    .unwrap();
    match repair_dir(&dir) {
        Ok(RepairStatus::Repaired(r)) => assert_eq!(r.blocks_rebuilt, 1),
        other => panic!("expected the real set repaired, got {other:?}"),
    }
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lead 4 (par2repair.rs, the critical-packet scan). W4-10 and M4-38
/// made a FileDesc reading a function of the SET of packets offered
/// (a descriptor that binds its id out-ranks one that does not), but the
/// scan stopped at the first file that held ANY reading for every id.
/// So an unbound forgery in the index file was taken, and the honest
/// binding descriptor in the next volume was never read: the repair
/// answered from a prefix of the packets while verify (`Par2Set::parse`,
/// which reads them all) answered from the binder - the two-halves
/// disagreement `SetReplay` exists to prevent, and the one a real CLI
/// run measured on 9 Nov 2026 (`v` 0 and `r` 5 on one set). An
/// unbound reading is now open until the scan ends.
#[test]
fn an_unbound_filedesc_in_the_index_does_not_outrank_a_binder_in_a_volume() {
    let dir = tmpdir("unbound-first");
    let a = payload(200, 5);
    std::fs::write(dir.join("a.bin"), &a).unwrap();
    let honest = honest_desc("a.bin", &a);
    let fid = par2::filedesc_id(&honest);
    let forged = par2::Desc {
        length: 1u64 << 62,
        ..honest.clone()
    };
    let mut index = main_packet(SET, BS, &[fid]);
    index.extend(desc_packet(SET, fid, &forged));
    index.extend(ifsc_packet(SET, fid, &a, BS));
    std::fs::write(dir.join("set.par2"), &index).unwrap();
    // The live half's answer, which the disk half has to equal.
    let volume = desc_packet(SET, fid, &honest);
    let live = par2::Par2Set::parse(&[&index, &volume]).expect("the set parses live");
    assert_eq!(
        live.files.iter().map(|f| f.length).collect::<Vec<_>>(),
        [200],
        "control: the live half takes the binder"
    );
    std::fs::write(dir.join("set.vol0+1.par2"), &volume).unwrap();
    match repair_dir(&dir) {
        Ok(RepairStatus::NoDamage) => {}
        other => panic!("the honest member verifies clean, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A reader that returns `Interrupted` before every real read - the
/// EINTR a signal delivers to a blocking `read` on an interruptible
/// mount (NFS `intr`, FUSE). Every std read loop must retry it.
struct Hiccups {
    data: Vec<u8>,
    pos: usize,
    owed: bool,
}

impl std::io::Read for Hiccups {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.owed = !self.owed;
        if self.owed {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        let n = buf.len().min(self.data.len() - self.pos).min(4096);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Lead 6 (verify.rs `hash_rest`, the final whole-file proof). Both of
/// its read loops passed `Interrupted` straight up as a failed repair.
/// Run over both arms (the reader thread is Windows-only by default).
#[test]
fn the_final_proof_retries_an_interrupted_read() {
    let data = payload(50_000, 17);
    let want: [u8; 16] = Md5::digest(&data).into();
    for readahead in [false, true] {
        let r = Hiccups {
            data: data.clone(),
            pos: 0,
            owed: false,
        };
        let got = hash_rest_with(r, Md5::new(), 8192, readahead)
            .unwrap_or_else(|e| panic!("readahead={readahead}: {e}"));
        assert_eq!(got, want, "readahead={readahead}");
    }
}
