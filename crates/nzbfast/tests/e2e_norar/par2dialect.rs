//! The PAR2 DIALECT rows of the no-RAR matrix read: shapes other tools
//! legitimately produce that this parser was reading differently from the
//! way the producer meant (M4-21, M4-22).
//!
//! A child of [`super`] rather than a sibling of it, because every
//! fixture here is built out of that module's own packet-surgery
//! helpers - `packets`, `reseal`, `filedesc_name`, `par2_file_id` and
//! `add_par2_patched` - which a sibling could not reach without widening
//! them for one caller. Split out when the union of two lanes' rows put
//! that file over its size-gate ceiling; the bodies are verbatim.
//!
//! Neither row is hostile input. The failure mode both close is a file
//! that ends up under the wrong name or outside the set, on a post
//! MultiPar or QuickPar wrote correctly.

use super::*;

/// Wrap a body in a fresh, fully sealed PAR2 packet under `set_id`.
///
/// The set id is COPIED from a packet already in the file rather than
/// recomputed from the Main body. That is the module header's rule and it
/// is load-bearing here for a second reason: `add_nonrecovery_member`
/// grows the Main packet, and a recomputed set id would orphan every
/// other packet in the same file from the one they belong to.
///
/// `pub(super)` so the packet-trust rows next door build their orphan
/// FileDesc with THIS sealer rather than a second copy of it - the
/// FileDesc-vs-Main family is one seam and its fixtures should not
/// become hand-copied siblings.
pub(super) fn par2_packet(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(b"PAR2\0PKT");
    p.extend_from_slice(&((64 + body.len()) as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]); // packet MD5, sealed below
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let sum: [u8; 16] = md5::Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&sum);
    p
}

/// The recovery-set id every packet in this blob carries.
pub(super) fn blob_set_id(data: &[u8]) -> [u8; 16] {
    let (s, _, _) = packets(data)
        .into_iter()
        .next()
        .expect("a generated .par2 has at least one packet");
    data[s + 32..s + 48].try_into().unwrap()
}

/// Add a VERIFY-ONLY member to a recovery set (M4-21): a FileDesc packet
/// describing `name`/`payload`, plus that file's id in the NON-recovery
/// half of every Main packet in the blob.
///
/// par2cmdline cannot produce this - every file it is handed goes into the
/// recovery set - so the shape is synthesised here the way MultiPar and
/// QuickPar emit it natively. The Main packet GROWS by 16 bytes, so its
/// length field is patched and the packet resealed; the recovery slices
/// are untouched and still describe exactly the files they were computed
/// over, which is what a real non-recovery listing looks like.
fn add_nonrecovery_member(data: &mut Vec<u8>, name: &str, payload: &[u8]) {
    let set_id = blob_set_id(data);
    let fid = par2_file_id(payload, name);
    // Back to front: growing a packet shifts every offset behind it.
    let mut mains: Vec<(usize, usize)> = packets(data)
        .into_iter()
        .filter(|(_, _, t)| t == b"PAR 2.0\0Main\0\0\0\0")
        .map(|(s, l, _)| (s, l))
        .collect();
    assert!(!mains.is_empty(), "no Main packet to extend");
    mains.reverse();
    for (s, l) in mains {
        data.splice(s + l..s + l, fid);
        data[s + 8..s + 16].copy_from_slice(&((l + 16) as u64).to_le_bytes());
        reseal(data, s, l + 16);
    }
    let mut body = fid.to_vec();
    let whole: [u8; 16] = md5::Md5::digest(payload).into();
    body.extend_from_slice(&whole);
    let h16: [u8; 16] = md5::Md5::digest(&payload[..payload.len().min(16384)]).into();
    body.extend_from_slice(&h16);
    body.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    body.extend_from_slice(name.as_bytes());
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let pkt = par2_packet(set_id, b"PAR 2.0\0FileDesc", &body);
    data.extend(pkt);
}

/// Add the optional Unicode Filename packet MultiPar writes beside a
/// FileDesc whose byte field holds a lossy spelling (M4-22): the target's
/// file id, then `unicode` as bare UTF-16LE - no BOM, which is what
/// producers actually emit.
fn add_unifilen(data: &mut Vec<u8>, ascii_name: &str, unicode: &str) {
    let set_id = blob_set_id(data);
    let fid: [u8; 16] = packets(data)
        .into_iter()
        .find(|&(s, l, t)| t == *b"PAR 2.0\0FileDesc" && filedesc_name(data, s, l) == ascii_name)
        .map(|(s, _, _)| data[s + 64..s + 80].try_into().unwrap())
        .unwrap_or_else(|| panic!("no FileDesc named {ascii_name} to widen"));
    let mut body = fid.to_vec();
    for u in unicode.encode_utf16() {
        body.extend_from_slice(&u.to_le_bytes());
    }
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let pkt = par2_packet(set_id, b"PAR 2.0\0UniFileN", &body);
    data.extend(pkt);
}

/// M4-21 (30 Aug 2026): a PAR2 Main packet may list file ids the set
/// DESCRIBES but carries no parity for - QuickPar's and MultiPar's
/// "verify but do not repair". Those descriptors were parsed and then
/// dropped on the floor: a payload whose only real name lived in one kept
/// its posted hash, was never verified, and nothing in the log said a name
/// had been seen and discarded.
///
/// Measured red on the 30 Aug 2026 baseline at the parser: the Main
/// packet's `take(nfiles)` kept the recovery ids and the extra FileDesc
/// went nowhere.
///
/// The fix reads them into a SEPARATE list - `Par2Set::nonrecovery`, whose
/// header says why merging them into `files` is not available: repair lays
/// files onto the global input-slice index by walking that list in order,
/// and a verify-only member that failed would summon a repair that cannot
/// exist. What they feed instead is the weakest naming tier, on the
/// evidence they carry: a name plus a whole-file MD5, so the name
/// nominates and content over the FULL settled file finalizes it.
///
/// `Extra.bin` and not `Extra.nfo`: a furniture extension is a different
/// row's seam (M4-33) and would make a red here ambiguous.
#[tokio::test(flavor = "multi_thread")]
async fn a_verify_only_filedesc_names_the_payload_it_describes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarnonrec");
    let covered = payload(120_000, 61);
    let extra = payload(90_000, 62);
    fx.add_file_renamed_by_par2("Covered.bin", "Pv3nKq81ZwT", &covered, 40_000);
    // Written to disk under its real name but NOT handed to `par2 create`,
    // so the set genuinely carries no parity for it - which is what
    // non-recovery means.
    fx.add_file_renamed_by_par2("Extra.bin", "Rk9mXt24BhL", &extra, 40_000);
    let staged = extra.clone();
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["Covered.bin"],
        40_000,
        move |d| {
            add_nonrecovery_member(d, "Extra.bin", &staged);
        }
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "non-recovery-member post failed:\n{log}");
    // The recovery member is unaffected - a red above must not be
    // readable as "the whole post fell over".
    let got_c = std::fs::read(out.join("Covered.bin"))
        .unwrap_or_else(|e| panic!("the recovery member missing: {e}\n{log}"));
    assert!(got_c == covered, "Covered.bin not byte-exact\n{log}");
    let got_e = std::fs::read(out.join("Extra.bin")).unwrap_or_else(|e| {
        panic!(
            "the verify-only member kept its posted hash - its FileDesc was \
             parsed and dropped: {e}\n{log}"
        )
    });
    assert!(got_e == extra, "Extra.bin not byte-exact\n{log}");
    assert!(
        !out.join("Rk9mXt24BhL").exists(),
        "the obfuscated source name survived beside the published one\n{log}"
    );
    assert!(
        !out.join("Pv3nKq81ZwT").exists(),
        "the recovery member's obfuscated name survived\n{log}"
    );
}

/// M4-22 (30 Aug 2026): the PAR2 spec's optional Unicode Filename packet
/// carries the real name where the FileDesc's byte field holds only a
/// transliteration. MultiPar and QuickPar write both; we skipped the
/// optional one as an unknown type and published the lossy spelling.
///
/// Measured red on the 30 Aug 2026 baseline at the parser: the packet was
/// well formed, carried `Björk - Vespertine.mkv`, and the set reported
/// `Bjork - Vesperti.mkv`.
///
/// The packet RENAMES and does nothing else. It touches no checksum and
/// not the file id every reader keys packets by, so the authority rule
/// this whole family runs on is unchanged: a name nominates a descriptor
/// and only content finalizes one (`live::SlotState::try_match`). The
/// payload here is posted under a hash, so the claim is made on content
/// either way - what moves is only which spelling gets published.
#[tokio::test(flavor = "multi_thread")]
async fn a_unicode_filename_packet_publishes_the_name_the_producer_meant() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    const LOSSY: &str = "Bjork - Vesperti.mkv";
    const REAL: &str = "Björk - Vespertine.mkv";
    let mut fx = Fixture::new("norarunifile");
    let data = payload(120_000, 63);
    fx.add_file_renamed_by_par2(LOSSY, "Zq7Rm2Xd91C", &data, 40_000);
    assert!(add_par2_patched(&mut fx, 20, &[LOSSY], 40_000, |d| {
        add_unifilen(d, LOSSY, REAL);
    }));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "unicode-filename post failed:\n{log}");
    let got = std::fs::read(out.join(REAL)).unwrap_or_else(|e| {
        panic!("the Unicode Filename packet was ignored, so the lossy FileDesc spelling won: {e}\n{log}")
    });
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join(LOSSY).exists(),
        "the lossy spelling survived beside the real name - two files where \
         the producer described one\n{log}"
    );
    assert!(
        !out.join("Zq7Rm2Xd91C").exists(),
        "the obfuscated source name survived\n{log}"
    );
}
