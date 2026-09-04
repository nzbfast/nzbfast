//! §310 stage 2, the ECONOMICS: a heal must fetch only the damaged
//! remainder, and the two arms are measured off the mock's own body
//! ledger.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//!
//! # The failure mode this exists to make visible
//!
//! `heal.rs` landed the wiring and `heal_tests.rs` pins it:
//! the queued row carries `heal_dir`, a season folder produces one job
//! per post, a second click is refused. None of that pins the claim the
//! feature is SOLD on. A heal that quietly re-downloads the whole
//! release still succeeds - the file comes back, the row reads
//! Completed, every wiring test stays green - and the user has simply
//! paid for a whole release to fix one bad block. There is no red
//! anywhere for that, which is why it needs a COUNT rather than an
//! assertion about a field.
//!
//! # The A/B, and its one variable
//!
//! Both legs are the same release shape - three equal members, one
//! verification-only recovery index, 30 payload articles - settled by a
//! real job into a real folder, damaged on disk, and then healed through
//! `mode=heal_start`. The ONLY thing that differs is how much of the
//! folder is still byte-exact:
//!
//! * **Leg A, the baseline.** All three members damaged. Nothing on
//!   disk is donatable, so the heal re-fetches the whole payload. This
//!   is what a heal costs with no intact bytes to take, and it is the
//!   honest worst case rather than a straw man: it is exactly what the
//!   feature would cost on EVERY heal if the donor road were not wired.
//! * **Leg B, the treatment.** ONE member damaged. Two members are
//!   byte-exact on disk and are taken whole off it; only the damaged
//!   member and the index come off the wire.
//!
//! Measured 2 Sep 2026 on the dev Mac, and printed by the test so a
//! reader gets the numbers without re-running it: **leg A 32 bodies,
//! leg B 12, against the same 30-article payload.**
//!
//! # Why the treatment leg is MULTI-FILE, which is not a convenience
//!
//! Adoption before the plan is WHOLE FILES only, and `get/donor.rs`
//! argues it at length: skipping an ARTICLE means proving the donor
//! covers the decoded byte range that article would have written, and an
//! NZB states only ENCODED segment sizes, so a partial file's remainder
//! cannot be named before its bodies arrive. `daemon_ladder`'s
//! `a_promoted_replacement_does_not_refetch_what_the_predecessor_left_whole`
//! makes the same point for the `alt_from` donor road, and pins the
//! limit on its one-file sibling. A single-file heal fixture would
//! therefore measure the honest worst case and read as a failure of the
//! feature, so the shape here is the multi-file one on both legs and the
//! worst case is leg A's damage rather than leg A's shape.
//!
//! # The cost, stated beside the saving
//!
//! A job with donors fetches its PAR2 index TWICE: once for the pre-pass
//! that reads the FileDesc digests, and once for the plan, whose
//! activation needs the packets in memory. That is the whole extra cost
//! of the arm and both bounds below count it. On leg A it buys nothing,
//! which is why leg A costs one article MORE than the same post's
//! ordinary download - also printed, so the price of a wasted pre-pass
//! is on the record next to the saving it usually buys.
//!
//! # The PAR2 set is synthesized, not shelled out
//!
//! `par2 create` is not on every box (CI carries 0.8.1, the dev boxes
//! 1.3.0), and `daemon_donor` and `daemon_ladder` both gate themselves
//! off the tree when it is missing. Nothing here needs a recovery slice:
//! the manifest capture reads FileDesc and IFSC packets, and the donor
//! pre-pass reads FileDesc packets, so a verification-only index over
//! real digests is the whole requirement. Synthesizing it - the same
//! builder `daemon_manifest` uses, widened to several members - is what
//! lets this measurement run everywhere the suite does, which for a
//! number the feature is sold on is worth more than the fidelity of a
//! recovery block nothing reads.

use super::*;
use crate::payloads;

/// PAR2 slice size for the synthesized index. Only the IFSC packets
/// read it; nothing here repairs.
const BLOCK: usize = 4096;
/// Article size, so a member's article count is a round number.
const ART: usize = 32_000;
/// Every member is this many bytes: ten articles each, three members a
/// release, which leaves the saving far outside anything a rounding
/// could account for.
const MEMBER: usize = 320_000;

fn md5_of(b: &[u8]) -> [u8; 16] {
    use md5::Digest;
    md5::Md5::digest(b).into()
}

/// Wrap a body in a valid packet header (magic, length, body MD5).
fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(b"PAR2\0PKT");
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5 = md5_of(&p[32..]);
    p[16..32].copy_from_slice(&md5);
    p
}

/// A minimal, honest verification-only PAR2 index over several files:
/// real whole-file MD5, real md5-16k, real per-block MD5+CRC32 with the
/// last block zero-padded, no recovery slices.
///
/// The multi-member widening of `daemon_manifest`'s own builder, which
/// is where the packet shape and the name-padding rule are argued. File
/// ids ascend with the member index, so the Main packet's id list is in
/// the ascending order the spec asks for.
fn par2_index_over(set_id: u8, files: &[(&str, &[u8])]) -> Vec<u8> {
    let set_id = [set_id; 16];
    let fid = |i: usize| -> [u8; 16] { [9u8 + i as u8; 16] };

    let mut main = Vec::new();
    main.extend_from_slice(&(BLOCK as u64).to_le_bytes());
    main.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for i in 0..files.len() {
        main.extend_from_slice(&fid(i));
    }
    let mut buf = pkt(set_id, b"PAR 2.0\0Main\0\0\0\0", &main);

    for (i, (name, data)) in files.iter().enumerate() {
        let mut desc = Vec::new();
        desc.extend_from_slice(&fid(i));
        desc.extend_from_slice(&md5_of(data));
        desc.extend_from_slice(&md5_of(&data[..data.len().min(16384)]));
        desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
        desc.extend_from_slice(name.as_bytes());
        // Null-padded to a multiple of 4, per spec - the scanner holds
        // every packet length to that, so an unpadded name drops the
        // whole FileDesc and with it the file.
        while !desc.len().is_multiple_of(4) {
            desc.push(0);
        }

        let mut ifsc = Vec::new();
        ifsc.extend_from_slice(&fid(i));
        for chunk in data.chunks(BLOCK) {
            let mut padded = chunk.to_vec();
            padded.resize(BLOCK, 0);
            ifsc.extend_from_slice(&md5_of(&padded));
            let mut h = crc32fast::Hasher::new();
            h.update(&padded);
            ifsc.extend_from_slice(&h.finalize().to_le_bytes());
        }

        buf.extend(pkt(set_id, b"PAR 2.0\0FileDesc", &desc));
        buf.extend(pkt(set_id, b"PAR 2.0\0IFSC\0\0\0\0", &ifsc));
    }
    buf
}

/// The member names both releases post. Deliberately the same on both
/// legs: the two folders are separate and the shapes are meant to read
/// as identical, so the only difference a reader has to hold is which
/// members each leg damages.
const MEMBERS: [&str; 3] = ["m1.bin", "m2.bin", "m3.bin"];

/// One release, built and registered with the mock in one step: three
/// members plus the index over them, every id live.
///
/// `tag` prefixes every article id, so the body ledger can be read back
/// per member - a count alone would pass a run that fetched a whole
/// member and skipped the damaged one.
struct Release {
    /// `(posted name, segments)` in NZB order.
    files: Vec<(String, Vec<(String, u64, u32)>)>,
    /// The member bytes, in `MEMBERS` order, for the damage step.
    bodies: Vec<Vec<u8>>,
}

impl Release {
    fn build(tag: &str, set_id: u8, seed: u64, articles: &mut HashMap<String, Vec<u8>>) -> Release {
        let bodies: Vec<Vec<u8>> = (0..MEMBERS.len())
            .map(|i| payloads::unique_payload(MEMBER, seed + i as u64))
            .collect();
        let over: Vec<(&str, &[u8])> = MEMBERS
            .iter()
            .zip(&bodies)
            .map(|(n, b)| (*n, b.as_slice()))
            .collect();
        let index = par2_index_over(set_id, &over);

        let mut files = Vec::new();
        for (i, name) in MEMBERS.iter().enumerate() {
            let segs = make_file_articles(name, &bodies[i], ART, &member_tag(tag, i), articles);
            files.push(((*name).to_string(), segs));
        }
        let segs = make_file_articles("testset.par2", &index, ART, &index_tag(tag), articles);
        files.push(("testset.par2".to_string(), segs));
        Release { files, bodies }
    }

    /// Articles declared for one member.
    fn arts(&self, name: &str) -> u64 {
        self.files
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, s)| s.len() as u64)
            .unwrap_or_else(|| panic!("{name} is not in this post"))
    }

    /// The payload the plan would fetch with no donor at all. NOT every
    /// declared article: this post has no recovery volumes, but stating
    /// the denominator as the payload keeps it the same quantity
    /// `daemon_ladder` scores against, where a clean run does defer them.
    fn payload_arts(&self) -> u64 {
        MEMBERS.iter().map(|n| self.arts(n)).sum()
    }

    /// Articles of the recovery INDEX, which the pre-pass and the plan
    /// each fetch once.
    fn index_arts(&self) -> u64 {
        self.arts("testset.par2")
    }

    fn xml(&self) -> String {
        let mut x = String::from(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        for (name, segs) in &self.files {
            x.push_str(&format!(
                "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
                segs.len()
            ));
            for (id, bytes, num) in segs {
                x.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
                ));
            }
            x.push_str("    </segments>\n  </file>\n");
        }
        x.push_str("</nzb>\n");
        x
    }
}

fn member_tag(tag: &str, i: usize) -> String {
    format!("{tag}m{}", i + 1)
}

fn index_tag(tag: &str) -> String {
    format!("{tag}ix")
}

/// Percent-encode a filesystem path for a query parameter. The daemon
/// urldecodes `value`, and a temp path can carry anything.
fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// What one leg measured.
struct Leg {
    tag: &'static str,
    /// The library folder that was damaged and healed.
    dir: PathBuf,
    /// Bodies the heal pulled, over its own window.
    bodies: u64,
    /// The ids it asked for, in order.
    asked: Vec<String>,
    /// What the same post cost on its ordinary, donor-free download.
    first_run: u64,
}

#[tokio::test(flavor = "multi_thread")]
async fn a_heal_fetches_only_the_damaged_remainder() {
    let base = std::env::temp_dir().join(format!("nzbfast-heal-ab-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&base);

    // `unique_payload` and not the suite's `payload`: these members are
    // damaged and then re-fetched, and a generator whose window repeats
    // lets a repair close a hole out of the file's own bytes - which
    // would score a saving nothing on the wire made.
    let mut articles = HashMap::new();
    let base_rel = Release::build("ba", 3, 0x11ea_1000, &mut articles);
    let treat_rel = Release::build("tr", 7, 0x11ea_2000, &mut articles);

    // Identical shapes, asserted rather than assumed: the A/B's one
    // variable is the damage, and a fixture edit that made the two posts
    // different sizes would quietly turn the printed comparison into a
    // comparison of two things.
    let payload_arts = base_rel.payload_arts();
    let index_arts = base_rel.index_arts();
    assert_eq!(payload_arts, treat_rel.payload_arts(), "same payload shape");
    assert_eq!(index_arts, treat_rel.index_arts(), "same index shape");
    assert!(index_arts > 0, "both posts must carry a par2 index");
    let damaged_arts = treat_rel.arts(MEMBERS[2]);

    let base_xml = base_rel.xml();
    let treat_xml = treat_rel.xml();
    let base_bodies = base_rel.bodies.clone();
    let treat_bodies = treat_rel.bodies.clone();

    let srv = MockServer::start(articles, Chaos::default()).await;
    let served = srv.served.clone();
    let body_log = srv.body_log.clone();

    let dir = base.join("run");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let complete_root = dir.join("complete");
    let d = serve(&dir, {
        let cfg = cfg.clone();
        let complete_root = complete_root.clone();
        move |port: u16| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            c.env("NZBFAST_OPEN", "1")
                .env("NZBFAST_NO_ENRICH", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("serve")
                .arg("--bind")
                .arg("127.0.0.1")
                .arg("--port")
                .arg(port.to_string())
                .arg("--out")
                .arg(&complete_root)
                .arg("--connections")
                .arg("4");
            c
        }
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let set = |name: &str, value: &str| {
            let r = http(
                port,
                &format!("/api?mode=config&name={name}&value={value}&output=json"),
                None,
            );
            assert!(r.contains("\"status\":true"), "set {name}: {r}");
        };
        let upload = |fname: &str, xml: &str| -> String {
            let boundary = "----healb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; \
                     filename=\"{fname}\"\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .map(|s| format!("SABnzbd_nzo_{s}"))
                .expect("addfile returned no nzo_id")
        };
        // Read out of the `history` array by `serde_json` and never by a
        // substring search over the SAB payload - see the harness's
        // `history_slot` for why that answers a different question. By
        // nzo_id rather than by name, because a heal carries the ORIGINAL
        // job's name and the two rows are otherwise indistinguishable.
        let terminal = |id: &str, tries: u32| -> String {
            for _ in 0..tries {
                let h = http(port, "/api?mode=history&output=json", None);
                let v: serde_json::Value =
                    serde_json::from_str(&h).unwrap_or(serde_json::Value::Null);
                if let Some(s) = v["history"]["slots"].as_array().and_then(|a| {
                    a.iter().find(|s| {
                        s["nzo_id"] == id && (s["status"] == "Completed" || s["status"] == "Failed")
                    })
                }) {
                    return s["status"].as_str().unwrap_or_default().to_string();
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("job {id} never settled");
        };
        let job_dir = |stem: &str| -> PathBuf {
            std::fs::read_dir(&complete_root)
                .expect("complete/ exists")
                .flatten()
                .map(|e| e.path())
                .find(|p| {
                    p.is_dir()
                        && p.file_name()
                            .is_some_and(|n| n.to_string_lossy().contains(stem))
                })
                .unwrap_or_else(|| panic!("no completed dir for {stem}"))
        };

        // The on-switch. `write_manifest` defaults OFF, so without this
        // no manifest is written, nothing convicts damage and there is
        // nothing to heal from.
        set("write_manifest", "1");

        // ---- Both releases settle clean, and the ordinary no-donor
        // cost of each is read off the ledger as it happens. ----
        let settle = |fname: &str, xml: &str| -> u64 {
            let before = served.load(std::sync::atomic::Ordering::Relaxed);
            let id = upload(fname, xml);
            assert_eq!(terminal(&id, 900), "Completed", "{fname} never settled");
            served.load(std::sync::atomic::Ordering::Relaxed) - before
        };
        let base_first_run = settle("Heal.Baseline.S01E01.1080p.nzb", &base_xml);
        let treat_first_run = settle("Heal.Treatment.S02E02.1080p.nzb", &treat_xml);

        let base_dir = job_dir("Heal.Baseline");
        let treat_dir = job_dir("Heal.Treatment");
        for jd in [&base_dir, &treat_dir] {
            assert!(
                jd.join(".nzbfast.manifest").is_file(),
                "no manifest in {}",
                jd.display()
            );
            // The library state a heal actually runs against: the
            // recovery files are swept once the manifest is written, so
            // the folder can be checked and cannot be repaired out of
            // anything it still holds.
            let left: Vec<PathBuf> = std::fs::read_dir(jd)
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "par2"))
                .collect();
            assert!(left.is_empty(), "recovery files not swept: {left:?}");
        }

        // ---- Damage, and it is the A/B's one variable. One byte
        // mid-file moves the whole-file MD5 and the block the manifest
        // covers, which is all a heal needs to convict a member. The
        // bytes are asserted to have really moved, so a fixture whose
        // damage silently stopped landing is red here rather than
        // reporting a heal of nothing. ----
        let damage = |jd: &Path, member: &str, was: &[u8]| {
            let p = jd.join(member);
            let mut b = std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            assert_eq!(b, was, "{member} did not settle byte-exact");
            b[MEMBER / 2] ^= 0x5a;
            std::fs::write(&p, &b).unwrap();
        };
        for (i, m) in MEMBERS.iter().enumerate() {
            damage(&base_dir, m, &base_bodies[i]);
        }
        damage(&treat_dir, MEMBERS[2], &treat_bodies[2]);

        // ---- The offer, which spends nothing, names exactly what was
        // damaged in each folder. ----
        let offer = |jd: &Path| -> serde_json::Value {
            let r = http(
                port,
                &format!(
                    "/api?mode=heal_offer&value={}&output=json",
                    enc(&jd.to_string_lossy())
                ),
                None,
            );
            serde_json::from_str(&r).unwrap_or_else(|e| panic!("heal_offer: {e}: {r}"))
        };
        let before_offer = served.load(std::sync::atomic::Ordering::Relaxed);
        for (jd, want) in [
            (&base_dir, MEMBERS.to_vec()),
            (&treat_dir, vec![MEMBERS[2]]),
        ] {
            let o = offer(jd);
            assert_eq!(o["status"], true, "{o}");
            let t = o["targets"].as_array().expect("targets");
            // ONE target either way: three damaged members of one post
            // are one download, which is the grouping `plan` exists for.
            assert_eq!(t.len(), 1, "one damaged post per folder: {o}");
            assert_eq!(t[0]["files"], serde_json::json!(want), "{o}");
            assert_eq!(t[0]["source"], "recorded", "{o}");
        }
        assert_eq!(
            served.load(std::sync::atomic::Ordering::Relaxed),
            before_offer,
            "the offer must not touch the wire"
        );

        // ---- The two heals, each measured over its own window. ----
        let run_leg = |tag: &'static str, jd: &PathBuf, first_run: u64| -> Leg {
            let before = served.load(std::sync::atomic::Ordering::Relaxed);
            let log_at = body_log.lock().unwrap().len();
            let r = http(
                port,
                &format!(
                    "/api?mode=heal_start&value={}&output=json",
                    enc(&jd.to_string_lossy())
                ),
                None,
            );
            let v: serde_json::Value =
                serde_json::from_str(&r).unwrap_or_else(|e| panic!("heal_start: {e}: {r}"));
            assert_eq!(v["status"], true, "{v}");
            assert!(v["refused"].as_array().is_some_and(|a| a.is_empty()), "{v}");
            let started = v["started"].as_array().expect("started");
            assert_eq!(started.len(), 1, "one heal job per damaged post: {v}");
            let id = started[0]["nzo_id"].as_str().expect("nzo_id").to_string();
            assert_eq!(
                terminal(&id, 900),
                "Completed",
                "the {tag} heal must complete"
            );
            Leg {
                tag,
                dir: jd.clone(),
                bodies: served.load(std::sync::atomic::Ordering::Relaxed) - before,
                asked: body_log.lock().unwrap()[log_at..].to_vec(),
                first_run,
            }
        };
        let leg_a = run_leg("baseline", &base_dir, base_first_run);
        let leg_b = run_leg("treatment", &treat_dir, treat_first_run);

        // ---- The measurement, printed so a reader gets it without
        // re-running the suite. ----
        for leg in [&leg_a, &leg_b] {
            println!(
                "§310 HEAL A/B leg {}: the heal fetched {} body/bodies against a \
                 {payload_arts}-article payload; the same post's ordinary download \
                 cost {}.",
                leg.tag, leg.bodies, leg.first_run
            );
        }

        // Leg A is the honest worst case and it is asserted as one: with
        // no intact member to take, a heal is a full re-download plus the
        // pre-pass index that bought nothing.
        assert!(
            leg_a.bodies >= payload_arts,
            "with every member damaged there is nothing whole to donate, so leg A \
             must re-fetch the payload in full. If this is red, article-level \
             adoption landed and TODO 310 wants updating: {} < {payload_arts}. \
             Asked for: {:?}",
            leg_a.bodies,
            leg_a.asked
        );
        assert!(
            leg_a.bodies <= payload_arts + 2 * index_arts,
            "leg A must cost the payload plus the index twice and no more: {} against \
             {payload_arts} + 2 x {index_arts}. Asked for: {:?}",
            leg_a.bodies,
            leg_a.asked
        );

        // The headline, and the claim the feature is sold on.
        assert!(
            leg_b.bodies < leg_a.bodies,
            "the whole point of a heal is that damage costs less than a release: \
             leg B fetched {} against leg A's {} on the same shape. Asked for: {:?}",
            leg_b.bodies,
            leg_a.bodies,
            leg_b.asked
        );
        assert!(
            leg_b.bodies < payload_arts,
            "a heal must fetch only the damaged remainder: {} bodies against a \
             {payload_arts}-article payload, with two of three members byte-exact \
             on disk. Asked for: {:?}",
            leg_b.bodies,
            leg_b.asked
        );
        // ...and the EXACT remainder, so a saving that quietly shrinks to
        // one article still fails here.
        let want = damaged_arts + 2 * index_arts;
        assert!(
            leg_b.bodies <= want,
            "the unadopted remainder is {damaged_arts} damaged article(s) plus \
             {index_arts} index article(s) fetched twice = {want}; got {}. \
             Asked for: {:?}",
            leg_b.bodies,
            leg_b.asked
        );
        // Named, not just counted: a count alone would pass a run that
        // fetched a whole member and skipped the damaged one.
        for i in [0usize, 1] {
            let tag = member_tag("tr", i);
            let hits: Vec<&String> = leg_b.asked.iter().filter(|id| id.contains(&tag)).collect();
            assert!(
                hits.is_empty(),
                "{} was byte-exact on disk and must be taken from there, not \
                 fetched: {hits:?}",
                MEMBERS[i]
            );
        }
        let damaged_tag = member_tag("tr", 2);
        assert!(
            leg_b.asked.iter().any(|id| id.contains(&damaged_tag)),
            "the damaged member must still come off the wire: {:?}",
            leg_b.asked
        );

        // And the point of the exercise: the folder is repaired, IN
        // PLACE. `heal.rs` states the limit this rests on - the
        // healed file lands wherever this daemon files that release,
        // which is the damaged folder for anything nzbfast produced and
        // nobody moved, and these two are exactly that. The shipped
        // checker is run over it rather than a digest re-derived here,
        // so what is asserted is what a user would see.
        for leg in [&leg_a, &leg_b] {
            let code = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
                .arg("verify")
                .arg(&leg.dir)
                .status()
                .expect("verify ran")
                .code()
                .unwrap_or(-1);
            assert_eq!(
                code,
                0,
                "the {} folder must verify clean after its heal: {}",
                leg.tag,
                leg.dir.display()
            );
        }
    })
    .await
    .unwrap();
}
