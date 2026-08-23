//! The speculative recovery prefetch's ladder (`spec_ladder`,
//! `pick_rung`) and the prefetch task itself against an NZB fixture.
//!
//! A child of `workers`, out here for the size gate (TODO 106) alongside
//! `par_race_tests`, and for the same reasons: named for its file so
//! size-gate.py keeps scoring it as test code, and `use super::*` reaches
//! exactly what the inline module reached because `super` is still
//! `workers`.

use super::*;

fn ladder_nzb() -> Arc<Nzb> {
    Arc::new(
        Nzb::parse(
            br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"m.part1.rar" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="700000" number="1">pay@t</segment></segments>
 </file>
 <file subject='"m.vol07+08.par2" yEnc (1/2)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="500000" number="1">v8a@t</segment>
   <segment bytes="500000" number="2">v8b@t</segment>
  </segments>
 </file>
 <file subject='"m.vol00+01.par2" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="130000" number="1">v1@t</segment></segments>
 </file>
 <file subject='"m.vol01+02.par2" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="260000" number="1">v2@t</segment></segments>
 </file>
</nzb>"#,
        )
        .unwrap(),
    )
}

/// C5: the retained ladder is triples only - recovery volumes,
/// sorted smallest-first, counts read from the volume names. The
/// payload file never appears.
#[test]
fn the_ladder_retains_triples_smallest_first() {
    let n = ladder_nzb();
    assert_eq!(
        spec_ladder(&n),
        vec![(2, 1, 130_000), (3, 2, 260_000), (1, 8, 1_000_000)]
    );
}

/// Exact-fit escalation: the smallest rung covering the deficit,
/// falling back to the biggest left when none covers it.
#[test]
fn pick_rung_exact_fits_then_falls_back_to_biggest() {
    let n = ladder_nzb();
    let ladder = spec_ladder(&n);
    assert_eq!(pick_rung(&ladder, 1), 0, "deficit 1: the 1-slice rung");
    assert_eq!(pick_rung(&ladder, 2), 1, "deficit 2: skip the 1-slice rung");
    assert_eq!(pick_rung(&ladder, 3), 2, "deficit 3: only vol07+08 covers");
    assert_eq!(
        pick_rung(&ladder, 99),
        2,
        "deficit beyond every rung: the biggest left"
    );
}

/// A selected rung's requests carry exactly the volume's articles -
/// bracketed ids, part numbers, every id mapped to the rung's file
/// index - and the id map's key IS the `ArticleReq`'s handle (R9:
/// one allocation per id, pointer equality not string equality).
#[test]
fn a_selected_rung_builds_its_volumes_requests() {
    let n = ladder_nzb();
    let mut reqs = Vec::new();
    let mut idm = std::collections::HashMap::new();
    crate::repair::volume_reqs(&n, 1, &mut reqs, &mut idm);
    assert_eq!(
        reqs.iter().map(|r| (&*r.id, r.part)).collect::<Vec<_>>(),
        [("<v8a@t>", 1), ("<v8b@t>", 2)]
    );
    assert_eq!(idm.len(), 2);
    for r in &reqs {
        let (key, &fi) = idm.get_key_value(&r.id).expect("every request mapped");
        assert_eq!(fi, 1);
        assert!(
            Arc::ptr_eq(key, &r.id),
            "{}: the id map holds a COPY of the request id, not the handle",
            r.id
        );
    }
}

/// C5 measurement (ignored - it is a number, not a gate). Prices
/// what `spawn_spec_prefetch` RETAINS for the whole run before any
/// article has gone missing: a field-scale recovery set (25
/// volumes, 25k recovery segments, powerpost-length ids), RSS
/// bracketed around the spawn call itself. The body is
/// type-agnostic, so it drops onto the pre-C5 eager-ladder tree
/// unchanged and re-takes the before half.
///
/// Run: `cargo test -p nzbfast --release --bin nzbfast c5_spec -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn c5_spec_ladder_rss_at_field_scale() {
    fn rss_kb() -> u64 {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or(0)
    }
    const VOLS: usize = 25;
    const SEGS: usize = 1000;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(
        " <file subject='\"big.part01.rar\" yEnc (1/1)' date=\"1700000000\">\n\
         <groups><group>alt.binaries.test</group></groups>\n<segments>\n\
         <segment bytes=\"768000\" number=\"1\">payload@t</segment>\n\
         </segments>\n </file>\n",
    );
    for v in 0..VOLS {
        xml.push_str(&format!(
            " <file subject='\"big.vol{:03}+1000.par2\" yEnc (1/{SEGS})' date=\"1700000000\">\n\
             <groups><group>alt.binaries.test</group></groups>\n<segments>\n",
            v * SEGS
        ));
        for s in 0..SEGS {
            // A representative powerpost id: ~50 bytes bracketed.
            xml.push_str(&format!(
                "<segment bytes=\"768000\" number=\"{}\">vol{v:03}seg{s:04}.\
                 aBcDeFgHiJkLmNoPqRsT@powerpost.local</segment>\n",
                s + 1
            ));
        }
        xml.push_str("</segments>\n </file>\n");
    }
    xml.push_str("</nzb>\n");
    let n = Arc::new(Nzb::parse(xml.as_bytes()).expect("parse"));
    drop(xml);
    let rec_segs: usize = n
        .files
        .iter()
        .filter(|f| f.kind() == FileKind::Par2Volume)
        .map(|f| f.segments.len())
        .sum();
    let servers: Vec<(ServerConfig, nzbkit::pool::PoolConfig)> = Vec::new();
    let out_dir = std::env::temp_dir().join(format!("nzbfast-c5-{}", std::process::id()));
    let buf_pool = nzbkit::pool::BufPool::new(2);
    let prefetched: Arc<std::sync::Mutex<Vec<(usize, Vec<std::path::PathBuf>)>>> =
        Default::default();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let demand = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let before = rss_kb();
    let t0 = std::time::Instant::now();
    let task = spawn_spec_prefetch(
        true,
        true,
        &n,
        &servers,
        &[],
        &out_dir,
        &buf_pool,
        &prefetched,
        &stop,
        &demand,
    )
    .expect("volumes present, so the watcher must spawn");
    let spawn_cost = t0.elapsed();
    let after = rss_kb();
    // What rung selection pays post-C5 to build one volume's
    // requests - the added loss-to-first-recovery-BODY latency,
    // priced against the loop's 250 ms poll.
    let t1 = std::time::Instant::now();
    let mut reqs = Vec::new();
    let mut idm = std::collections::HashMap::new();
    crate::repair::volume_reqs(&n, 1, &mut reqs, &mut idm);
    let rung_cost = t1.elapsed();
    eprintln!(
        "C5 spec ladder RSS: {rec_segs} recovery segments across {VOLS} volumes; \
         RSS {before} -> {after} KB (delta {} KB), spawn {:?}, \
         one {}-article rung built in {:?}",
        after as i64 - before as i64,
        spawn_cost,
        reqs.len(),
        rung_cost,
    );
    stop.store(true, Ordering::Release);
    task.await.unwrap();
}
