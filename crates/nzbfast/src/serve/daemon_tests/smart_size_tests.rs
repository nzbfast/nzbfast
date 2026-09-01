//! F5: what a Smart Folder rule does with a job whose declared size is
//! UNKNOWN, end to end through `Daemon::enqueue`.
//!
//! `smart/tests.rs` pins the same question at the RULE, which is where
//! the arithmetic lives; this file pins that the 0 really does travel
//! the whole way - `Nzb::eager_bytes` to `resolve_add_identity` to
//! `smart::first_match` to the row's `category` and `total_bytes` - so
//! a change at either end cannot quietly leave the other behind. The
//! behaviour asserted here is TODAY's and is not endorsed: which answer
//! a size-gated rule should give when the size is unknown is the open
//! product question in the zero-declared-bytes handoff (claim
//! `nzb-zero-bytes-downstream`).
//!
//! A child of daemon_tests, out for the size gate (TODO 106). The
//! module is named for its file so size-gate.py's CFG_TEST_MOD resolver
//! still reads it as test code; `use super::*` brings `with_daemon`.

use super::*;

/// An NZB whose `<segment>`s carry NO `bytes=` attribute at all - the
/// shape `nzbkit::nzb`'s own attribute comment accepts on purpose, and
/// whose absence it reads as "unknown, not zero". Four segments so the
/// job is plainly not an empty post.
fn no_bytes_nzb(name: &str, seg: &str) -> String {
    let segs: String = (1..=4)
        .map(|n| format!("<segment number=\"{n}\">{seg}-{n}@x</segment>"))
        .collect();
    format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/4)\">\
         <groups><group>g</group></groups><segments>{segs}</segments></file></nzb>"
    )
}

/// The same post with its bytes declared, as the control arm.
fn sized_nzb(name: &str, seg: &str, per: u64) -> String {
    let segs: String = (1..=4)
        .map(|n| format!("<segment bytes=\"{per}\" number=\"{n}\">{seg}-{n}@x</segment>"))
        .collect();
    format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/4)\">\
         <groups><group>g</group></groups><segments>{segs}</segments></file></nzb>"
    )
}

#[test]
fn a_job_that_declares_no_bytes_misses_every_size_gated_smart_folder_rule() {
    with_daemon("smart-unknown-size", |d| {
        // One rule, name-correct for both adds, gated on a size the
        // control arm clears comfortably.
        *d.smart_folders.lock_ok() = vec![crate::smart::Rule {
            name: "films".into(),
            pattern: "Unknownsize".into(),
            not_match: String::new(),
            min_size: 2_000_000,
            max_size: 0,
            category: "films".into(),
            tv_sort: false,
        }];

        let cat_of = |id: &str| {
            d.queue
                .lock_ok()
                .iter()
                .find(|j| j.lock_ok().nzo_id == id)
                .map(|j| {
                    let g = j.lock_ok();
                    (g.category.clone(), g.total_bytes, g.smart_rule.clone())
                })
                .expect("the row this add published")
        };

        // Control: the identical post WITH its bytes declared takes the
        // rule, so the pattern and the threshold are both known good.
        let sized = d
            .enqueue(
                sized_nzb("a.mkv", "sized", 768_000).as_bytes(),
                "Unknownsize.Control.2024.1080p.nzb",
                "",
                -100,
                None,
                None,
                "test",
                false,
            )
            .expect("the sized add")
            .nzo_id;
        let (cat, bytes, rule) = cat_of(&sized);
        assert_eq!(cat, "films", "the control arm takes the rule");
        assert_eq!(bytes, 4 * 768_000, "and its size is the declared one");
        assert_eq!(rule, "films");

        // The subject: no `bytes=` anywhere. `dupe_ok` because the two
        // adds are deliberately near-identical releases and the
        // duplicate ladder would otherwise park this one.
        let silent = d
            .enqueue(
                no_bytes_nzb("a.mkv", "silent").as_bytes(),
                "Unknownsize.Silent.2024.2160p.nzb",
                "",
                -100,
                None,
                None,
                "test",
                true,
            )
            .expect("an NZB with no byte attributes is accepted, by design")
            .nzo_id;
        let (cat, bytes, rule) = cat_of(&silent);
        assert_eq!(
            bytes, 0,
            "the manifest declared nothing, so the row carries 0 - which \
             is the UNKNOWN this whole file is about, not a measurement"
        );
        assert_eq!(
            cat, "",
            "and the rule declined it: the job files under the default \
             category even though its name matched"
        );
        assert_eq!(
            rule, "",
            "no rule is recorded, so 'why is this here?' has no answer on \
             the row either"
        );
    });
}
