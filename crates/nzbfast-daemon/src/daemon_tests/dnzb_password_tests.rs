//! TODO 358 item 5: an indexer's `X-DNZB-Password` header, carried on
//! the fetch, is one more source for `Job::password` - and it takes the
//! rung the NZB's own `<meta type="password">` holds, below the two the
//! user controls. The header off a real socket is pinned beside the
//! fetch (`nzbfast-api` `tests_grabs`); this is where the value LANDS.
//!
//! A child of daemon_tests, named for its file so size-gate.py's
//! CFG_TEST_MOD resolver reads it as test code; `use super::*` brings
//! the harness.

use super::*;

fn nzb(head: &str, seg: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <head>{head}</head>\
         <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
         <groups><group>g</group></groups><segments>\
         <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
         </segments></file></nzb>"
    )
}

fn fetched(xml: String, header_pw: &str) -> crate::fetch::Fetched {
    crate::fetch::Fetched {
        bytes: xml.into_bytes(),
        failure_link: String::new(),
        host: "indexer.example".to_string(),
        https: true,
        category: String::new(),
        password: header_pw.to_string(),
        addrs: Vec::new(),
        filename: String::new(),
    }
}

fn password_of(d: &Daemon, id: &str) -> Option<String> {
    d.queue
        .lock_ok()
        .iter()
        .find(|j| j.lock_ok().nzo_id == id)
        .map(|j| j.lock_ok().password.clone())
        .expect("the add is queued")
}

/// The whole ladder, one rung per add: the header fills an add that
/// carries nothing else, and loses to an explicit param, to the
/// `Name{{pw}}` convention and (the tie rule) to the NZB's own meta.
/// A blank header is no password at all, and the value survives a
/// restart because it is on the row as it is built.
#[test]
fn the_dnzb_password_header_takes_the_nzb_meta_rung() {
    with_daemon("dnzb-password", |d| {
        let add = |name: &str, f: &crate::fetch::Fetched, param: Option<&str>| {
            d.enqueue_fetched(
                f,
                name,
                "",
                -100,
                None,
                param,
                0,
                "test",
                DupeExempt::Nobody,
            )
            .expect("the add")
            .nzo_id
        };

        // Nothing else carries a password: the header is it.
        let only = add("Only.Header.nzb", &fetched(nzb("", "s1"), "hdrpw"), None);
        assert_eq!(password_of(d, &only).as_deref(), Some("hdrpw"));

        // An explicit API param outranks it.
        let param = add(
            "Explicit.Param.nzb",
            &fetched(nzb("", "s2"), "hdrpw"),
            Some("parampw"),
        );
        assert_eq!(password_of(d, &param).as_deref(), Some("parampw"));

        // So does the name convention.
        let named = add(
            "Named.Release{{namepw}}.nzb",
            &fetched(nzb("", "s3"), "hdrpw"),
            None,
        );
        assert_eq!(password_of(d, &named).as_deref(), Some("namepw"));

        // Same rung as the NZB meta, and the tie goes to the meta.
        let meta = add(
            "Meta.Release.nzb",
            &fetched(nzb("<meta type=\"password\">metapw</meta>", "s4"), "hdrpw"),
            None,
        );
        assert_eq!(password_of(d, &meta).as_deref(), Some("metapw"));

        // An indexer that always sends the header, blank when there is
        // nothing to say, must not hand the job an empty password.
        let blank = add("Blank.Header.nzb", &fetched(nzb("", "s5"), ""), None);
        assert_eq!(password_of(d, &blank), None);

        // On the row as it is built, so the stored record has it.
        let d2 = restart(d);
        assert_eq!(password_of(&d2, &only).as_deref(), Some("hdrpw"));
    });
}

/// The header parse's own rule, applied before the value reaches the
/// row: trimmed, and blank means absent.
#[test]
fn dnzb_password_trims_and_treats_blank_as_absent() {
    use crate::fetch::dnzb_password;
    assert_eq!(dnzb_password("s3cret").as_deref(), Some("s3cret"));
    assert_eq!(
        dnzb_password("  s3cret pass \t").as_deref(),
        Some("s3cret pass")
    );
    assert_eq!(dnzb_password(""), None);
    assert_eq!(dnzb_password("   "), None);
}
