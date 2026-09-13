//! `output=xml`, held to SAB's own `XmlOutputFactory` rather than to
//! what we happen to emit.
//!
//! The expected documents below were derived by running SAB's factory
//! in the head - `_dict`/`_list`/`run` from `sabnzbd/api.py`, byte-for-
//! byte identical at the `4.5.0` and `5.1.2` tags - over the JSON body
//! each of our arms actually sends. Where a rule looked arbitrary the
//! test says WHY it is SAB's rule, because the next reader's instinct
//! will be to "fix" it: the trailing newline inside every element, the
//! capitalised `True`, the unescaped quote, the hostname used as an
//! element name.
//!
//! ONE PLACE THE DOCUMENTS BELOW ARE ORDERED DIFFERENTLY FROM SAB'S,
//! and it is not a defect this lane introduced: `serde_json::Map` is a
//! `BTreeMap`, so an object's keys come out ALPHABETICAL where Python
//! emits them in insertion order. Our JSON bodies have always been
//! sorted that way, so the XML inherits it rather than diverging from
//! it, and SAB's format only asks a client to read a DICT by name -
//! only LISTS are positional, and list order is preserved exactly.
//!
//! One test per mode this teaches XML to, which is the bar the chip
//! set. The last two are the regression tests that matter more than any
//! of them: a caller that does not ask for XML must get the JSON path
//! untouched, and a mode nobody listed must still produce a
//! well-formed document rather than a bare fragment.

use super::*;
use serde_json::json;

/// `mode=version`. SAB: `report(keyword="version", data="4.5.0")`.
///
/// Our body is a SUPERSET - `nzbfast` and `beta` sit beside `version` -
/// and SAB's document has no element for them, so they are dropped.
/// That is the shape a client written against SAB parses.
#[test]
fn version_is_the_sab_element_only() {
    let out = sab_xml_body(
        "version",
        &json!({"version": "4.5.0", "nzbfast": "1.3.0", "beta": "2"}),
    );
    assert_eq!(
        out,
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<version>4.5.0</version>\n\n"
    );
}

/// `mode=get_cats`. SAB: `report(keyword="categories", data=[...])`,
/// and `categories` IS in `_PLURAL_TO_SINGLE`, so the rows are
/// `<category>` and not the `<item>` fallback.
#[test]
fn get_cats_rows_are_category_not_item() {
    let out = sab_xml_body("get_cats", &json!({"categories": ["*", "tv"]}));
    assert!(
        out.contains("<categories><category>*</category>\n<category>tv</category>\n</categories>"),
        "{out}"
    );
    assert!(!out.contains("<item>"), "{out}");
}

/// `mode=get_scripts`. `scripts` -> `script`, same table.
#[test]
fn get_scripts_rows_are_script() {
    let out = sab_xml_body("get_scripts", &json!({"scripts": ["None", "clean.sh"]}));
    assert!(
        out.contains("<scripts><script>None</script>\n<script>clean.sh</script>\n</scripts>"),
        "{out}"
    );
}

/// `mode=warnings`. A list of OBJECTS under a key that IS in the
/// table, so each row is `<warning>` - the `slot` default never gets a
/// look in. All four of SAB's keys ride inside it, `origin` included
/// (audit finding 3).
#[test]
fn warnings_rows_are_warning_with_all_four_keys() {
    let out = sab_xml_body(
        "warnings",
        &json!({"warnings": [{
            "type": "WARNING",
            "text": "No Usenet server is configured",
            "time": 1788143274_u64,
            "origin": "nzbfast",
        }]}),
    );
    assert!(out.contains("<warnings><warning>"), "{out}");
    for frag in [
        "<type>WARNING</type>",
        "<text>No Usenet server is configured</text>",
        "<time>1788143274</time>",
        "<origin>nzbfast</origin>",
    ] {
        assert!(out.contains(frag), "missing {frag} in {out}");
    }
    assert!(!out.contains("<slot>"), "{out}");
}

/// An EMPTY warnings list is still the container element, not an absent
/// one: SAB's `_list` writes the wrapper whether or not it wrote a
/// child. A client that reads `<warnings>` unconditionally would throw
/// on the absence.
#[test]
fn empty_list_still_emits_its_container() {
    let out = sab_xml_body("warnings", &json!({"warnings": []}));
    assert!(out.contains("<warnings></warnings>"), "{out}");
}

/// `mode=status` and `mode=fullstatus` are ONE function in SAB's
/// `_api_table` and one element here, which is audit finding 5 carried
/// into the XML path. A bool renders as Python's `str(True)`.
#[test]
fn status_and_fullstatus_are_one_document() {
    let body = json!({"status": {
        "paused": false,
        "uptime": "2d",
        "have_warnings": "0",
        "warnings": [],
        "servers": [{"servername": "news.example.com", "serveractive": true}],
    }});
    let a = sab_xml_body("status", &body);
    let b = sab_xml_body("fullstatus", &body);
    assert_eq!(a, b);
    assert!(a.contains("<paused>False</paused>\n"), "{a}");
    assert!(a.contains("<uptime>2d</uptime>\n"), "{a}");
    // `servers` -> `server`, and the row is an OBJECT, so `_dict` names
    // it from the table rather than falling back to `slot`.
    assert!(
        a.contains(
            "<servers><server><serveractive>True</serveractive>\n<servername>news.example.com</servername>\n</server>\n</servers>\n"
        ),
        "{a}"
    );
}

/// `mode=get_config`. Nested objects recurse; `categories` inside it
/// keeps its own singular from the same table.
#[test]
fn get_config_nests_and_keeps_category_rows() {
    let out = sab_xml_body(
        "get_config",
        &json!({"config": {
            "misc": {"complete_dir": "/downloads"},
            "categories": [{"name": "*", "order": 0, "newzbin": "", "priority": -100}],
        }}),
    );
    assert!(
        out.contains("<misc><complete_dir>/downloads</complete_dir>\n</misc>\n"),
        "{out}"
    );
    assert!(
        out.contains("<categories><category><name>*</name>\n"),
        "{out}"
    );
    // An empty STRING is an empty element, and so is a JSON null - SAB's
    // `xml_name(None)` is `""`, never the word "None".
    assert!(out.contains("<newzbin></newzbin>"), "{out}");
    assert!(out.contains("<order>0</order>"), "{out}");
}

/// `mode=get_files`. `files` -> `file`, and `bytes` stays the `"%.2f"`
/// STRING audit finding 9 made it - the XML path must not quietly
/// re-number it.
#[test]
fn get_files_rows_are_file_and_bytes_stays_a_string() {
    let out = sab_xml_body(
        "get_files",
        &json!({"files": [{
            "filename": "big.rar",
            "bytes": "2100000.00",
            "bytes_total": 2_100_000_u64,
            "age": "1135d",
            "nzf_id": "nzf_1",
            "status": "finished",
        }]}),
    );
    assert!(
        out.contains("<files><file><age>1135d</age>\n<bytes>2100000.00</bytes>\n"),
        "{out}"
    );
    assert!(out.contains("<filename>big.rar</filename>\n"), "{out}");
    assert!(out.contains("<bytes>2100000.00</bytes>"), "{out}");
    assert!(out.contains("<age>1135d</age>"), "{out}");
}

/// `mode=queue`. `slots` is NOT in the table, so its object rows take
/// the `_list` default and come out as `<slot>` - the hard-coded name
/// SAB's own docstring calls out, and the one a client indexes on.
#[test]
fn queue_slots_use_the_slot_fallback() {
    let out = sab_xml_body(
        "queue",
        &json!({"queue": {
            "paused": false,
            "speedlimit": "0",
            "slots": [{"nzo_id": "SABnzbd_nzo_1", "filename": "Some.Job"}],
        }}),
    );
    assert!(
        out.contains(
            "<slots><slot><filename>Some.Job</filename>\n<nzo_id>SABnzbd_nzo_1</nzo_id>\n</slot>\n</slots>\n"
        ),
        "{out}"
    );
    assert!(
        out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<queue>"),
        "{out}"
    );
}

/// `mode=history`. Same `<slot>` rule one payload over.
#[test]
fn history_slots_use_the_slot_fallback() {
    let out = sab_xml_body(
        "history",
        &json!({"history": {"noofslots": 1, "slots": [{"nzo_id": "h1", "status": "Completed"}]}}),
    );
    assert!(out.contains("<history><noofslots>1</noofslots>\n"), "{out}");
    assert!(
        out.contains("<slots><slot><nzo_id>h1</nzo_id>\n<status>Completed</status>\n</slot>\n"),
        "{out}"
    );
}

/// `mode=server_stats`. SAB passes `keyword=""` here, so the document
/// is wrapped in `<result>` - and `servers` is a DICT keyed by
/// hostname, which SAB turns into element NAMES without escaping or
/// validating them. `news.example.com` is not a name any schema would
/// accept; it is what SAB emits, and a client reads it positionally.
#[test]
fn server_stats_wraps_in_result_and_names_elements_after_hosts() {
    let out = sab_xml_body(
        "server_stats",
        &json!({
            "total": 100_u64,
            "servers": {"news.example.com": {"total": 100_u64, "articles_tried": {"2026-09-09": 5}}},
        }),
    );
    assert!(
        out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<result>"),
        "{out}"
    );
    assert!(out.contains("<servers><news.example.com>"), "{out}");
    assert!(
        out.contains("<articles_tried><2026-09-09>5</2026-09-09>\n</articles_tried>\n"),
        "{out}"
    );
    assert!(
        out.contains("<total>100</total>\n</news.example.com>\n"),
        "{out}"
    );
}

/// The ack modes. SAB writes these as a bare `report()`, whose XML is
/// `run("result", {"status": True})` - so `<result>` with the bool
/// inside, NOT a bare `<status>`.
#[test]
fn acks_are_result_wrapped() {
    for mode in ["pause", "resume", "restart", "shutdown"] {
        let out = sab_xml_body(mode, &json!({"status": true}));
        assert_eq!(
            out,
            "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<result><status>True</status>\n</result>\n\n",
            "{mode}"
        );
    }
}

/// `mode=addfile` / `mode=addurl`: `keyword=""` with a list of ids.
/// `nzo_ids` is not in the table and its rows are SCALARS, so they take
/// the OTHER fallback - `<item>`, not `<slot>`.
#[test]
fn add_ids_use_the_item_fallback() {
    let out = sab_xml_body(
        "addurl",
        &json!({"status": true, "nzo_ids": ["SABnzbd_nzo_1", "SABnzbd_nzo_2"]}),
    );
    assert!(
        out.contains("<nzo_ids><item>SABnzbd_nzo_1</item>\n<item>SABnzbd_nzo_2</item>\n</nzo_ids>"),
        "{out}"
    );
}

/// `mode=switch`: SAB passes `keyword="result"` with the pair as data,
/// so the `result` element here is the KEYWORD's, not the fallback's -
/// and the document must not end up double-wrapped.
#[test]
fn switch_result_is_not_double_wrapped() {
    let out = sab_xml_body("switch", &json!({"result": {"position": 2, "priority": 0}}));
    assert_eq!(
        out,
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<result><position>2</position>\n<priority>0</priority>\n</result>\n\n"
    );
}

/// `mode=change_cat`: SAB passes `keyword="status"` with a BOOL, so the
/// root element is `<status>` carrying the word - there is no wrapper
/// at all. The one mode whose root is not a container.
#[test]
fn change_cat_root_is_the_bare_status_element() {
    let out = sab_xml_body("change_cat", &json!({"status": true}));
    assert_eq!(
        out,
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<status>True</status>\n\n"
    );
}

/// An ERROR body is SAB's error report whatever mode raised it, and the
/// message must survive. `mode=get_files` is the case that proves the
/// branch is needed: that arm keeps `files` present and empty beside
/// the error, so a keyword-first rule would render `<files></files>`
/// and drop the sentence.
#[test]
fn an_error_body_is_a_result_report_and_keeps_the_message() {
    let out = sab_xml_body(
        "get_files",
        &json!({"status": false, "files": [], "error": "no such job"}),
    );
    assert!(out.contains("<result>"), "{out}");
    assert!(out.contains("<status>False</status>"), "{out}");
    assert!(out.contains("<error>no such job</error>"), "{out}");
    assert!(
        !out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<files>"),
        "{out}"
    );
}

/// A mode nobody put in the table - every nzbfast-only mode, and the
/// `unimplemented mode` fallback - still gets a ROOT element. SAB's own
/// comment for this is "xml always needs an outer keyword, even when
/// json doesn't"; without it the document would be a bare fragment.
#[test]
fn an_unlisted_mode_still_gets_a_root() {
    let out = sab_xml_body(
        "connladder_live",
        &json!({"status": true, "running": false, "host": "news.example.com"}),
    );
    assert!(
        out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<result>"),
        "{out}"
    );
    assert!(out.contains("<running>False</running>\n"), "{out}");
    assert!(out.contains("<status>True</status>\n</result>\n"), "{out}");
}

/// Escaping is `xml.sax.saxutils.escape` and nothing more: `&`, `<`,
/// `>`. A QUOTE stays a quote, because SAB writes element text and
/// never an attribute - reaching for `html.escape` (the reflex import)
/// would put `&quot;` in every job name that has one.
#[test]
fn escaping_is_saxutils_not_html() {
    let out = sab_xml_body(
        "queue",
        &json!({"queue": {"slots": [{"filename": "A & B <x> \"q\" 'a'"}]}}),
    );
    assert!(
        out.contains("<filename>A &amp; B &lt;x&gt; \"q\" 'a'</filename>"),
        "{out}"
    );
}

/// A JSON null is an EMPTY element. SAB's `xml_name` returns `""` for
/// `None` before `escape` sees it, so `serveripaddress` on an
/// unconnected server is `<serveripaddress></serveripaddress>` and
/// never the word "None" or "null".
#[test]
fn null_is_an_empty_element() {
    let out = sab_xml_body(
        "status",
        &json!({"status": {"servers": [{"serveripaddress": null, "serversslinfo": ""}]}}),
    );
    assert!(out.contains("<serveripaddress></serveripaddress>"), "{out}");
    assert!(out.contains("<serversslinfo></serversslinfo>"), "{out}");
}

/// The keyword table is a claim about SAB, so pin it as one. Every
/// entry cites a `report(...)` call in `sabnzbd/api.py`; anything not
/// listed is `""`, which is `<result>`.
#[test]
fn keyword_table_matches_sabs_report_calls() {
    for (mode, kw) in [
        ("version", "version"),
        ("get_cats", "categories"),
        ("get_scripts", "scripts"),
        ("warnings", "warnings"),
        ("status", "status"),
        ("fullstatus", "status"),
        ("get_config", "config"),
        ("get_files", "files"),
        ("queue", "queue"),
        ("history", "history"),
        ("switch", "result"),
        ("change_cat", "status"),
        // SAB's `keyword=""` modes, and ours.
        ("server_stats", ""),
        ("addfile", ""),
        ("addurl", ""),
        ("retry", ""),
        ("pause", ""),
        ("resume", ""),
        ("restart", ""),
        ("shutdown", ""),
        ("config", ""),
        ("index_stats", ""),
    ] {
        assert_eq!(sab_xml_keyword(mode), kw, "mode={mode}");
    }
}
