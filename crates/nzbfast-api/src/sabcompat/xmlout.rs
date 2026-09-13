//! `output=xml`: SAB's `XmlOutputFactory`, ported.
//!
//! Row 7 of `research/SAB-MODE-SHAPE-AUDIT-2026-08-31.md`, and the only
//! finding there that is a whole serializer rather than a field. SAB's
//! `report()` honours `output=xml` on EVERY mode and answers `text/xml`;
//! we read the parameter nowhere at all, so an XML client got a JSON
//! body with a JSON content type and threw at parse time. That is the
//! same class as GH #69 - a shape a statically-typed client cannot
//! deserialize - one layer up from the field level the rest of that
//! audit works at.
//!
//! WHY THIS IS A PORT AND NOT A DESIGN. SAB's XML is not a generic
//! JSON-to-XML mapping and a client parses it POSITIONALLY: the element
//! names come out of a hard-coded plural->singular table, everything
//! outside that table collapses to `item` or `slot`, and Python's own
//! `str()` decides what a value looks like (a bool is `True`, not
//! `true`). Half-right here is worse than absent, because a client that
//! parses `<slot>` where SAB emits `<file>` fails in the field rather
//! than at the door. Every rule below is `sabnzbd/api.py`, read at the
//! `4.5.0` tag (the version our `SAB_VERSION` advertises) and at
//! `5.1.2`, where the `report`/`XmlOutputFactory`/`_PLURAL_TO_SINGLE`
//! block is byte-identical.
//!
//! HOW A MODE'S OUTER ELEMENT IS DECIDED, which is the one thing that
//! does not fall out of the JSON. SAB builds both bodies from the SAME
//! pair: `report(keyword=K, data=D)` sends `{K: D}` as JSON and
//! `run(K, D)` as XML, and with `keyword=""` it sends `D` itself as
//! JSON and wraps XML in `<result>`. Our arms already emit SAB's JSON
//! `info`, so the pair is recoverable: look `K` up by mode name, and
//! the data is `info[K]`. `sab_xml_keyword` is that table, one entry
//! per mode we answer, each citing the `report(...)` call it mirrors.
//!
//! THE JSON PATH IS NOT TOUCHED BY ANY OF THIS. A caller that does not
//! send `output=xml` gets the identical bytes it got before - the
//! branch is at the single `req.respond` in `serve/http.rs` and this
//! module has no way to reach the JSON body. That is the regression
//! that would matter most, so `xml_is_opt_in` pins it.

use super::*;

/// SAB's `_PLURAL_TO_SINGLE` (`sabnzbd/api.py`), verbatim.
///
/// The whole reason a client can parse this format at all: a list under
/// one of these seven keys names its children, and every other list
/// falls back to the caller's default (`item` for scalars, `slot` for
/// objects). Adding a "sensible" entry of our own would rename an
/// element for every client at once, so this table only ever grows when
/// SAB's does.
fn plural_to_single<'a>(kw: &str, def_kw: &'a str) -> &'a str {
    match kw {
        "categories" => "category",
        "servers" => "server",
        "rss" => "feed",
        "scripts" => "script",
        "warnings" => "warning",
        "files" => "file",
        "jobs" => "job",
        _ => def_kw,
    }
}

/// SAB's `xml_name` (`sabnzbd/encoding.py`) - `escape()` from
/// `xml.sax.saxutils`, which is `&`, `<` and `>` and NOT the quotes.
///
/// `html.escape` would also do `"` and `'` and is the reflex import;
/// SAB does not use it, and since every value here lands in element
/// TEXT rather than an attribute, a quote needs no escaping to be
/// well-formed. Matching the reflex instead of the source would put
/// `&quot;` in every job name that carries one.
fn xml_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// Python's `str()` over a JSON scalar, which is what SAB's factory
/// applies before escaping.
///
/// `True`/`False` capitalised is not a typo and not ours to fix: SAB
/// interpolates the Python bool straight into the element text, so a
/// client calibrated against SAB compares against those exact words.
/// `null` is the empty string, because `xml_name` special-cases `None`
/// to `""` before `escape` ever sees it - so an absent value is an
/// EMPTY element rather than the string "None".
fn py_str(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        // Unreachable: `run` routes containers before this is called.
        _ => String::new(),
    }
}

/// SAB's `XmlOutputFactory._dict`.
///
/// An empty outer keyword emits NOTHING, children included - SAB's own
/// `else: return ""`. That looks like a bug and is load-bearing: it is
/// what makes the `keyword=""` modes go through `<result>` at the top
/// rather than spilling their keys at document level, where there would
/// be no root element and no well-formed document at all.
fn dict_out(keyw: &str, map: &serde_json::Map<String, Value>) -> String {
    if keyw.is_empty() {
        return String::new();
    }
    let mut inner = String::new();
    for (k, v) in map {
        inner.push_str(&run(k, v));
    }
    format!("<{keyw}>{inner}</{keyw}>\n")
}

/// SAB's `XmlOutputFactory._list`.
fn list_out(keyw: &str, items: &[Value]) -> String {
    if keyw.is_empty() {
        return String::new();
    }
    let mut inner = String::new();
    for it in items {
        match it {
            Value::Object(m) => inner.push_str(&dict_out(plural_to_single(keyw, "slot"), m)),
            Value::Array(a) => inner.push_str(&list_out(plural_to_single(keyw, "list"), a)),
            scalar => {
                let name = plural_to_single(keyw, "item");
                inner.push_str(&format!("<{name}>{}</{name}>\n", xml_name(&py_str(scalar))));
            }
        }
    }
    format!("<{keyw}>{inner}</{keyw}>\n")
}

/// SAB's `XmlOutputFactory.run`.
fn run(keyw: &str, v: &Value) -> String {
    match v {
        Value::Object(m) => dict_out(keyw, m),
        Value::Array(a) => list_out(keyw, a),
        scalar if !keyw.is_empty() => {
            format!("<{keyw}>{}</{keyw}>\n", xml_name(&py_str(scalar)))
        }
        _ => String::new(),
    }
}

/// The outer `keyword` SAB's own arm passes to `report()` for `mode`.
///
/// `""` means SAB calls `report()` bare or with `keyword=""`, both of
/// which wrap the body in `<result>`; that is also the honest answer
/// for every mode of OURS that SAB has no arm for, so it is the
/// default. A mode listed here with a keyword takes its data from
/// `info[keyword]`, which is exactly what our JSON already carries.
///
/// Line numbers move between releases, so each entry cites the SAB
/// function rather than a line.
pub fn sab_xml_keyword(mode: &str) -> &'static str {
    match mode {
        // `_api_version`: report(keyword="version", data=__version__).
        "version" => "version",
        // `_api_get_cats`: report(keyword="categories", ...).
        "get_cats" => "categories",
        // `_api_get_scripts`: report(keyword="scripts", ...).
        "get_scripts" => "scripts",
        // `_api_warnings`: report(keyword="warnings", ...).
        "warnings" => "warnings",
        // `_api_fullstatus`: report(keyword="status", ...). BOTH mode
        // names reach that one function in SAB's `_api_table`, which is
        // finding 5 of the audit - so both take the same element too.
        "status" | "fullstatus" => "status",
        // `_api_get_config`: report(keyword="config", ...).
        "get_config" => "config",
        // `_api_get_files`: report(keyword="files", ...), whose rows
        // therefore come out as `<file>` and not `<slot>`.
        "get_files" => "files",
        // `_api_queue_default`: report(keyword="queue", ...).
        "queue" => "queue",
        // `_api_history`: report(keyword="history", ...).
        "history" => "history",
        // `_api_switch`: report(keyword="result", data={position,
        // priority}). Our arm already wraps in `result` for LunaSea's
        // parser, so the JSON and the XML agree here for once.
        "switch" => "result",
        // `_api_change_cat` and friends: report(keyword="status",
        // data=bool) - the root element IS `<status>`, carrying the
        // bool as text, with no wrapper around it. Our body is
        // `{"status": ...}`, so `info["status"]` recovers SAB's `data`.
        "change_cat" => "status",
        // Everything else, ours and SAB's alike: `<result>`. That
        // covers the acks SAB writes as a bare `report()`
        // (pause/resume/restart/shutdown), the `keyword=""` payloads
        // (addfile, addurl, retry, server_stats) and every nzbfast-only
        // mode, which SAB has no opinion about.
        _ => "",
    }
}

/// The XML document SAB's `report()` would have sent for this mode,
/// given the JSON body we would otherwise have sent.
///
/// Three branches, and they are SAB's three in SAB's order:
///
/// 1. an ERROR report - `report(error=...)` - is always
///    `<result><status>False</status><error>...</error></result>`,
///    whatever mode raised it. Detected by the shape rather than by a
///    separate return channel, because that shape IS our error
///    convention: every arm answers `status:false` with an `error`
///    beside it. Without this branch `mode=get_files`'s error body
///    would render as an empty `<files/>` and drop the message, since
///    that arm keeps `files` present and empty beside the error.
/// 2. a keyword mode renders `run(keyword, info[keyword])`.
/// 3. anything else - `keyword=""`, or a keyword whose key is somehow
///    absent - renders `run("result", info)`, SAB's own fallback for
///    "xml always needs an outer keyword".
///
/// Keys of ours that SAB does not send ride along inside the element
/// they already sit in; keys SAB sends under `keyword` that we answer
/// with a SUPERSET at top level (`mode=version` carries `nzbfast` and
/// `beta` beside `version`) are dropped, because SAB's document has
/// nowhere to put them. Both are deliberate: an XML client is parsing
/// SAB's document, not ours.
pub fn sab_xml_body(mode: &str, info: &Value) -> String {
    let is_error = info.get("status") == Some(&Value::Bool(false)) && info.get("error").is_some();
    let kw = sab_xml_keyword(mode);
    // The three branches collapse to one match: `<result>` is the
    // catch-all, and the keyword form is the exception that has to earn
    // itself. `info.get("")` is `None` for every body we send, so the
    // `keyword=""` modes fall through the same arm as an error does -
    // which is SAB's own arrangement, where both go to `run("result",
    // ...)`.
    let body = match info.get(kw) {
        Some(data) if !is_error && !kw.is_empty() => run(kw, data),
        _ => run("result", info),
    };
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n{body}\n")
}

#[cfg(test)]
#[path = "xmlout_tests.rs"]
mod xmlout_tests;
