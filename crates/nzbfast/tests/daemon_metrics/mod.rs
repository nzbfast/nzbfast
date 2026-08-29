//! `GET /metrics`, end to end: the Prometheus exposition format the
//! daemon actually serves, parsed the way a scraper parses it.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//!
//! WHY THIS IS PARSED RATHER THAN GREPPED. Every failure this endpoint
//! can have is silent at the source and loud only at the far end. A
//! second `# TYPE` for one name is a PARSE ERROR that makes Prometheus
//! drop the WHOLE scrape, so a family added carelessly costs you every
//! family declared before it, and the symptom is a dashboard that has
//! gone blank rather than an error anywhere near the change. A sample
//! whose family was never opened arrives untyped and silently cannot be
//! `rate()`d. And a counter that goes DOWN between two scrapes is read
//! as a process restart, so a gauge mislabelled `counter` invents
//! restarts that never happened. None of the three is visible in a
//! `curl` a person eyeballs; all three are one assertion away here.

use super::*;

/// One parsed sample line.
struct Sample {
    name: String,
    labels: String,
    value: f64,
}

/// What a scraper takes from a body: the declared types, and the
/// samples. Panics with the offending line on anything the format does
/// not allow, because "the body was rejected" is exactly the failure
/// being pinned.
struct Scrape {
    types: std::collections::HashMap<String, String>,
    samples: Vec<Sample>,
}

fn parse_exposition(body: &str) -> Scrape {
    let mut types: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut helps: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut samples = Vec::new();
    for (n, line) in body.lines().enumerate() {
        let ln = n + 1;
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest
                .split_once(' ')
                .unwrap_or_else(|| panic!("line {ln}: malformed TYPE: {line:?}"));
            assert!(
                types.insert(name.to_string(), kind.to_string()).is_none(),
                "line {ln}: metric {name} declared TWICE - Prometheus drops the whole scrape"
            );
            assert!(
                matches!(
                    kind,
                    "counter" | "gauge" | "histogram" | "summary" | "untyped"
                ),
                "line {ln}: {name} has unknown type {kind:?}"
            );
            continue;
        }
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let name = rest.split(' ').next().unwrap_or("");
            assert!(
                helps.insert(name.to_string()),
                "line {ln}: metric {name} has TWO HELP lines"
            );
            assert!(
                !rest[name.len()..].trim().is_empty(),
                "line {ln}: {name} has an empty HELP: {line:?}"
            );
            continue;
        }
        assert!(
            !line.starts_with('#'),
            "line {ln}: a comment that is neither HELP nor TYPE: {line:?}"
        );
        // `name{labels} value` or `name value`. The value is everything
        // after the LAST space, which is what a scraper takes and is why
        // a label value holding a space is harmless.
        let (head, value) = line
            .rsplit_once(' ')
            .unwrap_or_else(|| panic!("line {ln}: no value: {line:?}"));
        let (name, labels) = match head.split_once('{') {
            Some((n, l)) => {
                let l = l
                    .strip_suffix('}')
                    .unwrap_or_else(|| panic!("line {ln}: unclosed label set: {line:?}"));
                (n, l.to_string())
            }
            None => (head, String::new()),
        };
        assert!(
            name.starts_with("nzbfast_"),
            "line {ln}: every metric this daemon exports is namespaced: {line:?}"
        );
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':'),
            "line {ln}: illegal character in metric name {name:?}"
        );
        assert!(
            types.contains_key(name),
            "line {ln}: sample of {name} before its # TYPE - it arrives untyped"
        );
        let v: f64 = match value {
            "+Inf" => f64::INFINITY,
            "-Inf" => f64::NEG_INFINITY,
            "NaN" => f64::NAN,
            other => other
                .parse()
                .unwrap_or_else(|e| panic!("line {ln}: value {other:?} does not parse ({e})")),
        };
        samples.push(Sample {
            name: name.to_string(),
            labels,
            value: v,
        });
    }
    Scrape { types, samples }
}

impl Scrape {
    fn value(&self, name: &str) -> f64 {
        self.samples
            .iter()
            .find(|s| s.name == name && s.labels.is_empty())
            .unwrap_or_else(|| panic!("no unlabelled sample for {name}"))
            .value
    }
}

/// The status line and body of one GET, headers kept - `http()` throws
/// the headers away and the Content-Type is half of what is asserted.
fn get(port: u16, path: &str) -> (u16, String, String) {
    let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let raw_bytes = raw(port, req.as_bytes());
    let text = String::from_utf8_lossy(&raw_bytes).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let code: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {head:?}"));
    let ctype = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-type:"))
        .map(|l| l[13..].trim().to_string())
        .unwrap_or_default();
    (code, ctype, body.to_string())
}

/// A daemon with no downloads, scraped twice.
///
/// The pool gauges are deliberately NOT exercised here: `pool_live` is
/// the running job's own fleet, so on an idle daemon there is no such
/// thing as "connections to this provider" and the per-server families
/// are correctly ABSENT. What this pins is everything that must be there
/// on every scrape, plus the three format rules a scraper enforces.
#[tokio::test(flavor = "multi_thread")]
async fn the_metrics_endpoint_answers_prometheus_text_that_parses() {
    let dir = std::env::temp_dir().join(format!("nzbfast-metrics-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"flat.example\",\"enabled\":true}]}",
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let (code, ctype, body) = tokio::task::spawn_blocking(move || get(port, "/metrics"))
        .await
        .unwrap();
    assert_eq!(code, 200, "{body}");
    // The version parameter is what tells a scraper which parser to
    // use. Dropping it works today only because Prometheus GUESSES
    // 0.0.4 for bare text/plain.
    assert_eq!(ctype, "text/plain; version=0.0.4; charset=utf-8");

    let first = parse_exposition(&body);
    assert!(
        first.samples.len() >= 30,
        "an idle daemon still reports its identity, line state, queue, history and memory: \
         got {} samples\n{body}",
        first.samples.len()
    );

    // The families that must be present whatever the daemon is doing,
    // with the type each is read as. A gauge mislabelled `counter`
    // invents restarts every time it falls; a counter mislabelled
    // `gauge` cannot be `rate()`d at all.
    for (name, kind) in [
        ("nzbfast_build_info", "gauge"),
        ("nzbfast_uptime_seconds", "gauge"),
        ("nzbfast_download_rate_bytes_per_second", "gauge"),
        ("nzbfast_speed_limit_bytes_per_second", "gauge"),
        ("nzbfast_line_speed_bytes_per_second", "gauge"),
        ("nzbfast_paused", "gauge"),
        ("nzbfast_offline", "gauge"),
        ("nzbfast_queue_jobs", "gauge"),
        ("nzbfast_queue_bytes_total", "gauge"),
        ("nzbfast_queue_bytes_remaining", "gauge"),
        // History is TRIMMED on its own schedule, so it falls without
        // anything having been undone - a counter here would teach
        // `rate()` to read a retention sweep as a burst of completions.
        ("nzbfast_history_jobs", "gauge"),
        ("nzbfast_memory_budget_bytes", "gauge"),
        ("nzbfast_memory_subsystem_bytes", "gauge"),
        ("nzbfast_memory_subsystem_peak_bytes", "gauge"),
        ("nzbfast_process_cpu_seconds_total", "counter"),
    ] {
        assert_eq!(
            first.types.get(name).map(String::as_str),
            Some(kind),
            "{name} must be exported as a {kind}\n{body}"
        );
    }
    // The units convention: base units only, so nothing is exported
    // pre-divided. A name ending in a scaled unit is the mistake.
    for s in &first.samples {
        for bad in [
            "_mb", "_kb", "_gb", "_minutes", "_ms", "_millis", "_percent",
        ] {
            assert!(
                !s.name.ends_with(bad),
                "{} is not a base unit - export bytes and seconds and let the dashboard convert",
                s.name
            );
        }
    }
    assert_eq!(first.value("nzbfast_paused"), 0.0);
    assert_eq!(first.value("nzbfast_queue_bytes_total"), 0.0);
    assert!(
        first.samples.iter().any(|s| s.name == "nzbfast_build_info"
            && s.labels
                .contains(&format!("version=\"{}\"", env!("CARGO_PKG_VERSION")))),
        "build_info must carry the running version\n{body}"
    );
    // Four states, and they are a partition: every job in the queue is
    // in exactly one, so a bucket added later cannot quietly not add up.
    assert_eq!(
        first
            .samples
            .iter()
            .filter(|s| s.name == "nzbfast_queue_jobs")
            .count(),
        4,
        "{body}"
    );

    // A second scrape, far enough apart that the clock has certainly
    // moved. Uptime must climb, and no counter may fall - a drop is
    // read as a process restart by every consumer.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let (code2, _, body2) = tokio::task::spawn_blocking(move || get(port, "/metrics"))
        .await
        .unwrap();
    assert_eq!(code2, 200, "{body2}");
    let second = parse_exposition(&body2);
    assert!(
        second.value("nzbfast_uptime_seconds") > first.value("nzbfast_uptime_seconds"),
        "uptime must climb: {} then {}",
        first.value("nzbfast_uptime_seconds"),
        second.value("nzbfast_uptime_seconds")
    );
    for a in &first.samples {
        if first.types.get(&a.name).map(String::as_str) != Some("counter") {
            continue;
        }
        let Some(b) = second
            .samples
            .iter()
            .find(|s| s.name == a.name && s.labels == a.labels)
        else {
            continue;
        };
        assert!(
            b.value >= a.value,
            "counter {}{{{}}} fell from {} to {} - every consumer reads that as a restart",
            a.name,
            a.labels,
            a.value,
            b.value
        );
    }

    let _log = d.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The eleven per-provider families, scraped MID-FLIGHT.
///
/// The two tests around this one scrape an IDLE daemon, and on an idle
/// daemon `pool_live` is None - so the whole of `server_metrics` had
/// never been executed by any test, with any value, ever. A metric NAME
/// is a published contract (someone's Grafana panel is written against
/// these strings), and a rename or a type flip has no symptom anywhere in
/// this repo unless a test holds a body that CONTAINS the families. This
/// is that body: a real download against the mock NNTP server, throttled
/// slow enough (`delay_ms` per article, two connections) that a scrape
/// reliably lands while the job is on the wire.
///
/// It also pins the three figures the idle tests can only assert at
/// zero - the rate gauge, `queue_jobs{state="downloading"}` and the
/// per-server byte counter - above zero, so a renderer that hard-coded
/// them would fail here.
#[tokio::test(flavor = "multi_thread")]
async fn a_mid_flight_scrape_reports_every_provider_family() {
    let dir = std::env::temp_dir().join(format!("nzbfast-metricsrun-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // 75 articles of 20 KB at 250 ms each over 2 connections is roughly
    // 160 KB/s, so the download runs for seconds - long enough that the
    // poll below cannot miss the Downloading window even on a loaded box.
    let data = payload(1_500_000, 43);
    let mut articles = HashMap::new();
    let segs = make_file_articles("metered.bin", &data, 20_000, "mf", &mut articles);
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <file poster=\"x\" date=\"0\" subject=\"&quot;metered.bin&quot; yEnc (1/1)\">\
         <groups><group>g</group></groups><segments>",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "<segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>"
        ));
    }
    xml.push_str("</segments></file></nzb>");

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.port()
        ),
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let boundary = "----metricsrun";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"Metered.S01E01.nzb\"\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&cat=tv&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = r
            .split("\"nzo_ids\":[\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("addfile must answer the new job's nzo_id")
            .to_string();

        // First barrier: the queue reports OUR job Downloading. Read
        // from the slot, never `q.contains(&id)` - the whyslow block
        // names ids of its own and the ids are prefixes of each other.
        let mut downloading = false;
        for _ in 0..300 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if queue_slot(&q, &id)["status"] == "Downloading" {
                downloading = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(downloading, "the job never reached Downloading");

        // Second barrier: a scrape whose body carries the live pool.
        // Downloading-in-the-queue precedes the pool publishing its
        // fleet and the first article landing, so poll the scrape
        // itself until the rate gauge has a window to report - never a
        // fixed sleep, this box runs several lanes' builds at once.
        let mut flight: Option<(Scrape, String)> = None;
        for _ in 0..300 {
            let (code, _, mbody) = get(port, "/metrics");
            assert_eq!(code, 200, "{mbody}");
            let s = parse_exposition(&mbody);
            let has_pool = s
                .samples
                .iter()
                .any(|x| x.name == "nzbfast_server_bytes_total" && x.value > 0.0);
            if has_pool && s.value("nzbfast_download_rate_bytes_per_second") > 0.0 {
                flight = Some((s, mbody));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let (s, mbody) =
            flight.expect("no scrape ever carried a live pool with bytes moving");

        // Every one of the eleven per-provider families, present with
        // the right TYPE and a sample labelled with the mock's host. A
        // counter mislabelled gauge cannot be rate()d; a gauge
        // mislabelled counter invents restarts every time it falls -
        // and six of these fall routinely (`connections`, `budget`,
        // `down_seconds`, the latency average...).
        let server_families = [
            ("nzbfast_server_connections", "gauge"),
            ("nzbfast_server_connection_budget", "gauge"),
            ("nzbfast_server_connections_granted_max", "gauge"),
            ("nzbfast_server_down", "gauge"),
            ("nzbfast_server_down_seconds", "gauge"),
            ("nzbfast_server_article_latency_seconds", "gauge"),
            ("nzbfast_server_bytes_total", "counter"),
            ("nzbfast_server_articles_tried_total", "counter"),
            ("nzbfast_server_articles_missing_total", "counter"),
            ("nzbfast_server_reconnects_total", "counter"),
            ("nzbfast_server_blocked_seconds_total", "counter"),
        ];
        for (name, kind) in server_families {
            assert_eq!(
                s.types.get(name).map(String::as_str),
                Some(kind),
                "{name} must be exported as a {kind}\n{mbody}"
            );
            assert!(
                s.samples
                    .iter()
                    .any(|x| x.name == name && x.labels.contains("server=\"127.0.0.1\"")),
                "{name} must carry a sample labelled with the provider's host\n{mbody}"
            );
        }

        // The values are real, not a rendered zero: bytes and article
        // dispatches have both happened by the time the rate gauge is
        // above zero, and there is exactly one provider to credit.
        let sv = |name: &str| {
            s.samples
                .iter()
                .find(|x| x.name == name && x.labels.contains("server=\"127.0.0.1\""))
                .unwrap_or_else(|| panic!("no {name} sample for the mock host\n{mbody}"))
                .value
        };
        assert!(sv("nzbfast_server_bytes_total") > 0.0, "{mbody}");
        assert!(sv("nzbfast_server_articles_tried_total") > 0.0, "{mbody}");
        assert!(
            sv("nzbfast_server_connections") >= 1.0,
            "bytes are moving, so at least one session is open\n{mbody}"
        );
        assert_eq!(
            sv("nzbfast_server_down"),
            0.0,
            "a provider serving articles is not down\n{mbody}"
        );

        // The pipeline gauges the idle tests can only pin at zero.
        assert!(
            s.samples
                .iter()
                .any(|x| x.name == "nzbfast_queue_jobs"
                    && x.labels == "state=\"downloading\""
                    && x.value >= 1.0),
            "one job is on the wire\n{mbody}"
        );
        assert!(s.value("nzbfast_download_rate_bytes_per_second") > 0.0, "{mbody}");

        // And the four families the idle test left unpinned. History is
        // still empty mid-flight and nothing is paused, so both derive
        // to zero; the RSS pair just has to be a real process's.
        assert_eq!(
            s.types.get("nzbfast_history_completed_bytes").map(String::as_str),
            Some("gauge"),
            "{mbody}"
        );
        assert_eq!(s.value("nzbfast_history_completed_bytes"), 0.0, "{mbody}");
        assert_eq!(
            s.types.get("nzbfast_queue_jobs_paused").map(String::as_str),
            Some("gauge"),
            "{mbody}"
        );
        assert_eq!(s.value("nzbfast_queue_jobs_paused"), 0.0, "{mbody}");
        assert_eq!(
            s.types.get("nzbfast_memory_rss_bytes").map(String::as_str),
            Some("gauge"),
            "{mbody}"
        );
        assert!(s.value("nzbfast_memory_rss_bytes") > 0.0, "{mbody}");
        assert_eq!(
            s.types.get("nzbfast_memory_rss_peak_bytes").map(String::as_str),
            Some("gauge"),
            "{mbody}"
        );
        assert!(s.value("nzbfast_memory_rss_peak_bytes") > 0.0, "{mbody}");
    })
    .await
    .unwrap();

    let _log = d.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The credential rule, both ways round.
///
/// `/metrics` is a read of this daemon's state, so it sits behind the
/// full API key like every other read on this port - and `metrics_open`
/// lifts that, because the Prometheus convention is an unauthenticated
/// scrape and a scrape config has nowhere tidy to keep a secret. Both
/// halves are pinned here: a switch that silently did nothing would
/// leave an operator believing they had opened a port they had not, and
/// a default that was open would publish every configured provider's
/// hostname to anyone who can reach the port.
#[tokio::test(flavor = "multi_thread")]
async fn metrics_needs_the_api_key_until_the_switch_opens_it() {
    let dir = std::env::temp_dir().join(format!("nzbfast-metricskey-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        "{\"servers\":[{\"host\":\"flat.example\",\"enabled\":true}]}",
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Keyless: open, exactly as every other endpoint is on a
        // keyless install. This is `full_key_ok`'s first arm, not this
        // route being lax.
        assert_eq!(get(port, "/metrics").0, 200, "keyless install stays open");

        // Mint a key through the bootstrap hatch that exists for
        // exactly this - the first `config name=apikey` write on a
        // daemon that has none.
        let set = http(
            port,
            "/api?mode=config&name=apikey&value=metrickey123&output=json",
            None,
        );
        assert!(set.contains("\"status\":true"), "{set}");

        assert_eq!(get(port, "/metrics").0, 401, "no key once one is set");
        assert_eq!(get(port, "/metrics?apikey=wrong").0, 401, "wrong key");
        let (code, ctype, body) = get(port, "/metrics?apikey=metrickey123");
        assert_eq!(code, 200, "{body}");
        assert_eq!(ctype, "text/plain; version=0.0.4; charset=utf-8");

        // The add-only NZB key does not open this door: the body names
        // every configured provider, which is not something a
        // credential that ships to a browser push extension may read.
        let nzb = http(
            port,
            "/api?mode=config&name=nzbkey&value=addonly123&apikey=metrickey123&output=json",
            None,
        );
        assert!(nzb.contains("\"status\":true"), "{nzb}");
        assert_eq!(
            get(port, "/metrics?apikey=addonly123").0,
            401,
            "the add-only key is not a read of daemon state"
        );

        // A scrape is a read. A POST that answered would be a route a
        // cross-origin form could reach.
        let post = http(
            port,
            "/metrics?apikey=metrickey123",
            Some(("text/plain", b"")),
        );
        assert!(
            post.contains("GET required") || post.is_empty(),
            "POST must be refused: {post}"
        );

        // And the switch.
        let on = http(
            port,
            "/api?mode=config&name=metrics_open&value=1&apikey=metrickey123&output=json",
            None,
        );
        assert!(on.contains("\"status\":true"), "{on}");
        assert_eq!(
            get(port, "/metrics").0,
            200,
            "metrics_open must open the endpoint to an unauthenticated scraper"
        );
        // It is echoed back, so the settings page and any client can
        // see the state they just set - the half of the three-list
        // plumbing that fails SILENTLY when it is missed.
        let cfgj = http(
            port,
            "/api?mode=get_config&apikey=metrickey123&output=json",
            None,
        );
        assert!(cfgj.contains("\"metrics_open\":true"), "{cfgj}");
    })
    .await
    .unwrap();

    let _log = d.stop();
    let _ = std::fs::remove_dir_all(&dir);
}
