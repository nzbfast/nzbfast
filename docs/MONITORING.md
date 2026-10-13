# Monitoring nzbfast with Prometheus and Grafana

The daemon serves `GET /metrics` in the Prometheus text format. This
page covers the scrape config, the Grafana dashboard and the alert
rules that ship in `docs/monitoring/`.

## Who can read /metrics

By default `/metrics` needs credentials:

- the **full API key**, as `?apikey=KEY` or an `X-Api-Key: KEY` header; or
- a live **dashboard session** (so opening `/metrics` in a logged-in
  browser tab works).

The add-only NZB key does **not** open it. A wrong key gets `401`, and
repeated wrong keys get `429` from the same rate limit as every other
API door. An install with no API key at all is open, as every other
endpoint on it is.

If a scrape config in a shared repository has nowhere to keep a secret,
or the exporter sits on a network you already trust, turn on the
`metrics_open` setting. That lifts the key requirement for `/metrics`
only. Know what you publish by doing so: no job names and no paths, but
each configured provider's **hostname** appears as a label. `metrics_open`
is off by default.

## Scrape config

nzbfast reads the key from the `apikey` query parameter or the
`X-Api-Key` header, not from `Authorization`, so use `params:`:

```yaml
scrape_configs:
  - job_name: nzbfast
    scrape_interval: 15s
    metrics_path: /metrics
    params:
      apikey: ["YOUR_FULL_API_KEY"]
    static_configs:
      - targets: ["nzbfast.local:6789"]
```

With `metrics_open` on, drop the `params:` block.

Check it by hand first:

```sh
curl -s -H "X-Api-Key: YOUR_FULL_API_KEY" http://nzbfast.local:6789/metrics | head
```

## What is exported

All names start with `nzbfast_`.

| Group | Metrics |
| --- | --- |
| Daemon | `build_info`, `uptime_seconds`, `paused`, `offline` |
| Speed | `download_rate_bytes_per_second`, `speed_limit_bytes_per_second`, `line_speed_bytes_per_second` |
| Queue | `queue_jobs{state}`, `queue_jobs_paused`, `queue_bytes_total`, `queue_bytes_remaining` |
| History | `history_jobs{outcome}`, `history_completed_bytes` |
| Memory and CPU | `memory_budget_bytes`, `memory_rss_bytes`, `memory_rss_peak_bytes`, `memory_subsystem_bytes{subsystem}`, `memory_subsystem_peak_bytes{subsystem}`, `process_cpu_seconds_total` |
| Per provider | `server_connections`, `server_connection_budget`, `server_connections_granted_max`, `server_down`, `server_down_seconds`, `server_article_latency_seconds`, `server_bytes_total`, `server_articles_tried_total`, `server_articles_missing_total`, `server_reconnects_total`, `server_blocked_seconds_total` |

Things worth knowing when you write your own queries:

- The `server_*` families exist **only while a job is on the wire**.
  They are absent on an idle daemon, on purpose: a series pinned at
  zero would claim the provider is idle.
- The per-provider counters reset when a new run takes the connection
  pool. Prometheus reads that as a restart, which `rate()` handles.
- `history_jobs` is a **gauge**. History is trimmed on its own
  schedule, so it can fall without anything being undone; do not wrap
  it in `rate()`.
- There is no disk metric. Free space on the download folder comes
  from `node_exporter` if you want to alert on it.

## Dashboard

Import `docs/monitoring/nzbfast-overview.json` in Grafana
(Dashboards, New, Import). Pick your Prometheus data source when asked.
It covers download rate, queue, per-provider connections, throughput,
latency and missing articles, history, memory and CPU.

## Alert rules

Add `docs/monitoring/nzbfast-alerts.yml` under `rule_files:` in
`prometheus.yml`. It alerts on:

- the daemon not answering scrapes;
- a downloading job with no throughput for 5 minutes (not paused, not
  offline);
- the daemon reporting offline;
- a provider granting no sessions;
- a provider answering no-such-article to most dispatches;
- several failed jobs in an hour;
- resident memory well past its budget.

A disk-space rule that uses `node_exporter`'s metrics is included
commented out.
