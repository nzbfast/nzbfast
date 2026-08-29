//! Everything serve() does before and around the bind: restoring the
//! persisted runtime state, seeding the Daemon's settings-backed fields,
//! taking the listener, the single-instance lock, the core task spawns
//! and the ready banner.
//!
//! The startup CALL ORDER is load-bearing (first_run_apikey before the
//! bind, the bind before the banner) - these functions were lifted out of
//! serve() without reordering anything, and must stay that way.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

pub(super) fn restore_runtime_state(
    daemon: &Arc<Daemon>,
    settings_path: &Path,
    _spool: &Path,
    _config: &Path,
    speedlimit: &Option<String>,
) -> Result<()> {
    // Bring back the job records a previous run persisted (Downloading
    // reverts to Queued inside load_queue - the download restarts and its
    // journal skips what already landed).
    daemon.load_queue();

    // M23 Smart Folders + cleanup rules: UI-managed live settings that
    // exist only in settings.json (no CLI flag), parsed here because
    // they need the daemon to exist.
    {
        let saved = load_settings(settings_path);
        restore_job_settings(daemon, &saved, settings_path);
        restore_ui_and_index_settings(daemon, &saved);
    }
    // A12: after BOTH of the above. load_queue has put back every record
    // that reached disk, and restore_job_settings has loaded the
    // categories (for §218's inference) and the kept-files notices (which
    // hold spool files of their own). Before any task spawns: the watch
    // poller must find a re-adopted job in the queue, by sha, before it
    // re-reads the user's copy of the same NZB.
    daemon.recover_orphaned_spool();

    if let Some(v) = &speedlimit {
        let bps = parse_size(v)
            .ok_or_else(|| anyhow::anyhow!("--speedlimit: bad size {v:?} (e.g. 4M, 500K, 0)"))?;
        daemon.set_speed_ceiling(bps);
        if bps > 0 {
            info!(target: "config", "speedlimit {:.1} KB/s", bps as f64 / 1e3);
        }
    }

    // A pause the user set is part of the state a restart has to land in,
    // the same as the queue itself. Before the scheduler below, which may
    // overrule it.
    restore_pause(daemon, &load_settings(settings_path));

    // `docker stop`, `systemctl stop`, a Ctrl-C in a terminal: all of
    // them are a request to stop, and until now none of them reached the
    // wind-down the tray's Quit item has always had (issue #13).
    install_shutdown_signals(daemon);
    Ok(())
}

/// ABSOLUTE from here on. Sonarr reads `misc.complete_dir` out of
/// get_config to learn where this client puts files, and a relative
/// path means nothing to another process - different cwd, often a
/// different container or host - so it reports "Remote Path Mapping"
/// while the downloads themselves land perfectly, because WE resolve
/// it against our own cwd. That is exactly the shape of the v1.0.9
/// report: right folder, wrong error. SABnzbd always answers absolute.
///
/// Resolved rather than canonicalized: the directory may not exist
/// yet on a first run, and canonicalize() fails on a missing path.
pub(super) fn absolute_out_root(out_root: PathBuf) -> PathBuf {
    if out_root.is_absolute() {
        out_root
    } else {
        std::env::current_dir()
            .map(|c| c.join(&out_root))
            .unwrap_or(out_root)
    }
}

// Size paydown, same move giveup.rs made: the accessor lives with the
// code that DECIDES what it reports. `resolve_tls_pair` below settles
// the pair, `announce_ready` prints the matching banner scheme, and
// daemon.rs was over its ceiling.
impl Daemon {
    /// The scheme THIS listener answers on, for every link we hand a
    /// client. Bind-time state like `port`, and the pair is
    /// both-or-neither (see `resolve_tls_pair`), so `tls_cert` decides.
    ///
    /// Links used to say `http` unconditionally, which a reverse proxy
    /// could correct with `X-Forwarded-Proto` but a DIRECT TLS listener
    /// could not: `/m3u`, `.strm` and the newznab items all pointed at
    /// plaintext on a TLS-only socket and got a reset.
    pub fn scheme(&self) -> &'static str {
        if self.tls_cert.is_some() {
            "https"
        } else {
            "http"
        }
    }
}

/// Both halves or neither: one file alone is a misconfiguration the
/// user should hear about, but not one worth refusing to start over -
/// the daemon they had yesterday still works, on plain HTTP.
pub(super) fn resolve_tls_pair<'a>(
    tls_cert: &'a Option<PathBuf>,
    tls_key: &'a Option<PathBuf>,
) -> Option<(&'a Path, &'a Path)> {
    match (tls_cert, tls_key) {
        (Some(c), Some(k)) => Some((c.as_path(), k.as_path())),
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => {
            eprintln!(
                "⚠ TLS is half-configured ({} is set, {} is not) - serving plain HTTP. \
                 Set both tls_cert and tls_key, or neither.",
                if tls_cert.is_some() {
                    "tls_cert"
                } else {
                    "tls_key"
                },
                if tls_cert.is_some() {
                    "tls_key"
                } else {
                    "tls_cert"
                },
            );
            None
        }
    }
}

pub(super) fn take_listener(
    bind: &str,
    port: u16,
    tls: Option<(&Path, &Path)>,
) -> Result<tiny_http::Server> {
    // Take the listener HERE: after the API key is settled, and before the
    // first thing that writes to the data directory.
    //
    // The bind used to sit at the very end of startup, thousands of lines
    // below, so a daemon that could not have its port had already created
    // `.spool` and written settings.json before it found out. Those writes
    // are not incidental clutter - they ARE the "is this a fresh install?"
    // answer that `legacy_rename_punctuation` reads above.
    // A failed start therefore converted the directory from "fresh" to
    // "existing", and the NEXT start read the converted answer.
    //
    // That was a live flake, not a theoretical one: the daemon suites
    // spawn on an OS-assigned port and relaunch when they lose it to a
    // parallel test, so under `cargo test --workspace`
    // `obfuscated_event_release_keeps_its_words` filed its download as
    // `Formula1 (2026) ... [2160p]` - the pre-upgrade punctuation shape -
    // because attempt 1's corpse told attempt 2 it was an upgrade. Nothing
    // about the failure looked like a port problem. For a user the same
    // ordering meant `nzbfast serve --port <taken>` left a half-initialised
    // data directory behind.
    //
    // WHY HERE AND NOT EARLIER. The port is final from `apply_saved_settings`
    // onwards (settings.json wins over the CLI), so this could sit further
    // up - but it must not. `first_run_apikey` above is the gate that
    // REFUSES to start on an empty or unreadable key file, and binding
    // before it would turn a lost port into a bind error where an operator
    // (and firstrun_key.rs) expects to be told the credential is broken.
    // Binding after it also means the listener never exists before the
    // credential does, so there is no window in which tiny_http's accept
    // thread is up without an API key behind it. The one thing a failed
    // bind can still leave is the minted key file, which is harmless: it
    // feeds neither `legacy_rename_punctuation` nor anything else that
    // decides fresh-vs-existing, and the next start correctly reuses it -
    // and MintDisclosure is armed above, so exactly this exit is the one
    // that tells the user the key exists.
    //
    // runtime.json is NOT written here: it stays down by the banner. Its
    // invariant is "the listener exists AND the file appears before the
    // readiness banner" - both still hold with the bind up here - and it
    // needs the daemon's launcher token, which is only constructed below.
    match tls {
        None => bind_past_a_closing_predecessor(bind, port, || match bind.parse() {
            Ok(a6) => tiny_http::Server::from_listener(
                dual_stack_v6_listener(a6, port)?,
                None,
                tiny_http::ServerLimits::default(),
            ),
            Err(_) => tiny_http::Server::http((bind, port)),
        })
        .map_err(|e| anyhow::anyhow!("bind {bind}:{port}: {e}")),
        Some((cert, key)) => {
            // Certificate problems are diagnosed HERE, before the bind,
            // so the error names the file and what is wrong with it -
            // tiny_http's own failure would say neither, and a browser's
            // refusal says it in a different tab on a different machine.
            let config = tls_server_config(cert, key)?;
            bind_past_a_closing_predecessor(bind, port, || {
                let ssl = tiny_http::SslConfig {
                    server_config: config.clone(),
                };
                match bind.parse() {
                    Ok(a6) => tiny_http::Server::from_listener(
                        dual_stack_v6_listener(a6, port)?,
                        Some(ssl),
                        tiny_http::ServerLimits::default(),
                    ),
                    Err(_) => tiny_http::Server::https((bind, port), ssl),
                }
            })
            .map_err(|e| anyhow::anyhow!("bind {bind}:{port} (tls): {e}"))
        }
    }
}

/// An IPv6 `--bind` gets its listener built by hand, because the one
/// socket option that decides what `::` MEANS is out of std's reach.
///
/// `IPV6_V6ONLY` defaults per platform: off on Linux and macOS (a `::`
/// bind answers IPv4 too, as `::ffff:a.b.c.d`), ON on Windows - where
/// `--bind ::` therefore served IPv6 alone, and an IPv4-only client on
/// the same box (issue #58: Radarr, which connects to `localhost` as
/// 127.0.0.1) was refused with nothing in any log to say why. Clearing
/// the flag here makes `::` mean the same thing on every platform we
/// ship.
///
/// Cleared for every IPv6 bind, not just `::`, because the flag only
/// has an effect on the unspecified address - on `::1` or a real
/// address it is inert, and one code path beats two. Best-effort on
/// purpose: a platform that refuses (OpenBSD forbids dual-stack
/// outright) keeps the v6-only listener it would have had before this
/// function existed, and the log says so rather than the start failing.
fn dual_stack_v6_listener(
    addr: std::net::Ipv6Addr,
    port: u16,
) -> std::result::Result<std::net::TcpListener, BindError> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    if let Err(e) = sock.set_only_v6(false) {
        warn!(
            target: "startup",
            "could not clear IPV6_V6ONLY on [{addr}]:{port} - listening IPv6-only: {e}"
        );
    }
    // std's own bind sets SO_REUSEADDR on unix (and deliberately not on
    // Windows, where it means something dangerous); mirror it so a
    // restart does not trip over the predecessor's TIME_WAIT sockets.
    #[cfg(unix)]
    sock.set_reuse_address(true)?;
    sock.bind(&std::net::SocketAddr::from((addr, port)).into())?;
    // 128 is what std's TcpListener::bind passes.
    sock.listen(128)?;
    Ok(sock.into())
}

/// How long "address already in use" may be a lie before we believe it.
///
/// Forty times the worst teardown measured below, and short enough that a
/// port a STRANGER holds is still reported as taken while the operator is
/// still looking at the terminal.
const BIND_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

type BindError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Bind, tolerating a predecessor whose listener the kernel has not
/// finished reclaiming.
///
/// `restart_in_place` replaces the image with `exec`, which closes the
/// listening socket for us - so on paper there is no moment when two
/// processes want the port. The kernel disagrees for a few milliseconds:
/// the PCB behind that socket is torn down asynchronously, and the
/// replacement image, which needs only ~12 ms to get from `exec` to here,
/// arrives while it is still there. Measured on macOS 27 with twelve
/// restart lanes in parallel: 46 of 1200 restarts (3.8%) failed to bind,
/// and at the moment of failure the port was not merely reserved - a
/// `connect` to it still completed a handshake. Every one of them cleared
/// within 1.2-20.5 ms.
///
/// So this is NOT the classic rebind problem and the classic answers do
/// not touch it. `SO_REUSEADDR` is already set (`std` sets it on every
/// unix listener) and covers TIME_WAIT, which is not what is happening -
/// there is no TIME_WAIT here, the whole port is empty seconds later.
/// The fd is already close-on-exec, so there is nothing left to close
/// explicitly, and closing the listener BEFORE the exec would only move
/// the same asynchronous teardown earlier while opening a window in which
/// a stranger could take the port for real. `SO_REUSEPORT` would let the
/// bind through, but by letting two daemons share the port - it would
/// dismantle the "second instance refuses to start" guarantee that the
/// test suites and every duplicated-container report rely on. What is
/// left is to wait the teardown out, which is what this does.
///
/// Left general rather than gated on "did we just re-exec?": a supervisor
/// that restarts us the instant we exit - systemd, Docker, the tray, or a
/// person retyping the command after Ctrl-C - lands in the same window
/// from the outside.
///
/// The same 1200 restarts with the wait in place lost none of them, and
/// 159 (13%) reported having waited - a higher number than the 3.8% that
/// used to die, because it counts every restart that met the window and
/// not just the ones the window outlasted. Longest absorbed: 25 ms.
fn bind_past_a_closing_predecessor<T>(
    bind: &str,
    port: u16,
    mut attempt: impl FnMut() -> std::result::Result<T, BindError>,
) -> std::result::Result<T, BindError> {
    let started = Instant::now();
    let mut waited = false;
    loop {
        let e = match attempt() {
            Ok(server) => {
                if waited {
                    info!(
                        target: "startup",
                        "{bind}:{port} was still held when we started - the previous \
                         listener took {} ms to close",
                        started.elapsed().as_millis()
                    );
                }
                return Ok(server);
            }
            Err(e) => e,
        };
        // tiny_http boxes the io::Error from its own bind verbatim, so
        // the kind survives; anything else is a real failure and is
        // reported at once.
        let busy = e
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse);
        if !busy || started.elapsed() >= BIND_GRACE {
            return Err(e);
        }
        waited = true;
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Build the rustls server config for `--tls-cert`/`--tls-key`, with the
/// failure modes an operator actually hits spelled out and the offending
/// FILE named: unreadable, not PEM, empty chain, expired or not yet valid,
/// key that does not match. The provider is aws-lc-rs by name, like every
/// other TLS surface in the tree (both aws-lc-rs and ring are linked, so a
/// provider-less `builder()` panics at run time - see
/// `nzbkit::benchserve::tls_config`).
///
/// Expiry is checked on the LEAF (first) certificate only, and it refuses
/// rather than warns: every client will refuse it too, so "starts, then
/// nothing can connect" is the strictly worse behaviour. A CA-flagged leaf
/// (basicConstraints CA:TRUE - what a bare `openssl req -x509` mints) only
/// warns: browsers accept it with a click-through, and only rustls-strict
/// clients refuse it as CaUsedAsEndEntity.
fn tls_server_config(cert: &Path, key: &Path) -> Result<std::sync::Arc<rustls::ServerConfig>> {
    use rustls::pki_types::pem::PemObject;
    let certs: Vec<rustls::pki_types::CertificateDer<'_>> =
        rustls::pki_types::CertificateDer::pem_file_iter(cert)
            .map_err(|e| anyhow::anyhow!("tls_cert {}: {e}", cert.display()))?
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("tls_cert {}: {e}", cert.display()))?;
    if certs.is_empty() {
        anyhow::bail!(
            "tls_cert {}: no certificates in the file (is it a PEM certificate?)",
            cert.display()
        );
    }
    match x509_parser::parse_x509_certificate(certs[0].as_ref()) {
        Ok((_, leaf)) => {
            let v = leaf.validity();
            let now = x509_parser::time::ASN1Time::now();
            if !v.is_valid_at(now) {
                anyhow::bail!(
                    "tls_cert {}: the certificate is {} (valid {} to {}) - every browser \
                     and API client will refuse it. Renew it, or remove tls_cert/tls_key \
                     to serve plain HTTP",
                    cert.display(),
                    if now > v.not_after {
                        "expired"
                    } else {
                        "not valid yet"
                    },
                    v.not_before,
                    v.not_after,
                );
            }
            if leaf.is_ca() {
                eprintln!(
                    "⚠ tls_cert {}: the certificate is flagged as a CA \
                     (basicConstraints CA:TRUE - what a bare `openssl req -x509` produces). \
                     Browsers allow it with a warning, but strict clients refuse a CA \
                     certificate used as a server certificate. Re-issue with \
                     -addext basicConstraints=critical,CA:FALSE to satisfy everyone.",
                    cert.display()
                );
            }
        }
        Err(e) => {
            anyhow::bail!(
                "tls_cert {}: not a valid X.509 certificate ({e})",
                cert.display()
            )
        }
    }
    let key_der = rustls::pki_types::PrivateKeyDer::from_pem_file(key)
        .map_err(|e| anyhow::anyhow!("tls_key {}: {e}", key.display()))?;
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| anyhow::anyhow!("tls: {e}"))?
    .with_no_client_auth()
    .with_single_cert(certs, key_der)
    .map_err(|e| {
        anyhow::anyhow!(
            "tls: {} / {}: {e} (usually the key does not belong to the certificate)",
            cert.display(),
            key.display()
        )
    })?;
    Ok(std::sync::Arc::new(config))
}

pub(super) fn acquire_serve_lock(spool: &Path, config: &Path) -> Result<Option<std::fs::File>> {
    // ONE daemon per data directory. Two daemons sharing one - the
    // classic shape is an old container still running while its
    // replacement starts on another port - trade last-writer-wins
    // clobbers of settings.json and the queue, each overwriting the
    // other's state on every save with nothing on screen to say so. An
    // OS advisory lock, so it dies with the process and there is no
    // stale-lock state to recover from.
    //
    // Placement: after `spool_dir`, whose migration logic treats an
    // empty new spool as a placeholder to remove - a lock file created
    // inside it earlier would read as a completed migration. After the
    // bind, so a daemon that merely lost its port still exits through
    // the bind error and writes nothing (pinned by
    // a_daemon_that_loses_its_port_writes_nothing). And before the
    // Daemon is constructed, ahead of every runtime writer.
    //
    // Only a HELD lock refuses. A filesystem that cannot lock at all
    // (some network mounts) carries on silently: refusing there would
    // brick every NAS install that survives today, to close a race it
    // cannot even detect.
    Ok(
        match std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(spool.join("serve.lock"))
        {
            Ok(f) => {
                // A restart is allowed to overlap itself: launchers and
                // deploy scripts start the replacement while the old
                // process is still tearing down, and the lock is released
                // at its death, not at any earlier point. So a held lock
                // gets a few seconds to clear before it is treated as a
                // genuinely concurrent daemon.
                let mut verdict = f.try_lock();
                for _ in 0..25 {
                    match verdict {
                        Err(std::fs::TryLockError::WouldBlock) => {
                            std::thread::sleep(std::time::Duration::from_millis(120));
                            verdict = f.try_lock();
                        }
                        _ => break,
                    }
                }
                match verdict {
                    Ok(()) => Some(f),
                    Err(std::fs::TryLockError::WouldBlock) => {
                        let dir = config.parent().unwrap_or(config);
                        anyhow::bail!(
                            "another nzbfast daemon is already serving from {} - two daemons \
                         sharing one data directory overwrite each other's settings and \
                         queue, so this one is stopping. Stop the other daemon first; an \
                         old container or launcher still running is the usual cause. To \
                         run several daemons on purpose, give each its own --config.",
                            dir.display()
                        );
                    }
                    Err(std::fs::TryLockError::Error(_)) => None,
                }
            }
            Err(_) => None,
        },
    )
}

pub(super) fn spawn_core_tasks(
    daemon: &Arc<Daemon>,
    config: &Path,
    settings_path: &Path,
    schedule: &Option<PathBuf>,
    feeds: &Option<PathBuf>,
    #[cfg(feature = "indexer")] index_db: &Path,
    mem_budget: nzbkit::mem::MemBudget,
) -> Result<()> {
    hooks::spawn_dispatcher(daemon);

    tasks::spawn_scheduler(daemon, settings_path, schedule)?;

    tasks::spawn_watch_folder(daemon);

    tasks::spawn_memory_trim(daemon);
    tasks::spawn_usage_flush(daemon);
    tasks::spawn_queue_saver(daemon);
    tasks::spawn_hunt_worker(daemon);

    tasks::spawn_auto_speed(daemon, config);

    #[cfg(feature = "indexer")]
    tasks::spawn_group_catalog(daemon, config);

    #[cfg(feature = "indexer")]
    tasks::spawn_search_log_writer(daemon);

    // Full scans, the tip watcher and VACUUM all write the same SQLite
    // file. A shared pass gate makes the exclusion two-way: checking an
    // atomic once did not stop a tip OVER already in flight from returning
    // and writing after a full pass began.
    let index_pass_gate = Arc::new(tokio::sync::Mutex::new(()));

    #[cfg(feature = "indexer")]
    tasks::spawn_index_scan(daemon, config, index_db, &index_pass_gate);

    #[cfg(feature = "indexer")]
    tasks::spawn_index_compact(daemon, &index_pass_gate);

    // The pre feed: the IRC listener and its database writer (both inert
    // unless the user has switched the feature on) - see tasks.rs.
    #[cfg(feature = "indexer")]
    tasks::spawn_predb_feed(daemon);

    #[cfg(feature = "indexer")]
    tasks::spawn_tip_watcher(daemon, config, &index_pass_gate);

    #[cfg(feature = "indexer")]
    tasks::spawn_oracle_sampler(daemon, config);

    // TODO 131 B3: the byte-probe naming lane. Gated like the
    // enrichment workers: it spends real provider articles, so test
    // and scratch daemons must be able to keep it entirely off the
    // wire with one env var.
    #[cfg(feature = "indexer")]
    if std::env::var_os("NZBFAST_NO_ENRICH").is_none() {
        tasks::spawn_probe7z(daemon, config);
        // TODO 131 #6: the posted-NZB ingestion rung - same gate, for
        // the same reason (it fetches posted objects off the fleet).
        tasks::spawn_nzb_import(daemon, config);
    }

    // TODO 131 red-team 5a: the pesto tiny-PAR2 naming rung. Same
    // wire-spend gate as the byte prober.
    #[cfg(feature = "indexer")]
    if std::env::var_os("NZBFAST_NO_ENRICH").is_none() {
        tasks::spawn_pesto(daemon, config);
    }

    // The parity scoreboard's daily sampler - inert until the user has
    // saved a reference indexer URL and switched it on.
    #[cfg(feature = "indexer")]
    tasks::spawn_scoreboard(daemon);

    // The indexer-confirm lane: correlation suggestions -> proven
    // names via the user's own indexer account. Inert until switched
    // on AND aimed at an account; its NO_ENRICH gate lives inside the
    // spawn (the env cannot change under a running process).
    #[cfg(feature = "indexer")]
    tasks::spawn_corr_confirm(daemon);

    tasks::spawn_health_prober(daemon, config);

    tasks::spawn_rss_poller(daemon, settings_path, feeds)?;

    tasks::spawn_watchlist_watcher(daemon);

    // §151: the external list sources that FILL that watchlist. Only the
    // polling loop is here - the sources and the items they own are
    // restored at construction (`listsrc::seed_lists`), because the
    // ingest legs above read their union with the user's own rows.
    spawn_list_sync(daemon);

    tasks::spawn_download_worker(daemon, config, &index_pass_gate, mem_budget);

    tasks::spawn_library_recheck(daemon, config);

    // C: the mover - finished jobs' move-completed relocations run
    // here, off the finalize tail. Re-queue what a previous run left
    // owed BEFORE the worker starts draining: `move_pending` persists,
    // and move_tree's staging survives a mid-move kill, so a restart
    // resumes with a fresh copy instead of a stranded payload.
    for job in daemon.history.lock_ok().iter() {
        let owed = {
            let g = job.lock_ok();
            g.state == crate::serve::job::JobState::Completed && g.move_pending
        };
        if owed {
            daemon.mover_enqueue(job);
        }
    }
    mover::spawn_mover(daemon);
    // §296: and the per-file half of it - a finished, PAR2-vouched
    // plain file reaches the destination while the rest of the job is
    // still on the wire. Inert unless `early_file_publish` is on.
    super::earlyfile::spawn(daemon);

    // §76: the queue-row quality chip - reads the running job's own
    // container header so the row can say what the file IS, and warn
    // when that contradicts the name it was posted under.
    tasks::spawn_media_prober(daemon);
    // §188: and the same chip on rows written by an OLDER build, whose
    // labels a since-fixed derivation rule got wrong. Runs once per
    // version, on its own thread, never blocking the daemon coming up.
    super::histmigrate::spawn_history_media_migrate(daemon);

    tasks::spawn_slow_job_watchdog(daemon, config, mem_budget);
    tasks::spawn_live_tuner(daemon, config);
    // §210: which interface carries the traffic, for the tune hint.
    super::locallink::spawn(daemon, config);
    super::linkpeak::spawn(daemon);
    // §129 3e: the chronic slow-storage judge. Inert unless a job is
    // downloading (or its own pause is holding).
    super::slowstore::spawn(daemon);
    // Issue #45: the History retention sweep. Inert unless a retention knob
    // is set; see `spawn_retention_sweep` for why a park-time pass alone
    // stopped being enough once the age rule could be minutes.
    super::histstore::spawn_retention_sweep(daemon);
    Ok(())
}

/// The background lanes that need nothing but the daemon and the config
/// path. Spawned after [`spawn_core_tasks`], and after the enrichment
/// workers, which need the TMDB key resolved first.
pub(super) fn spawn_aux_tasks(daemon: &Arc<Daemon>, config: &Path) {
    tasks::spawn_update_checker(daemon);
    tasks::spawn_scheduled_bench(daemon, config);
    tasks::spawn_auto_connections(daemon, config);
    finish_action::spawn_finish_watcher(daemon);
}

pub(super) fn announce_ready(
    daemon: &Arc<Daemon>,
    settings_path: &Path,
    bind: &str,
    port: u16,
    tls: bool,
    minted_key: &Option<(String, PathBuf)>,
    mint_disclosure: &mut MintDisclosure,
    open: bool,
) {
    // HTTP API on a blocking thread. The listener itself was taken at the
    // top of startup (see the bind note beside spool_dir); this is where
    // we start answering on it, and where readiness is announced.
    // Written only once the listener EXISTS, so its presence means this
    // daemon really did get the port (see `write_runtime_file`) - and
    // BEFORE the banner, because the banner is what everything else
    // treats as the readiness signal. Printing first left a window in
    // which a launcher (or a test harness) saw "nzbfast is running",
    // went looking for runtime.json, and found nothing: the handshake
    // then silently degraded to the no-token path, which is exactly the
    // permissive arm. The listener is already bound here, so nothing
    // about the file's meaning changes.
    write_runtime_file(settings_path, port, tls, &daemon.launcher_token);
    // The scheme in the banner is load-bearing: harnesses and launchers
    // treat the exact line as the readiness signal, and a user pasting
    // the URL must get the one this listener actually answers.
    let scheme = if tls { "https" } else { "http" };
    // TODO 281 IO3b: without `dashboard` there is no page at `/`, so the
    // usual line would send a reader to a 404 - which is precisely the
    // confusion a store binary must not create in its own log. The
    // "nzbfast is running" PREFIX is kept in both arms, because that is
    // what every launcher and test harness keys on; only the claim after
    // it changes. Nothing on the slim path reads this at all (both phone
    // shells take the port from `runtime.json`), and the harness that
    // does match the whole line runs default features.
    #[cfg(feature = "dashboard")]
    println!("nzbfast is running - open the dashboard at  {scheme}://localhost:{port}/");
    #[cfg(not(feature = "dashboard"))]
    println!("nzbfast is running - this build carries no web dashboard, only the API below");
    println!("(SABnzbd-compatible API for Sonarr/Radarr at  {scheme}://localhost:{port}/api)");
    if let Some((key, keyfile)) = &minted_key {
        // Printed exactly once, on the first run that generated it. It is
        // the credential the user must paste into Sonarr/Radarr, so it
        // goes right under the dashboard URL rather than into the startup
        // scrollback above.
        // Deliberately small. Nothing here is a task: the key was
        // generated for the user, the dashboard link above already
        // carries it, and Settings can show it again whenever they get
        // round to Sonarr. A boxed banner reserving a third of the first
        // screen made a step that asks nothing read like a step that
        // asks something, which is the opposite of true. The value still
        // gets printed, because a headless first run has nowhere else to
        // read it from.
        println!();
        println!("  API key: {key}");
        println!(
            "  Set up automatically. Sonarr/Radarr need it; Settings → Security \
             can show it again or make a new one."
        );
        let _ = keyfile;
        println!();
        // The key has been shown; the failure-path disclosure would now
        // be noise.
        mint_disclosure.disarm();
    }
    if daemon.apikey.lock_ok().is_none() {
        // No API key → every request is treated as fully authorized (bug
        // sweep). Make the exposure impossible to miss; logtee mirrors
        // this into the dashboard log as well.
        eprintln!(
            "⚠ SECURITY: no apikey is set - the API on {bind}:{port} is OPEN to every host that \
             can reach this machine. Any device on your network, or a web page you visit (CSRF), \
             can add or delete jobs and change settings. Set an API key in Settings, or firewall \
             the port, unless this box is on a fully trusted network."
        );
    }
    if open {
        open_dashboard(port, tls, minted_key.as_ref().map(|(k, _)| k.clone()));
    }
}

/// Issue #9: a fresh-install mint with a non-empty download root means
/// the config directory most likely moved - say so, loudly, once.
///
/// One explanation, printed at the moment it is true. A minted key
/// means the data directory read as brand new; a download root already
/// in use says the more likely story is an EXISTING install whose
/// config directory moved out from under it - a recreated container
/// reading an empty /config, a relative bind mount run from a
/// different directory, a fresh appdata path. From here everything
/// behaves like a first run, and without this line the user's next
/// stop is a bug report titled "all my settings are gone" (issue #9's
/// field report, verbatim).
///
/// A warning ONLY. The download root must never join the
/// fresh-vs-existing decision itself - that was tried, and it was a
/// security regression (see first_run_apikey). Nothing here changes
/// what was minted or decided.
pub(super) fn warn_if_config_moved(minted_key: &Option<(String, PathBuf)>, out_root: &Path) {
    if minted_key.is_some() {
        let prior_use = out_root.join(".spool").exists()
            || std::fs::read_dir(out_root)
                .map(|mut entries| entries.next().is_some())
                .unwrap_or(false);
        if prior_use {
            eprintln!(
                "⚠ starting as a NEW install (nothing in the config directory), but the \
                 download folder {} is not empty. If you had settings before - servers, \
                 paths, an API key - nothing deleted them: nzbfast is most likely reading \
                 a different config directory than your previous install used. Docker and \
                 NAS users: compare the /config volume mapping with the old container's. \
                 The manual has the recovery steps, under Troubleshooting (/manual in the \
                 dashboard). If this really is a new install, carry on - nothing is wrong.",
                out_root.display()
            );
        }
    }
}

/// What `boot` hands back: the daemon itself, the listener and
/// lock it took on the way, and the handful of opts values the
/// rest of serve() still needs. Everything else in ServeOpts is
/// consumed into the Daemon's fields.
pub(super) struct Booted {
    pub(super) daemon: Arc<Daemon>,
    pub(super) server: tiny_http::Server,
    /// The single-instance lock. Held, never read: dropping it
    /// frees the lock, so it must outlive the run - see the bind
    /// note in serve().
    pub(super) _serve_lock: Option<std::fs::File>,
    pub(super) spool: PathBuf,
    pub(super) bind: String,
    pub(super) port: u16,
    pub(super) tls_on: bool,
    pub(super) open: bool,
    pub(super) schedule: Option<PathBuf>,
    pub(super) feeds: Option<PathBuf>,
    pub(super) speedlimit: Option<String>,
    pub(super) mem_budget: nzbkit::mem::MemBudget,
    #[cfg(feature = "indexer")]
    pub(super) index_db: PathBuf,
}

/// Resolve the options, take the port and the lock, and build the
/// Daemon (TODO 106: lifted out of serve(), which was 535 lines
/// against a 500 ceiling and 334 of them this one struct literal).
/// The code is verbatim and the ORDER is load-bearing exactly as
/// startup.rs's header says: the key is settled before the bind,
/// the bind before anything writes to the data directory.
pub(super) fn boot(config: &Path, settings_path: &Path, opts: ServeOpts) -> Result<Booted> {
    // Owned copies so the construction below reads as it did inside
    // serve(), where both were locals.
    let config = config.to_path_buf();
    let settings_path = settings_path.to_path_buf();
    let ServeOpts {
        group_desc_isc: _,
        port,
        bind,
        tls_cert,
        tls_key,
        open,
        apikey,
        nzbkey,
        out_root,
        watch,
        script,
        connections,
        window,
        decoders,
        fast_verify,
        verify_lean,
        min_free,
        out_umask,
        auto_retry_mins,
        preflight,
        quota,
        quota_period,
        feeds,
        speedlimit,
        schedule,
        auto_speed,
        library_cats,
        library_recheck_secs,
        mem_budget,
        #[cfg(feature = "indexer")]
        index_db,
        #[cfg(feature = "indexer")]
        index_groups,
        #[cfg(feature = "indexer")]
        index_interval_secs,
        #[cfg(feature = "indexer")]
        index_backfill,
        #[cfg(feature = "indexer")]
        index_max_age_secs,
        #[cfg(feature = "indexer")]
        index_gates,
    } = opts;
    let legacy_rename_punctuation = legacy_rename_punctuation(&config, &out_root, &settings_path);
    // The indexer's master switch, and the one migration it needs.
    //
    // A saved value always wins - that is the user's answer. With NO
    // saved value we are either a fresh install (off: see the field's
    // doc comment) or an install from before the switch existed, and
    // those two are told apart by whether anything was ever chosen to
    // index. Groups here already carry settings.json and the config file
    // (see the settings merge above), so a CLI `--index-groups` or a
    // hand-written config counts too - starting a daemon that was
    // explicitly pointed at groups and then not scanning them would be
    // the same surprise as the upgrade case.
    #[cfg(not(feature = "indexer"))]
    let index_enabled = false;
    #[cfg(feature = "indexer")]
    let index_enabled = resolve_index_enabled(&settings_path, &index_groups);
    // Resolved once: every spool path below must agree, or a migrated
    // daemon reads half its state from the old location.
    // Both of these were inline here until origin's parallel size-gate
    // pass lifted them; the comments that explain them live on the
    // helpers now.
    let out_root = absolute_out_root(out_root);
    let tls_pair = resolve_tls_pair(&tls_cert, &tls_key);
    let server = take_listener(&bind, port, tls_pair)?;
    // From here on the port is the one the LISTENER got, not the one that
    // was asked for. They differ in exactly one case: `--port 0`, which
    // asks the OS to pick a free one. Everything downstream reads this
    // binding - runtime.json, the readiness banner, `Daemon::port` and the
    // settings card's "what is this run actually serving" - so a caller
    // that cannot name a port in advance still gets a daemon that names it
    // afterwards.
    //
    // The Android app is the caller that needs it (TODO 158 item 4). Its
    // on-device engine used to bind a hardcoded 6791, and Android apps
    // share one loopback namespace, so a port a sibling app can predict is
    // a port it can pre-bind. The app now passes 0 and reads the answer
    // back out of runtime.json.
    //
    // For a port the caller DID name this is the identity - a bind on 6789
    // reports 6789 - so no existing launch changes shape. `to_ip` is None
    // only for a unix-socket listener, which this build never takes; the
    // requested value is the honest fallback there.
    let port = server.server_addr().to_ip().map_or(port, |a| a.port());
    let tls_on = tls_pair.is_some();
    let spool = spool_dir(&config, &out_root);
    // Windows has no dotfile convention, so `.spool` is plainly visible
    // wherever it lands - including inside the user's download folder on
    // an install that predates the data-dir move. Create it up front so
    // there is something to set the attribute ON: every other writer
    // makes it implicitly via create_dir_all of a child, which would
    // leave the hide to lose a race it cannot see.
    let _ = std::fs::create_dir_all(&spool);
    nzbkit::disk::hide_from_user(&spool);
    let _serve_lock = acquire_serve_lock(&spool, &config)?;
    // The Daemon itself: see build_daemon. Only the argument list is
    // new - the literal moved verbatim. `spool`, `mem_budget` and
    // `index_db` are cloned because `Booted` below still returns them.
    let daemon = build_daemon(
        config,
        settings_path,
        out_root,
        spool.clone(),
        port,
        bind.clone(),
        tls_on,
        tls_cert,
        tls_key,
        apikey,
        nzbkey,
        opts.group_desc_isc,
        connections,
        window,
        decoders,
        fast_verify,
        verify_lean,
        preflight,
        auto_speed,
        auto_retry_mins,
        min_free,
        out_umask,
        quota,
        quota_period,
        watch,
        script,
        mem_budget,
        library_cats,
        library_recheck_secs,
        index_enabled,
        legacy_rename_punctuation,
        #[cfg(feature = "indexer")]
        index_db.clone(),
        #[cfg(feature = "indexer")]
        index_groups,
        #[cfg(feature = "indexer")]
        index_interval_secs,
        #[cfg(feature = "indexer")]
        index_backfill,
        #[cfg(feature = "indexer")]
        index_max_age_secs,
        #[cfg(feature = "indexer")]
        index_gates,
    );
    // Weakly, for the embedded host's reclamation test: one entry per
    // run, and a generation that survives its own stop is a leak that
    // shows up as a `Weak` still upgradable. Costs a pointer per run.
    super::census_daemon(&daemon);

    Ok(Booted {
        daemon,
        server,
        _serve_lock,
        spool,
        bind,
        port,
        tls_on,
        open,
        schedule,
        feeds,
        speedlimit,
        mem_budget,
        #[cfg(feature = "indexer")]
        index_db,
    })
}

/// Build the `Daemon` from the resolved options (TODO 106).
///
/// The struct literal is 379 of `boot`'s 503 lines and cannot be cut
/// any smaller than itself - it is one `field: value` per line for a
/// hundred-odd fields - so the whole of it moves and `boot` keeps the
/// resolution above it, whose ORDER is load-bearing (the key is settled
/// before the bind, the bind before anything writes to the data dir).
/// The literal is VERBATIM; only the argument list is new. Six
/// parameters carry the same `#[cfg(feature = "indexer")]` they carry
/// in `ServeOpts`, and `group_desc_isc` is passed as a bool because the
/// destructure in `boot` leaves it un-moved on `opts` (its pattern is
/// `_`), which is too subtle to re-create here.
#[expect(clippy::too_many_arguments)]
fn build_daemon(
    config: PathBuf,
    settings_path: PathBuf,
    out_root: PathBuf,
    spool: PathBuf,
    port: u16,
    bind: String,
    tls_on: bool,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    apikey: Option<String>,
    nzbkey: Option<String>,
    group_desc_isc: bool,
    connections: usize,
    window: usize,
    decoders: usize,
    fast_verify: bool,
    verify_lean: bool,
    preflight: bool,
    auto_speed: bool,
    auto_retry_mins: u64,
    min_free: Option<u64>,
    out_umask: Option<u32>,
    quota: Option<u64>,
    quota_period: char,
    watch: Option<PathBuf>,
    script: Option<PathBuf>,
    mem_budget: nzbkit::mem::MemBudget,
    library_cats: Vec<String>,
    library_recheck_secs: u64,
    index_enabled: bool,
    legacy_rename_punctuation: bool,
    #[cfg(feature = "indexer")] index_db: PathBuf,
    #[cfg(feature = "indexer")] index_groups: Vec<String>,
    #[cfg(feature = "indexer")] index_interval_secs: u64,
    #[cfg(feature = "indexer")] index_backfill: u64,
    #[cfg(feature = "indexer")] index_max_age_secs: u64,
    #[cfg(feature = "indexer")] index_gates: Option<crate::gates::Gates>,
) -> Arc<Daemon> {
    Arc::new(Daemon {
        hub: Arc::new(crate::StreamHub::default()),
        paused: std::sync::atomic::AtomicBool::new(false),
        offline: std::sync::atomic::AtomicBool::new(false),
        paused_by_offline: std::sync::atomic::AtomicBool::new(false),
        exiting: std::sync::atomic::AtomicBool::new(false),
        queue: Mutex::new(VecDeque::new()),
        history: Mutex::new(Vec::new()),
        queue_rev: AtomicU64::new(1),
        history_rev: AtomicU64::new(1),
        hist_inflight: Mutex::new(std::collections::HashSet::new()),
        hist_rewrite_fail_ms: AtomicU64::new(0),
        life_seq: AtomicU64::new(0),
        life_events: Mutex::new(VecDeque::new()),
        queue_idle_latch: AtomicBool::new(true),
        pause_announced: AtomicBool::new(false),
        postproc_backlog: Arc::new(AtomicUsize::new(0)),
        finish: Default::default(),
        save_soon: AtomicBool::new(false),
        save_wake: tokio::sync::Notify::new(),
        saver_armed: AtomicBool::new(false),
        save_failed_at: AtomicU64::new(0),
        hooks_tx: Mutex::new(None),
        history_keep_count: AtomicU64::new(0),
        history_keep_secs: AtomicU64::new(0),
        add_lock: Mutex::new(()),
        moving: Mutex::new(std::collections::HashSet::new()),
        mover_q: Mutex::new(VecDeque::new()),
        mover_inflight: std::sync::atomic::AtomicUsize::new(0),
        mover_wake: tokio::sync::Notify::new(),
        mover_bucket: Mutex::new(mover::PaceState::default()),
        move_pace: Mutex::new("yield".to_string()),
        // §296. OFF by default - see the field docs for why the answer
        // is not "it is safe, so turn it on": it engages only for a job
        // whose tail renames and sweeps nothing, so for everyone else it
        // is a poll and a second read of every finished file in
        // exchange for no early file at all.
        early_file_publish: std::sync::atomic::AtomicBool::new(false),
        write_manifest: std::sync::atomic::AtomicBool::new(false),
        boot_at: Instant::now(),
        metrics_open: std::sync::atomic::AtomicBool::new(false),
        reserved: Mutex::new(std::collections::HashSet::new()),
        progress: ProgressCell::default(),
        drain_dl: Mutex::new(None),
        active_total: AtomicU64::new(0),
        active_dl: Mutex::new(None),
        started_at: Mutex::new(None),
        last_download_end: Mutex::new(Instant::now()),
        stall_since: Mutex::new(None),
        playback_disk: Mutex::new(std::collections::HashMap::new()),
        next_id: AtomicU64::new(1),
        out_root: std::sync::RwLock::new(out_root.clone()),
        move_completed: std::sync::RwLock::new(None),
        move_completed_cats: std::sync::RwLock::new(Vec::new()),
        spool: spool.clone(),
        cfg_path: config.clone(),
        cats: Mutex::new(DEFAULT_CATS.iter().map(|s| s.to_string()).collect()),
        port,
        // What THIS run's listener bound to. `boot` still owns the
        // string (Booted returns it for the readiness banner), so this
        // is a clone rather than a move.
        bind,
        // A failed mint leaves an EMPTY token, and `launcher_proof` then
        // answers a challenge with sha256(":nonce") - a value any process
        // could compute. Refuse to answer at all instead: the wrappers
        // treat "no proof" as "an older daemon" and fall back, which is
        // strictly better than a proof anyone can forge.
        launcher_token: random_apikey().unwrap_or_default(),
        port_locked: port_locked(),
        // What THIS run bound with (both present and valid, or the run
        // would not exist) - the settings card reads these back, and
        // `pending` in get_config diffs them against the saved values.
        tls_cert: if tls_on { tls_cert.clone() } else { None },
        tls_key: if tls_on { tls_key.clone() } else { None },
        library_cats: Mutex::new(library_cats),
        active_stream: Mutex::new(None),
        #[cfg(feature = "indexer")]
        index_db: index_db.clone(),
        #[cfg(feature = "indexer")]
        index: Mutex::new(None),
        #[cfg(feature = "indexer")]
        index_read: IndexReadPool::default(),
        #[cfg(feature = "indexer")]
        index_read_warned: AtomicU64::new(0),
        #[cfg(feature = "indexer")]
        index_migrated: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        index_stats_cache: Mutex::new(Default::default()),
        auto_speed: std::sync::atomic::AtomicBool::new(auto_speed),
        preflight: std::sync::atomic::AtomicBool::new(preflight),
        auto_connections: std::sync::atomic::AtomicBool::new(true),
        // OFF until the §129 real-line gate passes (design §9 step 4).
        live_tune: std::sync::atomic::AtomicBool::new(false),
        shaped_hosts: Mutex::new(Default::default()),
        capped_hosts: Mutex::new(Default::default()),
        wall_hide_adult: std::sync::atomic::AtomicBool::new(true),
        auto_defer: std::sync::atomic::AtomicBool::new(true),
        post_health: std::sync::atomic::AtomicBool::new(true),
        post_health_defer: std::sync::atomic::AtomicBool::new(true),
        alt: Default::default(),
        post_health_fail: std::sync::atomic::AtomicBool::new(false),
        auto_prefetch: std::sync::atomic::AtomicBool::new(true),
        race_stragglers: std::sync::atomic::AtomicBool::new(true),
        adaptive_timeouts: std::sync::atomic::AtomicBool::new(true),
        oracle_route: std::sync::atomic::AtomicBool::new(false),
        index_deepen: AtomicU64::new(200_000),
        index_coverage: std::sync::atomic::AtomicBool::new(true),
        index_gapfill: AtomicU64::new(4),
        index_probe7z: std::sync::atomic::AtomicBool::new(true),
        index_probe7z_budget: AtomicU64::new(150),
        index_pesto: std::sync::atomic::AtomicBool::new(true),
        index_pesto_budget: AtomicU64::new(120),
        index_search_log: std::sync::atomic::AtomicBool::new(true),
        #[cfg(feature = "indexer")]
        search_log_buf: Mutex::new(std::collections::HashMap::new()),
        #[cfg(feature = "indexer")]
        search_log_clear_pending: std::sync::atomic::AtomicBool::new(false),
        index_nzbimport: std::sync::atomic::AtomicBool::new(true),
        index_nzbimport_budget: AtomicU64::new(300),
        bench_interval: AtomicU64::new(0),
        bench_last: AtomicU64::new(0),
        bench_running: std::sync::atomic::AtomicBool::new(false),
        bench_history_lock: Mutex::new(()),
        update_manifest: Mutex::new(None),
        update_serial_seen: std::sync::atomic::AtomicU64::new(0),
        // Notify-only: finding a newer version raises the dashboard
        // banner and nothing else - the daemon never replaces its own
        // binary (the self-update code was removed in 1.0.5; the
        // manifest itself is still ed25519-verified before the banner
        // trusts it). ON by default so users hear about releases; turn
        // it off here (or empty update_url) and the daemon never
        // phones the manifest at all.
        update_checks: std::sync::atomic::AtomicBool::new(true),
        unit_bits: std::sync::atomic::AtomicBool::new(false),
        update_url: Mutex::new(DEFAULT_UPDATE_URL.to_string()),
        ui_locale: Mutex::new(String::new()),
        cors_origin: Mutex::new(CORS_DEFAULT.to_string()),
        sidecar: Mutex::new(None),
        sidecar_tails: Mutex::new(Vec::new()),
        media_final_owed: Mutex::new(Vec::new()),
        best_rate_bps: AtomicU64::new(0),
        speed_ceiling: AtomicU64::new(0),
        mem_budget_total: mem_budget.total,
        feeds: Mutex::new(Vec::new()),
        feed_health: Mutex::new(Default::default()),
        last_refusals: Mutex::new(Default::default()),
        events: Mutex::new(Default::default()),
        indexers: Mutex::new(Vec::new()),
        watchlist_external: std::sync::atomic::AtomicBool::new(false),
        watchlist_external_set: std::sync::atomic::AtomicBool::new(false),
        indexer_rt: Mutex::new(IndexerRuntime::default()),
        // §74: on by default and inert without the indexer - see the
        // field. Saved settings replay over these below.
        watchlist_instant: AtomicBool::new(true),
        watchlist_instant_max: std::sync::atomic::AtomicU32::new(INSTANT_MAX_DEFAULT),
        // Retention insurance: 0 = off, and off means byte-identical to
        // a daemon without the feature. Saved settings replay below.
        insurance_cap_gb: AtomicU64::new(0),
        watchlist_deferred: AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        instant_kicks: Mutex::new(std::collections::VecDeque::new()),
        #[cfg(feature = "indexer")]
        instant_pending: Mutex::new(std::collections::HashMap::new()),
        instant_hint: Mutex::new(Vec::new()),
        nzblnk_gate: NzblnkGate::default(),
        smart_folders: Mutex::new(Vec::new()),
        par_cleanup: AtomicBool::new(true),
        postproc_jobs: AtomicU64::new(2),
        slow_storage: Default::default(),
        pause_cost: Default::default(),
        // OFF unless asked for: a silent install keeps its modes (#20).
        out_umask: std::sync::atomic::AtomicU32::new(out_umask.unwrap_or(u32::MAX)),
        fast_par: AtomicBool::new(FAST_PAR_DEFAULT),
        prefer_external_unrar: AtomicBool::new(false),
        cleanup_exts: Mutex::new(Vec::new()),
        password_file: Mutex::new(config.with_file_name("passwords.txt")),
        password_prompt: Mutex::new("done".to_string()),
        preview: Mutex::new(PREVIEW_DEFAULT.to_string()),
        unpack_eat_volumes: Mutex::new("off".to_string()),
        // Loaded from settings.json below (next to smart_folders); the
        // reclassify flag starts set so startup reconciles the stored
        // rows against the current config exactly once (the index stamps
        // the config fingerprint, so an unchanged config is a no-op).
        custom_categories: std::sync::RwLock::new(Vec::new()),
        reclassify_pending: std::sync::atomic::AtomicBool::new(true),
        // Auto-rename defaults: on, with resolution in the name; codecs /
        // source / group off; junk sweep on; keep-media-only off. Saved
        // settings replay over these below.
        identity_lookup: std::sync::atomic::AtomicBool::new(true),
        auto_rename: std::sync::atomic::AtomicBool::new(true),
        rename_resolution: std::sync::atomic::AtomicBool::new(true),
        rename_vcodec: std::sync::atomic::AtomicBool::new(false),
        rename_acodec: std::sync::atomic::AtomicBool::new(false),
        rename_source: std::sync::atomic::AtomicBool::new(false),
        rename_group: std::sync::atomic::AtomicBool::new(false),
        rename_year_parens: std::sync::atomic::AtomicBool::new(legacy_rename_punctuation),
        rename_quality_brackets: std::sync::atomic::AtomicBool::new(legacy_rename_punctuation),
        rename_extra_words: std::sync::atomic::AtomicBool::new(true),
        rename_identify: std::sync::atomic::AtomicBool::new(true),
        // Off by default, alone among the rename sub-settings: it
        // changes filenames an existing install already wrote, and an
        // *arr's import matcher is reading those. See the field docs.
        rename_episode_titles: std::sync::atomic::AtomicBool::new(false),
        history_rows: AtomicU64::new(10),
        history_color_names: std::sync::atomic::AtomicBool::new(true),
        ladder_live: Mutex::new(None),
        ladder_busy: std::sync::atomic::AtomicBool::new(false),
        ladder_cancel: std::sync::atomic::AtomicBool::new(false),
        preview_cache: Mutex::new(Vec::new()),
        preview_busy: std::sync::atomic::AtomicBool::new(false),
        media_chip_color: std::sync::atomic::AtomicBool::new(true),
        shape_chip_color: std::sync::atomic::AtomicBool::new(true),
        rename_junk: std::sync::atomic::AtomicBool::new(true),
        // Default OFF, where SABnzbd's equivalent is on. Skipping is
        // irreversible within the job - the bytes are gone from the
        // wire, and a wrong call cannot be undone by a later pass -
        // while `rename_junk` (on by default) already removes real
        // samples once the download is done. The default therefore
        // costs a teaser's worth of bandwidth and nothing else; turning
        // it on trades that for the risk a name always carries.
        skip_samples: std::sync::atomic::AtomicBool::new(false),
        rename_media_only: std::sync::atomic::AtomicBool::new(false),
        rename_from_nzb: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        index_max_age_secs: AtomicU64::new(index_max_age_secs),
        #[cfg(not(feature = "indexer"))]
        index_max_age_secs: AtomicU64::new(0),
        // Retention defaults ON: if a user bothered to set a max-age
        // window they almost always want the DB to hold ~that window,
        // not hoard everything older. Off = ingest-gate-only (the
        // pre-M31 behavior), toggle in Settings (persists across
        // restarts like the other live settings).
        index_retention: seed_index_retention(&settings_path),
        index_pause_on_download: seed_index_pause_on_download(&settings_path),
        index_paused: seed_index_paused(&settings_path),
        enrich_paused: seed_enrich_paused(&settings_path),
        index_enabled: std::sync::atomic::AtomicBool::new(index_enabled),
        // Pre feed: OFF unless the user has explicitly saved it on. A
        // missing key, a null, or a non-bool all land here - there is no
        // path that opens an outbound IRC connection by accident.
        predb_enabled: seed_predb_enabled(&settings_path),
        predb_server: seed_predb_server(&settings_path),
        predb_channels: seed_predb_channels(&settings_path),
        predb_nick: seed_predb_nick(&settings_path),
        #[cfg(feature = "indexer")]
        predb_pending: Mutex::new(Vec::new()),
        predb_status: Mutex::new(String::new()),
        // Correlation: same explicit-opt-in contract as the feed. Both
        // default OFF; a missing key never turns an inference engine on.
        predb_corr_enabled: seed_predb_corr_enabled(&settings_path),
        predb_corr_auto: seed_predb_corr_auto(&settings_path),
        #[cfg(feature = "indexer")]
        predb_max_rows: std::sync::atomic::AtomicU64::new(predb_seed::PREDB_MAX_ROWS_DEFAULT),
        #[cfg(feature = "indexer")]
        predb_seed_days: std::sync::atomic::AtomicU64::new(predb_seed::PREDB_SEED_DAYS_DEFAULT),
        #[cfg(not(feature = "indexer"))]
        predb_seed_days: std::sync::atomic::AtomicU64::new(180),
        #[cfg(feature = "indexer")]
        predb_seed_running: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        predb_seed_status: Mutex::new(String::new()),
        // Parity scoreboard: OFF and sourceless unless the user saved
        // their own reference indexer. No path samples anybody's API by
        // accident, and no key or URL ever ships as a constant.
        scoreboard_enabled: seed_scoreboard_enabled(&settings_path),
        scoreboard_url: seed_scoreboard_url(&settings_path),
        scoreboard_source: seed_scoreboard_source(&settings_path),
        corr_confirm_enabled: seed_corr_confirm_enabled(&settings_path),
        corr_confirm_source: seed_corr_confirm_source(&settings_path),
        scoreboard_cats: seed_scoreboard_cats(&settings_path),
        scoreboard_key: seed_scoreboard_key(&settings_path),
        scoreboard_calibrate: seed_scoreboard_calibrate(&settings_path),
        #[cfg(feature = "indexer")]
        scoreboard_running: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        scoreboard_status: Mutex::new(String::new()),
        // Spots are new, so there is no existing-install case to seed
        // from: nobody has one running today. Straight off until asked.
        spot_enabled: seed_spot_enabled(&settings_path),
        spot_groups: seed_spot_groups(&settings_path),
        spot_backfill: seed_spot_backfill(&settings_path),
        spot_deepen: seed_spot_deepen(&settings_path),
        spot_resolve: seed_spot_resolve(&settings_path),
        #[cfg(feature = "indexer")]
        index_generation: AtomicU64::new(0),
        index_jobs_active: Arc::new(AtomicUsize::new(0)),
        // M34 size cap. UI-only settings (no CLI flags), read straight
        // off settings.json like index_retention above.
        index_max_bytes: seed_index_max_bytes(&settings_path),
        // OFF unless the user has explicitly saved it on. A missing key,
        // a null, or a non-bool all land here - there is no path that
        // turns deletion on by accident.
        index_evict: seed_index_evict(&settings_path),
        #[cfg(feature = "indexer")]
        index_evict_order: seed_index_evict_order(&settings_path),
        #[cfg(feature = "indexer")]
        index_evict_kinds: seed_index_evict_kinds(&settings_path),
        #[cfg(feature = "indexer")]
        index_keep_kinds: seed_index_keep_kinds(&settings_path),
        #[cfg(feature = "indexer")]
        index_evict_scope: seed_index_evict_scope(&settings_path),
        #[cfg(feature = "indexer")]
        index_evict_headroom: seed_index_evict_headroom(&settings_path),
        #[cfg(feature = "indexer")]
        compact_pending: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        last_auto_trim: std::sync::Mutex::new(None),
        #[cfg(feature = "indexer")]
        index_ledger: std::sync::Mutex::new(Default::default()),
        #[cfg(feature = "indexer")]
        index_opened: Mutex::new(
            crate::persist::load_json_with_backup(&spool.join("index-opened.json"))
                .and_then(|v| serde_json::from_value::<OpenedLog>(v).ok())
                .unwrap_or_default(),
        ),
        #[cfg(feature = "indexer")]
        index_gates: seed_index_gates(&settings_path, index_gates),
        line_speed: seed_line_speed(&settings_path),
        link_peak: linkpeak::LinkPeak::load(spool.join("linkpeak.json")),
        line_carry: linecarry::LineCarry::load(spool.join("linecarry.json")),
        whyslow: whyslow::WhySlow::default(),
        tune_hint: Mutex::new(String::new()),
        local_link: Mutex::new(None),
        cpu_sample: Mutex::new(None),
        speed_win: Mutex::new(VecDeque::new()),
        usage: Mutex::new(
            crate::persist::load_json_with_backup(&spool.join("usage.json"))
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default(),
        ),
        provquality: provquality::ProvQuality::load(spool.join("provquality.json")),
        run_usage_flushed: Mutex::new(Default::default()),
        block_band: Mutex::new(Default::default()),
        pause_until: Mutex::new(None),
        pause_wake: std::sync::Condvar::new(),
        pause_timer_live: std::sync::atomic::AtomicBool::new(false),
        connections: std::sync::atomic::AtomicUsize::new(connections.max(1)),
        window: std::sync::atomic::AtomicUsize::new(window.max(1)),
        decoders: std::sync::atomic::AtomicUsize::new(decoders.max(1)),
        fast_verify: std::sync::atomic::AtomicBool::new(fast_verify),
        verify_lean: std::sync::atomic::AtomicBool::new(verify_lean),
        min_free: AtomicU64::new(min_free.unwrap_or(MIN_FREE_DEFAULT)),
        queue_hold: std::sync::Mutex::new(None),
        pause_source: std::sync::Mutex::new("user"),
        limit_source: std::sync::Mutex::new("user"),
        auto_retry_secs: seed_auto_retry_secs(&settings_path, auto_retry_mins),
        server_outage_mins: seed_server_outage_mins(&settings_path),
        quota: AtomicU64::new(quota.unwrap_or(0)),
        quota_spent: AtomicU64::new(0),
        quota_reset: AtomicBool::new(false),
        dupe_action: Mutex::new("pause".to_string()),
        dupe_scope: Mutex::new("smart".to_string()),
        cat_meta: Mutex::new(std::collections::HashMap::new()),
        quota_period: std::sync::atomic::AtomicU8::new(match quota_period {
            'm' => b'm',
            'w' => b'w',
            _ => b'd',
        }),
        watch_dir: Mutex::new(watch),
        watch_keep_nzb: AtomicBool::new(false),
        refeed_nzb: AtomicBool::new(false),
        watch_recursive: AtomicBool::new(false),
        watch_move_rejected: AtomicBool::new(false),
        watch_failed: Mutex::new(std::collections::HashMap::new()),
        delete_kept: Mutex::new(std::collections::VecDeque::new()),
        deleted_recent: Mutex::new(std::collections::VecDeque::new()),
        auth_fails: Mutex::new(std::collections::HashMap::new()),
        #[cfg(feature = "indexer")]
        enrich_hot: Mutex::new(std::collections::VecDeque::new()),
        #[cfg(feature = "indexer")]
        group_catalog: Mutex::new(None),
        #[cfg(feature = "indexer")]
        group_fetching: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        group_fetch_err: Mutex::new(None),
        #[cfg(feature = "indexer")]
        group_stats: Mutex::new(Arc::new(crate::groupstats::StatsCache::default())),
        #[cfg(feature = "indexer")]
        group_sampling: Mutex::new(std::collections::HashSet::new()),
        group_desc_isc: std::sync::atomic::AtomicBool::new(group_desc_isc),
        // The CLI/settings value is the raw chain text (§192); the
        // daemon holds it parsed.
        scripts: Mutex::new(nzbget_script::script_chain(
            &script
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
        )),
        script_timeout: AtomicU64::new(3600),
        pre_queue_script: Mutex::new(None),
        pre_queue_timeout: AtomicU64::new(30),
        notify_targets: Mutex::new(Vec::new()),
        notify_health: Mutex::new(Default::default()),
        failure_link: Mutex::new("off".to_string()),
        quality_prefs: seed_quality_prefs(&settings_path),
        apikey: Mutex::new(apikey),
        nzbkey: Mutex::new(nzbkey),
        stream_secret: seed_stream_secret(&settings_path),
        omdb_key: seed_omdb_key(&settings_path),
        tmdb_key: seed_tmdb_key(&settings_path, &config),
        library_recheck_secs: AtomicU64::new(library_recheck_secs.max(1)),
        #[cfg(feature = "indexer")]
        index_groups: Mutex::new(index_groups),
        #[cfg(not(feature = "indexer"))]
        index_groups: Mutex::new(Vec::new()),
        index_interests: Mutex::new(String::new()),
        index_interests_applied: Mutex::new(String::new()),
        index_interest_groups: Mutex::new(Vec::new()),
        #[cfg(feature = "indexer")]
        index_interval_secs: AtomicU64::new(index_interval_secs),
        #[cfg(not(feature = "indexer"))]
        index_interval_secs: AtomicU64::new(900),
        #[cfg(feature = "indexer")]
        index_backfill: AtomicU64::new(index_backfill),
        #[cfg(not(feature = "indexer"))]
        index_backfill: AtomicU64::new(20000),
        scan_now: tokio::sync::Notify::new(),
        #[cfg(feature = "indexer")]
        scan_deep: AtomicU64::new(0),
        #[cfg(feature = "indexer")]
        scan_progress: Mutex::new(Vec::new()),
        index_scan_par: AtomicU64::new(3),
        scan_active: std::sync::atomic::AtomicBool::new(false),
        busy: Default::default(),
        index_tip_secs: AtomicU64::new(20),
        watch_interval_secs: AtomicU64::new(5),
        watch_scan_now: tokio::sync::Notify::new(),
        oracle_sample: AtomicU64::new(300),
        schedule: Mutex::new(Vec::new()),
        schedule_text: Mutex::new(String::new()),
        watchlist: seed_watchlist(&settings_path),
        watch_state: seed_watch_state(&spool),
        watch_now: tokio::sync::Notify::new(),
        lists: seed_lists(&settings_path, &spool),
        arr_giveup_threshold: AtomicU64::new(0),
        arr_instances: Mutex::new(Vec::new()),
        giveup: Arc::new(Mutex::new(Default::default())),
        hunt: Default::default(),
        settings_path: settings_path.clone(),
        #[cfg(feature = "indexer")]
        taste_cache: Mutex::new(None),
        #[cfg(feature = "indexer")]
        owned_keys_cache: Mutex::new(None),
        #[cfg(feature = "indexer")]
        oracle_bb_cache: Mutex::new(None),
    })
}

// Clippy's `items_after_test_module`: a `#[cfg(test)]` module has to be
// the LAST item in its file, and §145.1 landed this one in the middle of
// startup.rs, which turned main's clippy gate red. Moved verbatim rather
// than silenced - every other test module in the tree already sits at the
// end of its file.
#[cfg(test)]
mod bind_grace_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    fn taken() -> BindError {
        Box::new(std::io::Error::from(std::io::ErrorKind::AddrInUse))
    }

    /// The restart case: the port answers "taken" for a few polls and
    /// then frees up. That must be waited out, not reported.
    #[test]
    fn a_port_that_frees_up_shortly_is_waited_out() {
        let calls = AtomicUsize::new(0);
        let started = Instant::now();
        let got = bind_past_a_closing_predecessor("127.0.0.1", 1, || {
            if calls.fetch_add(1, Ordering::Relaxed) < 3 {
                Err(taken())
            } else {
                Ok("bound")
            }
        });
        assert_eq!(got.map_err(|e| e.to_string()), Ok("bound"));
        assert_eq!(calls.load(Ordering::Relaxed), 4);
        assert!(started.elapsed() >= Duration::from_millis(15));
    }

    /// A port a STRANGER holds is still refused - the grace is a wait,
    /// not a surrender - and refused inside its own budget.
    #[test]
    fn a_port_that_stays_taken_is_still_refused() {
        let started = Instant::now();
        let got = bind_past_a_closing_predecessor("127.0.0.1", 1, || Err::<(), _>(taken()));
        assert!(got.is_err());
        assert!(started.elapsed() >= BIND_GRACE);
        assert!(
            started.elapsed() < BIND_GRACE * 4,
            "{:?}",
            started.elapsed()
        );
    }

    /// Only "address already in use" is a teardown lag. Every other bind
    /// failure - a privileged port, a bad address - is the operator's to
    /// see immediately, not after a second of silence.
    #[test]
    fn any_other_bind_failure_is_reported_at_once() {
        let calls = AtomicUsize::new(0);
        let started = Instant::now();
        let got = bind_past_a_closing_predecessor("127.0.0.1", 1, || {
            calls.fetch_add(1, Ordering::Relaxed);
            Err::<(), _>(
                Box::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied)) as BindError,
            )
        });
        assert!(got.is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    /// End to end through tiny_http, because the retry hinges on its
    /// boxed error still being the io::Error the bind produced: if that
    /// ever stops downcasting, every test above keeps passing and the
    /// daemon quietly goes back to dying on a 4%-of-restarts race.
    #[test]
    fn take_listener_outlasts_a_listener_that_is_still_being_dropped() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            drop(held);
        });
        let started = Instant::now();
        let server = take_listener("127.0.0.1", port, None)
            .expect("the port frees up well inside the grace");
        assert!(started.elapsed() >= Duration::from_millis(100));
        drop(server);
    }

    /// The hand-built v6 path answers a v6 client, everywhere. Loopback
    /// on purpose: a `::` bind in a test raises the macOS firewall
    /// dialog, and `::1` exercises the same socket2 construction.
    #[test]
    fn take_listener_v6_serves_a_v6_client() {
        let server = take_listener("::1", 0, None).expect("bind ::1");
        let port = match server.server_addr().to_ip() {
            Some(a) => a.port(),
            None => unreachable!("a TCP bind has an IP address"),
        };
        let conn = std::net::TcpStream::connect(("::1", port));
        assert!(conn.is_ok(), "v6 loopback connect failed: {conn:?}");
    }

    /// Issue #58, and Windows-only twice over: IPV6_V6ONLY defaults ON
    /// there alone, so only there does this assert bite - and only
    /// there does binding `::` not raise the macOS firewall dialog.
    /// windows-unit runs it; without `set_only_v6(false)` the connect
    /// is refused.
    #[cfg(windows)]
    #[test]
    fn a_wildcard_v6_bind_answers_an_ipv4_client() {
        let server = take_listener("::", 0, None).expect("bind ::");
        let port = match server.server_addr().to_ip() {
            Some(a) => a.port(),
            None => unreachable!("a TCP bind has an IP address"),
        };
        let conn = std::net::TcpStream::connect(("127.0.0.1", port));
        assert!(conn.is_ok(), "IPv4 connect to a :: bind failed: {conn:?}");
    }
}
