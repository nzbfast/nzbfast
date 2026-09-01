//! Test-only Daemon fixture (§106 phase 3). The real `Daemon` is built
//! exactly once, inline in `serve()`, after the listener is bound - but
//! nothing in the struct itself is a socket, so tests can stand one up
//! against a temp directory and reach the ~40 in-memory methods (and
//! every `set_*` settings helper) that were untestable before the split.
//!
//! Mirrors the `serve()` literal with fixed defaults in place of CLI
//! options. Tests must not assert on a default they care about - set the
//! field explicitly first. If a field is added to `Daemon`, this literal
//! fails to compile: add the field here with the same default `serve()`
//! uses.

use super::*;

/// How long a TEST WAIT in this binary tolerates seeing NO PROGRESS at
/// all before it reports a STALL.
///
/// A NO-PROGRESS GAP, deliberately, and never a total. It is a budget
/// for BEATING STARVATION and nothing else - `wait_until`'s rule over
/// in `crates/nzbfast/tests/harness/mod.rs`, which is the shape this
/// binary had no equivalent of: "the deadline only has to beat
/// scheduler starvation, never the thing being waited for". What stays
/// bounded is therefore one STEP, the number of steps being a property
/// of the test rather than of the box.
///
/// THE MEASUREMENT THAT SIZED IT is the mover's, and it is the loudest
/// of the starvation sources rather than the only one: a wait on a
/// daemon-side completion that lands after `save_queue()` queues behind
/// `Daemon::hold_queue_writes`, a PROCESS-GLOBAL mutex every
/// `save_queue` takes and every one of the ~2,770 tests in `cargo test
/// -p nzbfast --bin nzbfast` shares. Instrumented on the 32-core dev
/// Mac, 31 Aug 2026: 143-208 waits over 200 ms per sweep, the longest
/// 978 ms, under CPU load alone. The long form, and which three mover
/// tests it reddened, is at `serve::mover::lane_tests::NO_PROGRESS`,
/// which takes this number from here.
///
/// AND NONE OF THE THREE SITES ADDED ON 31 Aug 2026 IS BEHIND THAT
/// LOCK - measured, not assumed, because reading the code says
/// otherwise and that reading is what the chip for those sites was
/// written on. The redrive settle reads an observable written and
/// released BEFORE the task's `save_queue`, and holding that lock for
/// 5 s on another thread across the redrive left the settle observed at
/// 22 ms; the picker spin waits on `enqueue`, which publishes under the
/// queue lock and saves after releasing it, and whose real cost is its
/// own `write_spool_copy`; and the drain-count settle never builds a
/// `Daemon` at all - it drives `run_capped_sieve` directly, so its
/// exposure is scheduler latency plus two PROCESS-WIDE counters any
/// other test in the binary can perturb. So do NOT read a trip at one
/// of those as evidence about the queue-write lock. Disk and the
/// scheduler are what they share, which is also what the tail below is
/// about.
///
/// WHY IT LIVES HERE rather than at the mover's site. FOUR SITES in
/// three files reference it - `serve::mover::lane_tests`'s own
/// constant, which all nine of that file's waits go through, plus the
/// three added on 31 Aug 2026: `serve::tests_api`'s redrive settle and
/// its drain-count settle, and `serve::daemon::daemon_tests`'s picker
/// spin. And the number has already MOVED ONCE - 30 s to 60 s in
/// `cea15ceed`, hours after it was written, when a merge brought the
/// disk-starvation measurement below. Four sites each spelling their
/// own 60 is a fifth re-measurement that moves one and leaves three,
/// which is the argument CLAUDE.md's fourteenth gate makes about a
/// threshold hand-copied into four sibling drivers.
///
/// AND IT STILL CANNOT COVER A STARVED BOX. Measured 31 Aug 2026 by
/// the lane that wrote up the `terminate-after = 600` ceiling
/// (`37bdf653f`): at load 130-160 with seventeen `cargo-nextest`
/// processes across worktrees, a test that runs in 3.3 s took SEVEN
/// MINUTES - 127x, state `U` at 0.0% CPU. That is disk starvation, not
/// a product hang, and no budget a test can name survives it. So the
/// reading rule is that commit's: above ~load 100 a trip here is a
/// statement about the MACHINE, run `uptime` before believing it, and
/// trust the failure KIND - a wrong ANSWER is real at any load, a
/// no-progress trip under contention is not. Applied to the three
/// sites added on 31 Aug: their own worst readings were 44 ms (the
/// redrive settle) and 126 ms (the picker spin), so that tail puts
/// them at 5.6 s and 16.0 s - which is how it was decided that the
/// picker's old 10 s budget was demonstrably too small and the
/// redrive's, honestly, was not.
///
/// WHAT MUST NOT TAKE IT, because the next person to grep for a
/// `Duration::from_secs` deadline in a test will find these three and
/// they are the opposite construction - the deadline IS the assertion,
/// so raising it deletes the test:
/// `repair::side_fetch_tests`'s 20 s, which is what makes a side pool
/// that never dials a STARVED verdict rather than a 300 s watchdog
/// timeout; `smart::tests::a_hanging_trash_call_does_not_hold_the_caller`'s
/// 5 s, whose subject is `run_bounded` giving up; and
/// `serve::daemon::daemon_tests::index_read_tests`' 10 s, whose subject
/// is `index_read_checked` answering `Saturated` instead of parking.
/// The first is named in the handoff; the other two are not, and both
/// are spelled `elapsed() < Duration` rather than `Instant::now() +
/// Duration`, so the fingerprint that found the first cannot see them.
pub(crate) const NO_PROGRESS: std::time::Duration = std::time::Duration::from_secs(60);

/// A Daemon over a temp directory: `dir/out` as the download root,
/// `dir/spool` as the spool, `dir/settings.json` for settings (created
/// on demand by the seed helpers). No sockets, no spawned tasks, no
/// index database - `index: None`.
pub(crate) fn test_daemon(dir: &Path) -> Arc<Daemon> {
    let out_root = dir.join("out");
    let spool = dir.join("spool");
    let _ = std::fs::create_dir_all(&out_root);
    let _ = std::fs::create_dir_all(&spool);
    let config = dir.join("nzbfast.toml");
    // SEEDED, and it has to be BEFORE the literal below. `Config::load`
    // answers a MISSING file by going and finding a SABnzbd install's ini
    // through `sabnzbd_ini_path`, which searches `$HOME` - so a fixture
    // that leaves this path empty is not testing the daemon, it is
    // testing the machine. This fleet has SABnzbd installed from the
    // competitive benchmarking and a CI runner does not, which is how the
    // same test gave opposite answers on two consecutive days (f63b6a3af,
    // e0f94fc60) and took `linux-tests`, `unit-one-process` and
    // `windows-unit` red on main for ninety minutes.
    //
    // The metered guard on the alternate-spend doors is only the loudest
    // reader. `crates/nzbfast/src/serve` reaches that fallback from
    // thirty-four places - servers, sabcompat, logscrub, report,
    // groupscan, sidecar, tasks, tuner, health, indexer, locallink,
    // settings, daemon and nine api/ handlers - and
    // `seed_tmdb_key(&settings_path, &config)` two dozen lines below is an
    // ARGUMENT of the `Daemon` literal, so it reads this file as the
    // Daemon is built. A write placed after the literal would be a write
    // that construction never sees, which is why `tools/host-config-gate.py`
    // checks the ORDER as well as the write.
    //
    // A test that wants a different server list writes its own over this
    // one - `flat_rate_config` below, or the block-account config
    // `a_block_account_refuses_an_unlimited_hunt` writes.
    let _ = std::fs::write(
        &config,
        r#"{"servers":[{"host":"flat.example","enabled":true}]}"#,
    );
    let settings_path = dir.join("settings.json");
    Arc::new(Daemon {
        hub: Arc::new(crate::StreamHub::default()),
        paused: std::sync::atomic::AtomicBool::new(false),
        early_file_publish: std::sync::atomic::AtomicBool::new(false),
        write_manifest: std::sync::atomic::AtomicBool::new(false),
        boot_at: Instant::now(),
        metrics_open: std::sync::atomic::AtomicBool::new(false),
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
        out_root: std::sync::RwLock::new(out_root),
        move_completed: std::sync::RwLock::new(None),
        move_completed_cats: std::sync::RwLock::new(Vec::new()),
        // TODO 317: opt-in and OFF by default. See `Daemon::write_through`.
        write_through: AtomicBool::new(false),
        write_through_cats: Mutex::new(Vec::new()),
        spool: spool.clone(),
        cfg_path: config.clone(),
        cats: Mutex::new(DEFAULT_CATS.iter().map(|s| s.to_string()).collect()),
        port: 0,
        bind: "127.0.0.1".to_string(),
        launcher_token: String::new(),
        port_locked: false,
        tls_cert: None,
        tls_key: None,
        library_cats: Mutex::new(Vec::new()),
        active_stream: Mutex::new(None),
        #[cfg(feature = "indexer")]
        index_db: spool.join("index.db"),
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
        auto_speed: std::sync::atomic::AtomicBool::new(false),
        preflight: std::sync::atomic::AtomicBool::new(false),
        auto_connections: std::sync::atomic::AtomicBool::new(true),
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
        mem_budget_total: 1 << 30,
        feeds: Mutex::new(Vec::new()),
        feed_health: Mutex::new(Default::default()),
        last_refusals: Mutex::new(Default::default()),
        events: Mutex::new(Default::default()),
        indexers: Mutex::new(Vec::new()),
        watchlist_external: std::sync::atomic::AtomicBool::new(false),
        watchlist_external_set: std::sync::atomic::AtomicBool::new(false),
        indexer_rt: Mutex::new(IndexerRuntime::default()),
        watchlist_instant: AtomicBool::new(true),
        watchlist_instant_max: std::sync::atomic::AtomicU32::new(INSTANT_MAX_DEFAULT),
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
        out_umask: std::sync::atomic::AtomicU32::new(u32::MAX),
        fast_par: AtomicBool::new(FAST_PAR_DEFAULT),
        prefer_external_unrar: AtomicBool::new(false),
        cleanup_exts: Mutex::new(Vec::new()),
        password_file: Mutex::new(dir.join("passwords.txt")),
        password_prompt: Mutex::new("done".to_string()),
        preview: Mutex::new(PREVIEW_DEFAULT.to_string()),
        unpack_eat_volumes: Mutex::new("off".to_string()),
        custom_categories: std::sync::RwLock::new(Vec::new()),
        reclassify_pending: std::sync::atomic::AtomicBool::new(true),
        identity_lookup: std::sync::atomic::AtomicBool::new(true),
        auto_rename: std::sync::atomic::AtomicBool::new(true),
        rename_resolution: std::sync::atomic::AtomicBool::new(true),
        rename_vcodec: std::sync::atomic::AtomicBool::new(false),
        rename_acodec: std::sync::atomic::AtomicBool::new(false),
        rename_source: std::sync::atomic::AtomicBool::new(false),
        rename_group: std::sync::atomic::AtomicBool::new(false),
        rename_year_parens: std::sync::atomic::AtomicBool::new(false),
        rename_quality_brackets: std::sync::atomic::AtomicBool::new(false),
        rename_extra_words: std::sync::atomic::AtomicBool::new(true),
        rename_identify: std::sync::atomic::AtomicBool::new(true),
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
        skip_samples: std::sync::atomic::AtomicBool::new(false),
        rename_media_only: std::sync::atomic::AtomicBool::new(false),
        rename_from_nzb: std::sync::atomic::AtomicBool::new(false),
        index_max_age_secs: AtomicU64::new(0),
        index_retention: seed_index_retention(&settings_path),
        index_pause_on_download: seed_index_pause_on_download(&settings_path),
        index_paused: seed_index_paused(&settings_path),
        enrich_paused: seed_enrich_paused(&settings_path),
        index_enabled: std::sync::atomic::AtomicBool::new(false),
        predb_enabled: seed_predb_enabled(&settings_path),
        predb_server: seed_predb_server(&settings_path),
        predb_channels: seed_predb_channels(&settings_path),
        predb_nick: seed_predb_nick(&settings_path),
        #[cfg(feature = "indexer")]
        predb_pending: Mutex::new(Vec::new()),
        predb_status: Mutex::new(String::new()),
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
        spot_enabled: seed_spot_enabled(&settings_path),
        spot_groups: seed_spot_groups(&settings_path),
        spot_backfill: seed_spot_backfill(&settings_path),
        spot_deepen: seed_spot_deepen(&settings_path),
        spot_resolve: seed_spot_resolve(&settings_path),
        #[cfg(feature = "indexer")]
        index_generation: AtomicU64::new(0),
        index_jobs_active: Arc::new(AtomicUsize::new(0)),
        index_max_bytes: seed_index_max_bytes(&settings_path),
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
        index_opened: Mutex::new(OpenedLog::default()),
        #[cfg(feature = "indexer")]
        index_gates: seed_index_gates(&settings_path, None),
        line_speed: seed_line_speed(&settings_path),
        link_peak: super::linkpeak::LinkPeak::load(spool.join("linkpeak.json")),
        line_carry: super::linecarry::LineCarry::load(spool.join("linecarry.json")),
        whyslow: super::whyslow::WhySlow::default(),
        tune_hint: Mutex::new(String::new()),
        local_link: Mutex::new(None),
        cpu_sample: Mutex::new(None),
        speed_win: Mutex::new(VecDeque::new()),
        usage: Mutex::new(Default::default()),
        provquality: super::provquality::ProvQuality::load(spool.join("provquality.json")),
        run_usage_flushed: Mutex::new(Default::default()),
        block_band: Mutex::new(Default::default()),
        pause_until: Mutex::new(None),
        pause_wake: std::sync::Condvar::new(),
        pause_timer_live: std::sync::atomic::AtomicBool::new(false),
        connections: std::sync::atomic::AtomicUsize::new(20),
        window: std::sync::atomic::AtomicUsize::new(64),
        decoders: std::sync::atomic::AtomicUsize::new(2),
        fast_verify: std::sync::atomic::AtomicBool::new(false),
        verify_lean: std::sync::atomic::AtomicBool::new(false),
        min_free: AtomicU64::new(MIN_FREE_DEFAULT),
        queue_hold: std::sync::Mutex::new(None),
        pause_source: std::sync::Mutex::new("user"),
        limit_source: std::sync::Mutex::new("user"),
        auto_retry_secs: seed_auto_retry_secs(&settings_path, 0),
        server_outage_mins: seed_server_outage_mins(&settings_path),
        quota: AtomicU64::new(0),
        quota_spent: AtomicU64::new(0),
        quota_period: std::sync::atomic::AtomicU8::new(b'd'),
        quota_reset: AtomicBool::new(false),
        dupe_action: Mutex::new("pause".to_string()),
        dupe_scope: Mutex::new("smart".to_string()),
        cat_meta: Mutex::new(std::collections::HashMap::new()),
        watch_dir: Mutex::new(None),
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
        group_desc_isc: std::sync::atomic::AtomicBool::new(false),
        scripts: Mutex::new(Vec::new()),
        script_timeout: AtomicU64::new(3600),
        pre_queue_script: Mutex::new(None),
        pre_queue_timeout: AtomicU64::new(30),
        notify_targets: Mutex::new(Vec::new()),
        notify_health: Mutex::new(Default::default()),
        failure_link: Mutex::new("off".to_string()),
        quality_prefs: seed_quality_prefs(&settings_path),
        apikey: Mutex::new(None),
        nzbkey: Mutex::new(None),
        stream_secret: seed_stream_secret(&settings_path),
        omdb_key: seed_omdb_key(&settings_path),
        tmdb_key: seed_tmdb_key(&settings_path, &config),
        library_recheck_secs: AtomicU64::new(300),
        index_groups: Mutex::new(Vec::new()),
        index_interests: Mutex::new(String::new()),
        index_interests_applied: Mutex::new(String::new()),
        index_interest_groups: Mutex::new(Vec::new()),
        index_interval_secs: AtomicU64::new(900),
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
        watchlist: Mutex::new(Vec::new()),
        watch_state: Mutex::new(Default::default()),
        watch_now: tokio::sync::Notify::new(),
        lists: Default::default(),
        arr_giveup_threshold: AtomicU64::new(0),
        arr_instances: Mutex::new(Vec::new()),
        giveup: Arc::new(Mutex::new(Default::default())),
        hunt: Default::default(),
        settings_path,
        #[cfg(feature = "indexer")]
        taste_cache: Mutex::new(None),
        #[cfg(feature = "indexer")]
        owned_keys_cache: Mutex::new(None),
        #[cfg(feature = "indexer")]
        oracle_bb_cache: Mutex::new(None),
    })
}

/// Pin a FLAT-RATE server config at `d.cfg_path`, so the metered guard
/// on the alternate-spend doors has a real answer to read.
///
/// EVERY test that drives an automatic (`Trigger::Auto`) alternate down
/// `alt_admit` or `hunt_budget` needs this, and a test that skips it is
/// not testing the daemon, it is testing the machine. `Config::load`
/// falls back to a SABnzbd install's ini when its own file is missing
/// (its own doc comment says "every bench box here does" have one), so
/// the guard reads the DEVELOPER'S SABnzbd server list: flat rate,
/// therefore not metered, therefore the spend is admitted. On a CI
/// runner there is no SABnzbd, the load fails, and `hunt_metered`
/// answers TRUE - which is the right way round, an unreadable config
/// must not authorise unlimited automatic spend (Codex F-10) - so the
/// same test says the opposite thing. The failure reads as "CI is
/// broken" and is not.
///
/// It has now happened twice, on two different doors, which is why the
/// helper lives HERE beside `test_daemon` rather than in the test file
/// that first needed it. f63b6a3af pinned four hunt tests on 24 Aug
/// 2026 with a copy private to `hunt_tests.rs`; 486a97584 then put the
/// same ceilings on the SPARE PROMOTION door the next day, and the two
/// tests of that door - one of them in `daemon_tests/spare_tests.rs`,
/// which could not see the private copy - took `linux-tests`,
/// `unit-one-process` and `windows-unit` red on main while every
/// machine on this fleet stayed green.
///
/// Writing the file is what makes the answer the TEST'S, on any host.
/// Do not drop it back to relying on the fallback, and do not "fix" a
/// recurrence by loosening `hunt_metered` - the whole point of that
/// guard is that it fails closed. A test that wants the metered arm
/// writes its own block-account config over this one, which is what
/// `a_block_account_refuses_an_unlimited_hunt` and
/// `unlimited_is_refused_on_a_block_account_only_when_nobody_clicked`
/// do.
///
/// SINCE 26 Aug 2026 `test_daemon` SEEDS THE SAME CONFIG ITSELF, so the
/// class is removed rather than reported: no fixture built there can reach
/// the host's file at all, on any door, and `tools/host-config-gate.py`
/// refuses the seed being taken away again. Calling this helper is now a
/// statement of intent rather than a repair, and it stays at the sites that
/// make one - a test about the metered arm should say which server list it
/// is asserting against. It is still the right thing to call in a fixture
/// that builds its own `cfg_path` outside `test_daemon`.
///
/// THE PROBE, AND HOW FAR IT HAS ACTUALLY BEEN RUN. Point `HOME` at an
/// empty directory and run the COMPILED bin test binary: that is a CI
/// runner's answer, reproduced on this Mac. `cargo test` will not do,
/// because it rebuilds the world against the new `CARGO_HOME`. On
/// 25 Aug 2026 the probe was widened off the bin binary to the whole
/// documented CI sweep, 5,030 tests, and the class came back clean, so
/// the two doors named above are the only fixtures anywhere that were
/// reading the host's server list. That is the measurement behind
/// leaving this a fixture rule rather than a gate; a third door is what
/// would change the answer.
///
/// The three `smart::trash_tests` that also fail under the probe are
/// its own artefact, but NOT for the reason first recorded. Only
/// `the_volume_trash_takes_over_when_finder_will_not` carries
/// `cfg(target_os = "macos")`; the other two compile and run on every
/// target. What excuses all three is the PATH and not a platform gate:
/// on macOS the trash lands in `$HOME/.Trash`, which the probe has just
/// taken away, while on Linux they take another branch and pass, which
/// is what `linux-tests` green on d90f64cb shows. So do NOT read a
/// trash-test failure on a LINUX box as this same artefact - there it
/// is a real defect.
pub(crate) fn flat_rate_config(d: &Daemon) {
    std::fs::write(
        &d.cfg_path,
        r#"{"servers":[{"host":"flat.example","enabled":true}]}"#,
    )
    .expect("config");
}
