# Environment variables

Every `NZBFAST_*` variable read by the code in `crates/*/src`, grouped
Supported first. "Supported" means an operator may reasonably set it;
"Debug-only" covers rollout kill-switches, bench/tuning knobs, and test
harness plumbing - they can vanish or change meaning between releases.

Strings like `__NZBFAST_INDEX__`, `__NZBFAST_INDEXERS__`,
`__NZBFAST_SPOTS__`, `__NZBFAST_LOCALE__`, and `__NZBFAST_UI_TOKENS__`
also appear in the source but are HTML placeholder tokens substituted
into the embedded dashboard pages, not environment variables.

## Supported

| Name | Purpose | Default | Class |
|---|---|---|---|
| `NZBFAST_CONFIG` | Config file path, same as `--config`; makes every subcommand and the daemon agree on one file (the container image sets `/config/config.json`) | `config.local.json` in the cwd | Supported |
| `NZBFAST_STORAGE` | Force storage-type detection for the output path: `rotational`, `ssd`, or `auto` | `auto` (detect) | Supported |
| `NZBFAST_READ_TIMEOUT_SECS` | Read-stall timeout for pooled NNTP connections, in seconds. On the non-adaptive path it is the flat whole-response timeout. With adaptive timeouts on (the default), setting this ABOVE 10 also lifts the adaptive pre-first-byte ceiling to the same value (lift-only, never below the 2-10 s window) - the accommodation for providers with slow cold-storage lookups. Set `NZBFAST_ADAPTIVE_TIMEOUT=0` to return to the flat timeout entirely | 30 | Supported |
| `NZBFAST_ADAPTIVE_TIMEOUT` | Per-knob override of the "Adaptive connection timeouts" setting (a two-phase bound: a pre-first-byte budget adapting to each server's measured response latency, so dead connections are detected in 2-10 s, plus an 8 s no-progress deadline once bytes flow; a slow but alive transfer is never cut for exceeding a flat cap): `1` on, anything else off. Unset, the setting decides (default on) | follows setting | Supported |
| `NZBFAST_DESYNC_FENCE` | `0` disables the §129 3g alignment fence: a DATE pipelined behind every BODY sent to a provider whose 430/423 refusals carry no message-id, so a response dropped upstream is caught at the next read instead of silently charging its refusal to the article behind it. It costs one six-byte command and one short answer per article against such providers, and no round trips. The escape hatch is for a provider whose answers cannot be relied on at all - the pool already retires fencing on its own for a provider that never answers DATE | unset (fence on) | Supported |
| `NZBFAST_CHASE_VERIFY_GATE` | `1` gates the archive chase decode on the PAR2 verified-block watermark: the decode consumes only vouched bytes, so a mid-download repair can never rewrite already-decoded data and the job survives where it used to demote to the disk pass. Experimental while it soaks | off | Experimental |
| `NZBFAST_STALL_ABORT_SECS` | Download stall watchdog: abort when decoded bytes AND outstanding articles are both frozen this long | 180 | Supported |
| `NZBFAST_TAIL_FANOUT` | Per-knob override of the "Race slow articles" setting: `1` arms the endgame tail fan-out only, `2` also arms it from the moment the queue runs dry, anything else disarms it. Unset, the setting decides (default on, early) | follows setting | Supported |
| `NZBFAST_HEDGE` | Per-knob override of the setting's adaptive straggler hedge (dup race staleness bound 3x the trained article time instead of a flat 8 s): `1` on, anything else off. Unset, the setting decides | follows setting | Supported |
| `NZBFAST_RECYCLE_SLOPE` | Per-knob override of the setting's slow-session recycle (a connection under 25% of its server's per-worker rate after 10 s redials): `1` on, anything else off. Unset, the setting decides | follows setting | Supported |
| `NZBFAST_TTFB_HEDGE` | `1` dup-races an in-flight article once its read has sat ~1 s (or 2x the server's measured response latency, whichever is larger) in pre-byte silence, instead of waiting out the full adaptive pre-byte budget - first answer wins, the waiting read is never killed, and the hedge issue-rate cap bounds the spend. Rides the adaptive read path, so it is inert with adaptive timeouts off. TODO 115: the deadair matrix residual (26 s at the old 2 s floor, 30.5 s at today's 4 s one, vs the ~22 s clean floor) is the budget's floor paid per stall | off | Experimental |
| `NZBFAST_RECYCLE_SLOW` | `1` also redials a connection whose articles lose two duplicate races in a row (reactive variant; largely subsumed by the slope recycle) | off | Experimental |
| `NZBFAST_STEER_DEPTH` | `1` arms M7b.2 depth steering: a server whose windowed (~10 s half-life) per-connection rate falls under 1/4 of the best other live server's tops its pipelines up to depth 1 instead of the configured window, restoring above 1/2 (hysteresis). The server keeps every connection fetching unique work - this bounds how many articles sit parked behind each slow session, which is what turns into the job tail at queue-dry. Composes with stream mode (min of the two caps); a lone server, or a fleet with untrained rates, is never clamped | off | Experimental |
| `NZBFAST_STEER_ARM` | Depth-steering arm threshold as a fraction of the best other live server's per-conn rate (0 < x < 1). An engineering guess pending the steering rig's threshold curve - tune here, then the measured value gets hard-coded | 0.25 | Experimental |
| `NZBFAST_STEER_DISARM` | Depth-steering disarm threshold (hysteresis upper bound, 0 < x <= 1) | 0.5 | Experimental |
| `NZBFAST_STEER_WINDOW` | Pipeline depth a clamped server tops up to. 1 is the design value (the stream-mode precedent runs the whole fleet at 1); other values exist for the rig's depth curve only | 1 | Experimental |
| `NZBFAST_RACE_ENVELOPE` | `1` arms M7b.2 envelope racing: the straggler hedge judges each article by its OWNER's article-time EWMA instead of the fleet's (which a shaped provider's own slow completions drag up until nothing looks stale), an idle connection may duplicate an in-flight article whose owner is under 1/4 of the fleet-best per-conn rate once it has cost more than 3x a fast server's article time, and the whole-run 2x slow-owner rule retires. Duplicate spend is bounded by the hygiene cap below; the endgame verdict ladder is exempt from it (a Missing verdict is not speed) | off | Experimental |
| `NZBFAST_DUP_CAP_MB` | Hygiene-cap floor in MB: racing stops arming speculative duplicates once the bytes of LOSING copies reach max(this, the percentage below of delivered bytes). Sized so the excess stays unremarkable in a provider's own volume panel | 32 | Experimental |
| `NZBFAST_DUP_CAP_PCT` | Hygiene-cap percentage of delivered bytes (see above) | 2 | Experimental |
| `NZBFAST_RACE_AGE_MULT` | Envelope-race age bound as a multiple of the fleet-fastest article time (clamped to the hedge family's 500 ms floor / 8 s ceiling). The rig showed this bound and depth steering overlap - a depth-clamped article's single-article serve time sits near the default bound - so the real-line session sweeps it before any default flip | 3 | Experimental |
| `NZBFAST_HOT_SPARE` | `1` parks one authenticated spare connection per server for instant reconnects. Needs cap-aware gating before it can default: at an exact provider connection cap the spare steals a worker slot | off | Experimental |
| `NZBFAST_FLAP_CAP_KEEPERS` | Makes the flap breaker cap-aware: a flap-clamped server whose accept cap was observed (dials bounced off a capacity refusal while sessions were held) keeps min(observed cap, configured connections) keeper connections instead of one, so a provider willing to serve two sessions is not clamped to half of that. Keepers redial only when their own session dies and pace off any capacity bounce, so total dials stay in the single-keeper's order. `1` forces on, `0` forces off | on | Supported |
| `NZBFAST_BACKOFF_IMMEDIATE` | Immediate-first-retry session backoff: the first failed session on a server retries instantly and the geometric ladder (2 s, 4 s, 8 s... capped 30 s) starts from the second failure, so a transient blip (a long-serving connection that just died) recovers without waiting while a persistently refusing server still meets the full ladder - its total extra cost is one dial per worker per failure episode. `0` restores the old always-wait ladder | on | Supported |
| `NZBFAST_TTFB_FLOOR_MS` | Floor of the adaptive pre-first-byte budget, in ms. The budget is 4x the server's measured latency clamped to [floor, ceiling], and providers answering in tens of ms sit pinned at the floor - so this, not `NZBFAST_READ_TIMEOUT_SECS` (the ceiling), is what decides when a pre-byte read gives up. Every expiry costs the whole session, so on a multi-provider fleet a floor that is too tight tears down healthy connections: measured 6 Aug, 23 fleet reconnects at 2000 vs 7 at 4000, all of them our own budget rather than any peer hanging up. **The A/B that gated the default ran 14 Aug 2026 on a 10 GbE box against a six-provider fleet, and moved it 2000 -> 4000.** apollo13 across six providers, ABBA: 22 and 12 fleet reconnects at 2000 against 10 and 7 at 4000, 100% attributed to our own budget at both floors (`peer closed` never appeared), aggregate throughput unchanged at 5.70/6.62 vs 5.65/6.36 Gbps. The dead-air payout survives the wider floor - chaos-rig `deadair` 26.5 s at 2000, 30.5 s at 4000, 34.5 s at 8000, against a 22-23 s clean floor and 59 s with the adaptive path off - because the stalls overlap across the pool instead of serialising, and every leg still found all 12 stalls and hash-gated. Note the older claim that 8000 "fails the dead-air payout" is NOT supported by that measurement; 8000 was not re-raced on the fleet, so it stays unrecommended on the untested side rather than the failed one | 4000 | Experimental |
| `NZBFAST_QUIT_BOUND_MS` | How long a courtesy QUIT waits for the server's goodbye before closing anyway. The QUIT is already sent either way; the wait only avoids closing with the goodbye in flight | 150 | Supported |
| `NZBFAST_KEEPALIVE` | `1` enables short TCP keepalive probing (15 s idle, 5 s interval, 4 misses; plus a 20 s unacked-data bound on Linux) so silently dropped peers are declared dead by the kernel in seconds. Unix only | off | Experimental |
| `NZBFAST_PAR_RACE` | `1` lets a slow finish abandon still-queued articles and complete via PAR2 repair when recovery blocks on hand cover the worst case at 2x margin and the fetch remainder is over 30 s away | off | Experimental |
| `NZBFAST_NO_TAIL_GIVEUP` | Set: disables the §146 tail give-up, which ends a damaged post's zero-throughput verdict tail early - once every remaining article is walking the 430 refusal ladder and recovery blocks on hand cover the exact walker set at 2x margin, the walkers are abandoned and repair starts immediately instead of waiting for unanimous refusals from every backbone | unset (give-up on) | Supported |
| `NZBFAST_CRC_STEER` | CRC retry-elsewhere: a body that fails its yEnc CRC (or decodes to the wrong article - a split-brain server) is refetched from a DIFFERENT server once before the damage is accepted; off, a corrupt article rides to PAR2 repair. Detection is the decode consumer's existing pass, so there is no extra decode; the only cost is keeping the per-article CRC on where PAR2 full-MD5 delegation would have skipped it. Default follows whether an elsewhere exists: on with a same-level peer on a different host/backbone, off otherwise (single server pays nothing). `1` forces on, `0` forces off. `NZBFAST_CRC_RETRY` is honored as an alias (the pre-graduation name) | on when an elsewhere exists | Supported |
| `NZBFAST_TAIL_PREFETCH` | `1` lets the active job's network tail start the next queued job early on the bounded borrow fleet (1-2 connections per healthy host) | off | Experimental |
| `NZBFAST_LIVE_TUNE` | `1` arms the live connection tuner (TODO 112): a per-server epoch controller that tracks the knee during real downloads by moving the number of connections IN USE - perturb by one, keep what measured better, heavy hysteresis. The configured per-server `connections` stays the ceiling and is never written; `pin_connections` exempts a server entirely | off | Experimental |
| `NZBFAST_LIVE_TUNE_EPOCH_SECS` | Epoch length for the live connection tuner, seconds (floor 5; short values are for rigs, not lines - real providers swing 2-3x minute to minute) | 60 | Experimental |
| `NZBFAST_AUTO_RETRY_SECS` | Auto-retry interval for failed jobs, in seconds; overrides the `auto_retry_mins` setting (tests use it to compress the timeline) | `auto_retry_mins * 60` | Supported |
| `NZBFAST_THROTTLE_WRITE_MBPS` | Cap the consumer's write rate (MB/s) to simulate a slow disk; backpressure then closes TCP windows upstream | unset (no throttle) | Supported |
| `NZBFAST_LOG` | Log filter, by level and by `[tag]`: `debug`, or `warn,queue=debug,index=off`. The tag in each log line is the filter key. `RUST_LOG` is honoured too, second | `info` | Supported |
| `NZBFAST_LOG_CAP_MB` | Size cap for the stdout log file before in-place truncation; `0` = uncapped | 50 | Supported |
| `NZBFAST_EXTRA_CA` | Path to a PEM file of extra TLS trust anchors (self-signed news servers, the benchserve rig) | unset | Supported |
| `NZBFAST_KTLS` | `1` moves TLS record crypto into the kernel after the handshake (Linux, builds made with `--features ktls` only). Measured a 40% CPU **regression** on kernel 6.8/x86_64, so it is off by default and only worth trying on a kernel whose AES-GCM is not slower than aws-lc-rs' (x86_64 >= 6.11, or arm64). A kernel that refuses falls back to userspace TLS silently, one log line | unset (userspace TLS) | Experimental |
| `NZBFAST_SHARDS` | Force the number of I/O runtime shards, clamped 1..16 (`1` = single runtime) | auto: 1, or 2..4 on 12+ cores with 24+ connections | Supported |
| `NZBFAST_NNTP_COMPRESS` | `0` disables RFC 8054 COMPRESS DEFLATE on header-scan connections (download connections never compress) | on when the server advertises it | Supported |
| `NZBFAST_PORT_LOCKED` | `1` = the launcher owns the listening port (container mapping, Synology adminport); a dashboard-saved port must not move it | unset | Supported |
| `NZBFAST_OPEN` | `1` runs the daemon deliberately keyless: no API key is minted or required. For installs behind another auth layer | unset (a key is minted on first run and required) | Supported |
| `NZBFAST_CONTAINER` | `1` marks a container runtime that drops neither `/.dockerenv` nor `/run/.containerenv`, so container-specific UI and update guidance apply | unset (marker files detected) | Supported |
| `NZBFAST_ALLOW_EPHEMERAL_CONFIG` | `1` silences the container entrypoint's warning that the config directory is not a mounted volume (settings die with the container). For deliberate throwaway runs | unset (warning prints) | Supported |
| `NZBFAST_BUNDLED` | Internal launcher plumbing: the Mac .app and Windows tray set `1` at spawn to mark a wrapper-owned binary (gates bundled-install behaviour). Not meant to be set by hand | unset | Supported |

## Debug-only

### Kill-switches (rollout escape hatches)

`=1` for the extraction gates; the ones marked "set" trigger on presence
with any value.

| Name | Purpose | Default | Class |
|---|---|---|---|
| `NZBFAST_NO_ENRICH` | Set: disables all metadata-enrichment workers and identity-oracle network calls - the test suite's "do not touch the real internet" switch | unset (enrichment on) | Debug-only |
| `NZBFAST_NO_TRASH` | `1`: force every recoverable delete down the permanent-delete branch, as if `delete_to_trash` were off. On macOS the Trash is scripted through Finder, so a test or tool that deletes a temp file it then removes itself leaves Finder to raise a modal "-43" dialog on the developer's desktop. `tests/scratch` does the same thing in-process for any test holding a scratch dir; this covers the ones that do not | unset (setting decides) | Debug-only |
| `NZBFAST_MOVE_IOPOL` | `throttle` or `utility`: run the copy half of completed-job moves (cross-device staging, the same-filesystem copy fallback) at background disk-I/O priority so a concurrent download's write side keeps the disk. macOS `setiopolicy_np`; Linux idle-class `ioprio_set` (both values map to idle); no-op elsewhere. Dark knob while the default is priced - see research/MOVE-INTERFERENCE-2026-08-05.md | unset (normal priority) | Debug-only |
| `NZBFAST_PREDB_ALLOW_PLAINTEXT` | `1`: let the pre feed connect to the plain IRC port when TLS fails. Off by default because the downgrade is one anybody on the path can force - block 6697, answer on 6667, and inject release names the exact legs match on automatically. Only for a network with no TLS relay | unset (TLS required) | Supported |
| `NZBFAST_SEARCH_LOG_FLUSH_SECS` | Seconds between writes of the §131 D3 search-miss buffer (clamped 1-3600). Recording a search only touches memory, so this is how long a search waits before it reaches the index - shortened by the e2e that pins the logging call sites | unset (60 s) | Debug-only |
| `NZBFAST_NO_NATIVE_REPAIR` | Set: disables the native PAR2 repair path (misnamed/shifted-data adoption included) | unset (native repair on) | Debug-only |
| `NZBFAST_NO_NATIVE_UNRAR` | Set: prefer an external `unrar` over native rars extraction (env twin of the `prefer_external_unrar` setting; also latches the top-level RAR chase off) | unset (native) | Debug-only |
| `NZBFAST_NO_INSTREAM_DECRYPT` | `1`: decrypt encrypted store-mode RAR in a finish pass instead of in-stream during download | unset (in-stream) | Debug-only |
| `NZBFAST_DECRYPT_ENOSPC_ONCE` | Fault injection for the finish decrypt (TODO 100 retry e2e): `pre` fails once per process with a disk-full error before any ciphertext is touched, `post` fails once after every publish landed - the journal state a real unpack-stage ENOSPC leaves behind | unset (no injection) | Debug-only |
| `NZBFAST_POSTPROC_INLINE` | `1`: bisection kill-switch for the §129 post-processing lane - forces lane width 1 AND worker-blocking submission, byte-for-byte the pre-lane scheduling envelope (the download worker waits for each job's tail again) | unset (lane on, width `postproc_jobs`) | Debug-only |
| `NZBFAST_FINISH_DRY_RUN` | `1`: the queue-finished sleep/shutdown action announces itself and stops there, without running the platform command. Lets a test arm a real shutdown and prove the trigger fires only when it should, on a machine that has to stay on | unset (the command runs) | Debug-only |
| `NZBFAST_NO_NESTED_ONEPASS` | `1`: turn off one-pass routing of nested archives | unset (on) | Debug-only |
| `NZBFAST_NO_NESTED_CHASE` | `1`: disable the chasing decompressor for nested compressed RAR (inner archive lands on disk instead) | unset (on) | Debug-only |
| `NZBFAST_NO_NESTED_7Z` | `1`: demote an inner .7z to a disk pass instead of chasing it | unset (on) | Debug-only |
| `NZBFAST_NO_NESTED_ZIP` | `1`: demote an inner zip to a disk pass instead of chasing it | unset (on) | Debug-only |
| `NZBFAST_NO_TOP_7Z` | `1`: disable one-pass extraction of a top-level 7z | unset (on) | Debug-only |
| `NZBFAST_NO_TOP_RAR_CHASE` | `1`: disable the top-level compressed-RAR chase | unset (on) | Debug-only |
| `NZBFAST_NO_TOP_ZIP` | `1`: disable one-pass extraction of a top-level zip (a zip nested inside another archive still streams - use `NZBFAST_NO_NESTED_ONEPASS` for that) | unset (on) | Debug-only |
| `NZBFAST_NO_7Z_TRIM` | `1`: disable drop-behind trimming of already-consumed archive bytes | unset (trim on) | Debug-only |
| `NZBFAST_NO_RAR_TRIM` | `1`: disable drop-behind trimming in the RAR chase - a set over the held-bytes cap demotes to the unrar ladder instead of being released volume by volume | unset (trim on) | Debug-only |
| `NZBFAST_NO_OUTPUT_CRC` | `1`: skip the final-output CRC pass on extracted files | unset (CRC on) | Debug-only |
| `NZBFAST_NO_HOLDS_PAGE` | `1`: restore pre-paging behaviour - held bytes stay in memory instead of paging to scratch under the cap | unset (paging on) | Debug-only |
| `NZBFAST_NO_SPEC_PREFETCH` | Set: CLI runs skip speculative recovery-volume prefetch when an article first goes terminally Missing (daemon runs are gated by `hub.spec_prefetch` instead) | unset (prefetch on for CLI) | Debug-only |

### Tuning and bench knobs

| Name | Purpose | Default | Class |
|---|---|---|---|
| `NZBFAST_FAST_VERIFY` | `0`/`1` overrides the fast-verify setting in either direction (bench A/Bs) | setting; on by default | Debug-only |
| `NZBFAST_WARM_POOL` | `0` forces the warm connection pool off everywhere, regardless of per-server settings | per-server `warm_pool` setting | Debug-only |
| `NZBFAST_NTT` | Overrides "fast par mode" NTT dispatch: `1` on (behind shape gates), `force` skips the shape gates, `0`/`off` disables. Beats the daemon setting | unset (setting decides; on by default) | Debug-only |
| `NZBFAST_NTT_BUDGET` | NTT retention memory budget in bytes | scaled from physical RAM / cgroup limit | Debug-only |
| `NZBFAST_NTT_W` | NTT stripe width in 16-bit words (min 16) | 512 | Debug-only |
| `NZBFAST_NTT_THREADS` | NTT syndrome worker count | available cores, clamped to the stripe count | Debug-only |
| `NZBFAST_STREAM_WINDOW` | Per-connection pipeline depth while a media stream reader is attached | 1 | Debug-only |
| `NZBFAST_STREAM_RUNWAY_MB` | Contiguous data required past a stalled stream position before the response resumes (`0` = resume on first covered chunk) | 16 | Debug-only |
| `NZBFAST_DEFER_WARMUP_SECS` | Warmup before the slow-job defer monitor starts judging (tests compress it) | 45 | Debug-only |
| `NZBFAST_DEFER_WINDOW_SECS` | Measurement window for the slow-job defer decision | 30 | Debug-only |
| `NZBFAST_DEFER_GONE_MIN_MISSES` | Refused articles in one window that make "no server carries this post" a verdict rather than noise. A window with zero bytes and at least this many 430s defers the job to the back of the queue, so a taken-down release stops holding everything behind it; a wedged server answers nothing at all and so can never trip it | 64 | Debug-only |
| `NZBFAST_HEALTH_TICK_SECS` | Interval between §77 post-health probe ticks (tests compress it) | 15 | Debug-only |
| `NZBFAST_HEALTH_RECHECK_SECS` | How long a job must sit queued before its one post-health re-probe | 3600 | Debug-only |
| `NZBFAST_NESTED_MAX_DEPTH` | Overrides the nested-extraction depth cap (test override; beats the daemon setting) | daemon setting, else built-in default | Debug-only |
| `NZBFAST_SCAN_IDLE_SECS` | Indexer header-scan idle deadline before a pass is abandoned | 300 | Debug-only |
| `NZBFAST_INDEX_GATE_WAIT_SECS` | How long the download runner waits for the index pass gate before starting the job anyway with a logged warning (tests compress it) | 60 | Debug-only |
| `NZBFAST_DROP_CACHE` | `1`/`0` force page-cache drop-behind of written data on Linux (benching; the CLI defaults on, the daemon off because a stream reader can attach) | path default | Debug-only |
| `NZBFAST_WRITE_PACE_MB` | macOS write pacing: fsync every N MB of new bytes per output file so dirty pages never pile up into one line-stalling flush burst; `0` off | 32 (macOS) | Debug-only |
| `NZBFAST_WIN_SPARSE` | Windows: mark output files sparse (FSCTL_SET_SPARSE) so NTFS stops zero-filling below valid-data-length on out-of-order writes (~1.6x write amplification without it); `0` off | on (Windows) | Debug-only |
| `NZBFAST_WIN_WRITERS` | Windows: spread positioned writes across N handles per output file (measured no gain on the bench box - see disk.rs) | 1 (Windows) | Debug-only |
| `NZBFAST_NOCACHE` | `1`: set F_NOCACHE on output writers (macOS) so large sequential output bypasses the page cache (line-rate benching) | unset (cached) | Debug-only |
| `NZBFAST_CHANNEL_DEPTH` | Override the fetch->decode channel depth (articles), clamped 8-8192 (line-rate benching) | budget-derived | Debug-only |
| `NZBFAST_TLS_AES256` | Set: force the full TLS cipher list on every host - escape hatch for an untested provider that misbehaves with the trimmed list | unset (per-host list) | Debug-only |
| `NZBFAST_SKIP_PCRC` | `1` skips per-article yEnc CRC checks. Loopback-rig measurement switch ONLY: the CRC is the sole guard on PAR2-less sets | unset (CRC checked) | Debug-only |

### Diagnostics and test-harness plumbing

| Name | Purpose | Default | Class |
|---|---|---|---|
| `NZBFAST_POOL_DEBUG` | Set: dump unresolved queue/in-flight pool state when an idle stall is detected | unset | Debug-only |
| `NZBFAST_REPAIR_TIMING` | Set: print PAR2 repair phase timings | unset | Debug-only |
| `NZBFAST_FOLD_TRACE` | Set: trace the repair streaming-fold pass | unset | Debug-only |
| `NZBFAST_DEBUG_HOOKS` | Set: expose test-only API hooks (e.g. `debug_hold_index` wedges the shared index lock to reproduce daemon starvation) | unset | Debug-only |
| `NZBFAST_TEST_FORBID_UNRAR` | Test canary: set makes any external `unrar` invocation fail loudly, proving encrypted-store jobs completed natively | unset | Debug-only |
| `NZBFAST_TEST_STALL_FINALIZE_MS` | Test hook: sleep this many ms in job finalize to pin the drained-but-still-Downloading window in the queue suite | unset | Debug-only |
| `NZBFAST_TEST_STALL_TAIL_MS` | Test hook: sleep this many ms at the top of the post-network tail (after net-drain, before settle's read-back) so the §129 lane suite can observe the Finishing state deterministically | unset | Debug-only |
| `NZBFAST_SOAK_MINUTES` | Long-run soak (TODO 82, `tests/leak_soak.rs`): how long to keep cycling the mixed queue. The run always does at least warmup+6 cycles, however short this is | 20 | Debug-only |
| `NZBFAST_SOAK_SETTLE_SECS` | Soak: idle wait between a cycle draining and the resource sample. Must stay above the daemon's 60 s idle memory trim plus its 15 s tick, or RSS drift measures allocator retention instead of a leak; values under 80 are rejected | 90 | Debug-only |
| `NZBFAST_SOAK_WARMUP_CYCLES` | Soak: leading cycles excluded from the statistics (startup faulting, pool warm-up, caches reaching working size - RSS was measured flat from cycle 6) | 5 | Debug-only |
| `NZBFAST_SOAK_REPORT` | Soak: where to write the JSON report (verdicts plus every sample - what a new baseline gets re-recorded from) | the run's temp dir | Debug-only |
| `NZBFAST_BETA` | Build-time only: `build.rs` bakes the beta serial from `packaging/beta-serial.txt` in via `cargo:rustc-env`; the API reports it. Never read at runtime | empty (not a beta) | Debug-only |
