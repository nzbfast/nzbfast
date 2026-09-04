# Mobile client API contract (playback contract v1, FROZEN)

The endpoint list the native mobile clients use. Rows 1-15 are the P0
surface; rows 16-17 are the frozen v1 additions, and row 18 is the
update notice (Android, 4 Sep 2026). This file
is the single shared contract: the Android Compose app (here) and the
iOS SwiftUI shell both build against it. Rows below marked "iOS" are
used by that client only. Sources are cited as
file:line in crates/nzbfast/src/serve/. Response snapshots recorded
from a live daemon live in `app/src/test/resources/snapshots/` and are
exercised by the JVM unit tests (`app/src/test/`).

## Auth

- API key travels as `X-Api-Key: <key>` header on every call this
  client makes (query `?apikey=` and `Authorization: Bearer` also work
  server-side; precedence query > header > form body, mod.rs:5669).
- `mode=version` answers without a key; a WRONG key is still rejected.
- 403 body: `{"status":false,"error":"API Key Required"|"API Key
  Incorrect", ...}`.
- Never send a `t=` query param to `/api` - that path is claimed by
  the newznab facade (mod.rs:5679).
- Two-tier keys exist: the full apikey and an add-only nzbkey
  (allowlist: addfile, addurl, version, status, fullstatus, get_cats).
  This app uses the full key.

## Endpoints used by the app

| # | call | notes |
|---|------|-------|
| 1 | `GET /api?mode=version` | liveness + first-run probe. Reads `version`. |
| 2 | `GET /api?mode=queue` | reads `queue.paused`, `queue.status`, `queue.kbpersec`, and per slot: `nzo_id`, `filename`, `status`, `percentage`, `mb`, `mbleft`, `timeleft`, `activity`. Slot `status` values seen: Downloading, Queued, Paused, Moving, plus tail-phase words. |
| 3 | `GET /api?mode=history` | reads `history.slots[]`: `nzo_id`, `name`, `status` (Completed/Failed/Queued), `size`, `fail_message`, `completed`. |
| 4 | `POST /api?mode=addfile` | multipart/form-data; file part field `nzbfile` (server takes the first part with a filename, mod.rs:6382); optional form fields `cat`, `nzbname`, `password`, `priority`, `stream=1`. Response `{"status":true,"nzo_ids":[...],"held":[...]}`; with `stream=1` also `m3u` and `stream` URLs. |
| 5 | `GET /api?mode=addnzblnk&link=<nzblnk:?...>` | response like addfile; `{"status":false,"reason":"badlink",...}` on a bad link. |
| 5b | `GET /api?mode=addurl&name=<url>` | iOS (pasted NZB URLs). Same `cat`/`nzbname`/`password`/`priority`/`stream` params and response shapes as addfile (api/queue.rs:976). |
| 6 | `GET /api?mode=queue&name=pause|resume&value=<nzo_id>` | per-job. `{"status":bool}`; resume of a finishing job returns `{"status":false,"error":"this job is still finishing"}`. |
| 7 | `GET /api?mode=queue&name=delete&value=<nzo_id>[&del_files=1]` | value also takes `all` or a csv. |
| 8 | `GET /api?mode=history&name=delete&value=<nzo_id>[&del_files=1]` | value also takes `all|failed|completed`. |
| 9 | `GET /api?mode=pause` / `GET /api?mode=resume` | global. `pause` takes optional `value=<minutes>`. |
| 10 | `GET /api?mode=get_config` | reads only `config.nzbfast.servers_configured` (first-run signal). |
| 11 | `POST /api?mode=server_save` JSON `{"index":-1,"server":{host,port,tls,username,password,connections}}` | first-run news-server save; index -1 appends. `{"status":true,"count":n}`. Defaults: port 563, tls true, connections 8 (mod.rs:3643). |
| 12 | `POST /api?mode=server_test` same body | dry run. `{"status":true,"greeting","latency_ms"}` or `{"status":false,"error","refusal"}`. |
| 13 | `GET /preview/probe/<nzo_id>` | THE playback-readiness signal. `media != null` = playable now; `media == null && pending == true` = keep polling (dashboard polls every 6 s); `media == null && pending == false` = settled no. Also `file`, `size`, `coverage{head_bytes,pct,tail_ok}`, `source`. Auth: key or per-job `?t=`. 404 while nothing is downloadable. |
| 14 | `GET /m3u/<nzo_id>` | body line 2 is `http://<host>/stream/<id>?t=<token>` - the tokenized play URL. The app plays THIS so the long-lived player URL never carries the API key - URLs that reach players and logs hold the scoped per-job token, never the key. |
| 15 | `GET /stream/<nzo_id>` | byte-serving. No file-selection param - the daemon picks the media file (live: largest writer with a media extension; finished: largest media file, or the filed episode for season packs; stream.rs:31,37,56). Ranges: always `Accept-Ranges: bytes`; 206 + `Content-Range` on Range; `Content-Type: video/mp4` for .mp4 else `video/x-matroska`; no chunked encoding. Live jobs: reads block on the write frontier; a Range past the frontier promotes those articles (a real seek). Finished jobs and library force-starts need key or `t` token; live byte-serving is deliberately unauthenticated. 503 past 64 concurrent streams. |

## Playback contract v1 - FROZEN (workstream A2, 2026-08-05)

**Adopted by both shells (B2/C2 first half, 2026-08-05).** Home and
the player in the Compose app and the SwiftUI shell poll row 16 as
their ONE call; rows 2, 3 and the probe cadence of row 13 are no
longer polled (the rows stay frozen - they are still the SAB-compat
surface and the fallback). What adoption pinned down:

- The Play affordance is `playback.ready` on the job row; the per-job
  probe is fired ONCE when the user opens a live job, because the
  probe is what promotes a file index forward (row 13) and
  `mode=playback` never does.
- The play URL is the row's `stream` field; `/m3u` (row 14) is the
  fallback for a row that lacked one.
- The player's buffer/health overlay reads the `stream` telemetry
  from the same poll. The counters are process-wide and cumulative,
  so the overlay anchors at the first sample it sees and shows the
  movement since the player opened. That was enough - a per-job or
  per-reader breakdown would be a contract ADDITION (keys may be
  added) and has deliberately NOT been taken yet.

Everything in this section is frozen for v1: keys keep their name,
their type and their meaning, and the daemon may only ADD keys.
`contract: 1` on the payload says which version answered. The three
calls above that the players use (13, 14, 15) are part of the freeze
too. Server side: `crates/nzbfast/src/serve/api/playback.rs` and
`stream::playback_readiness`; gate test
`playback_contract_answers_readiness_and_scoped_tokens` in
crates/nzbfast/tests/playback_contract/mod.rs.

### 16. `GET /api?mode=playback` - the one compact call

Full API key only (queue contents are never add-only). Optional
`limit` (default 10, max 100) applies to BOTH lists; `category` and
`nzo_ids` filter as they do on queue/history.

```
{ "status": true, "contract": 1,
  "version": "4.5.0", "nzbfast": "1.0.16",
  "paused": false, "pause_int": "0",
  "speed_bps": 0.0, "diskspace_gb": 601.03, "warnings": 0,
  "link_peak": 0.0, "link_peak_src": "",
  "queue_total": 1, "history_total": 0, "queue_idle": false,
  "queue":   [ <job>, ... ],
  "history": [ <job>, ... ],
  "stream": { "readers": 0, "blocked_reads": 0, "zero_filled_bytes": 0,
              "runway_mb": 16, "runway_wait_ms": 3000 } }
```

A `<job>`:

```
{ "nzo_id": "...", "name": "...", "status": "Downloading", "cat": "*",
  "percentage": 31.0, "mb": 2.86, "mbleft": 1.97,
  "timeleft": "0:00:00", "activity": "fetching",
  "fail_message": "",            // history rows
  "bytes": 2994402,              // history rows
  "completed": 1785958761,       // history rows, unix seconds
  "playback": { ... },
  "stream": "http://host/stream/<id>?t=<token>" }
```

Numbers are NUMBERS here (the SAB payloads quote theirs); `status`
words and `activity` tokens are the same ones rows 2 and 3 carry.
`queue_total` / `history_total` count before `limit` cuts the page.

Contract ADDITION (2026-08-26, keys may be added, TODO 281 AN2):
`queue_idle` (bool) - the daemon's own drain latch, `Daemon::note_queue_idle`.

It is NOT the same fact as an empty `queue` list, and the difference is
the reason it exists. A job that has finished downloading is stamped
`Completed` and retained OUT of the queue a hundred lines before its
record is filed into history, so for the whole length of its tail - the
repair, the extract, the move - it is in NEITHER list. The latch accounts
for that backlog (`postproc_backlog`) where the lists cannot, and it is
re-armed by enqueue.

The caller is the Android foreground service, which STOPS THE ENGINE on
it: the alternative reading tears a job down mid-repair. A client that
predates the addition sees no key, and absent must read FALSE - "I cannot
tell" and "there is nothing left to do" cannot be the same answer when
the consequence of the second is killing the process. The Compose app
parses it that way and the four `playback_*.json` fixtures, all
pre-addition recordings, are what test it
(`playbackWithoutQueueIdleIsNotIdle`).

Contract ADDITION (2026-08-06, keys may be added): `link_peak` (bps)
and `link_peak_src` ("measured" | "line" | "") - the link's learned
peak, same values the dashboard's queue poll carries. Clients anchor
their throughput chart's 100% to it (dashed rule); `link_peak` 0 or
absent means no anchor is known and the chart scales to its window.
A blip above the peak may draw past the rule without rescaling.

`playback` is per-file readiness - the file `/stream/<id>` would
actually serve, decided by the same two pickers that serve it:

```
{ "ready": true, "reason": "disk", "file": "job 720p.mkv",
  "size": 900579, "source": "disk", "seekable": true,
  "coverage": { "head_bytes": 900579, "pct": 100.0, "tail_ok": true } }
```

`reason` is a closed token set - branch on it, never on prose:

| reason | ready | meaning |
|---|---|---|
| `live` | yes | playing now, still downloading (container parsed) |
| `disk` | yes | finished; the file is on disk |
| `pending` | no | downloading, not enough of the container yet - poll |
| `not_started` | no | queued, paused or held |
| `not_fetched` | no | library entry; playing it STARTS the download |
| `moving` | no | finished; the payload is in flight to its final folder - wait, do not write it off |
| `no_media` | no | finished, no playable file on disk any more |
| `failed` | no | the job failed |
| `unknown` | no | no such nzo_id |

Contract ADDITION (2026-08-23, values may be added to `reason`):
`moving`. The mover copies a finished payload to its final folder and
rewrites the job's `out_dir` LAST, so for the whole duration of a move
(unbounded, on a NAS) the record names the folder the bytes are
leaving; a recategorize and a retry redrive relocate one the same way.
That window used to read `no_media`, which tells a client the file is
gone when it is whole and about to be readable again. `ready` stays
false for it - `/stream/<id>` answers 503 + `Retry-After` in the same
window - so a client that branches on `ready` is already right; one
that branches on the token should say "moving, back shortly" and keep
polling where it would have dropped the row.

`seekable` is `ready && coverage.tail_ok`: the index at the end of the
file has arrived, so scrubbing will work. `coverage` is null when
there is nothing to cover yet.

This call is READ-ONLY by design: unlike `/preview/probe/<id>` it
never promotes articles to pull a file index forward. A client that
wants that (and the full track/codec/language detail) still calls the
probe for the ONE job a user opened.

`stream` telemetry is cumulative since daemon start - difference two
polls for a rate. `blocked_reads` counts reads that had to wait for
their span (server-side buffering); `zero_filled_bytes` is picture
served as zeros because the articles under it were terminally missing
(see research/STREAM-HARDENING-2026-08.md for both mechanisms and for
what `runway_mb` / `runway_wait_ms` shape).

### 17. `GET /api?mode=stream_token&value=<nzo_id>`

The scoped secret for a URL handed OUTSIDE the app - an external
player, a share sheet, a `.strm` pointer.

```
{ "status": true, "nzo_id": "...", "token": "examplet...",
  "stream": "http://host/stream/<id>?t=<token>", "expires": null }
```

`{"status":false,"error":"unknown nzo_id"}` for an id the daemon does
not have. The token is derived from the install secret and the job id:
it starts and serves THAT job and nothing else, and it does not
expire (a `.strm` in a Jellyfin library may first be played months
later) - scope is what makes it safe, not lifetime. **The API key must
never appear in a URL handed to a player, a log or a file.** Row 16's
`stream` field carries the same token, so a client polling `playback`
does not need this call at all.

## B2/C2 second half - adoption notes (2026-08-06)

Both shells, in step:

- **Seek discipline**: while a live job answers `playback.seekable:
  false`, scrubbing and skip are disabled (Android: the fast-forward/
  rewind buttons hide and the time bar refuses touch via a disabled
  `DefaultTimeBar`; iOS: slider and skip buttons disable and dim).
  `source: "history"` rows and ready tails seek freely. The gate is
  the CONTRACT field, not player state - the player cannot know the
  tail is a hole before it stalls in it.
- **PiP (Android)**: leaving the app while the player is up enters a
  PiP window (`onUserLeaveHint`); in PiP every overlay and the
  controller hide (the OS draws its own). Activity declares
  `supportsPictureInPicture`.
- **PiP/AirPlay (iOS): deliberately NOT built this phase.** VLCKit's
  drawable is a plain UIView - real PiP needs an
  AVSampleBufferDisplayLayer/AVPlayerLayer pipeline, which arrives
  with the A4 remux track (AVPlayer for remuxed files, VLCKit
  fallback). Building a fake PiP over VLCKit now would be thrown away
  then. Same for video AirPlay.
- **Share intake**: Android already had SEND/VIEW filters (.nzb +
  nzblnk). iOS now declares the `.nzb` document type
  (`com.nzbfast.nzb`, conforms to `public.xml`) so "Open in nzbfast"
  appears on share sheets; a shared file routes through the same
  `addFile` upload the document picker uses, then lands on Home.
- **Keep-screen-on** was already in both players (B2's list carried
  it); pause-on-metered stays open - it is on-device-engine work
  (connectivity callbacks driving the local daemon), not a player
  change.

## Row 18 (`mode=update_check`) - the update notice (2026-09-04)

| # | call | notes |
|---|------|-------|
| 18 | `GET /api?mode=update_check` | `{"status":true,"current":"<the daemon's version>","available":"<newer version>"|null,"manifest":{...}|null}`. `available` is null when the daemon is already on the newest published release; `{"status":false,"error":"..."}` when the check did not answer - an unreachable channel, or a manifest the daemon REFUSED (bad signature, failed anti-rollback ratchet). Both of those are read as "ask again soon", never as up to date. api/system.rs:1284. |

NOTIFY ONLY on both sides. The daemon has had no apply path since
self-update was removed in 1.0.5, and the app has none either: Android
cannot replace its own package without REQUEST_INSTALL_PACKAGES, which
this app does not hold and will not ask for. The notice is a card with a
link to https://github.com/nzbfast/nzbfast/releases.

Called at most once a day, when the app comes to the foreground. It is
the one call in this client that makes the daemon reach out to the
internet, and the answer changes a few times a year, so it is
deliberately not on the poll.

The app compares `available` against ITS OWN version as well, because
`available` is the daemon's comparison against the daemon: in on-device
mode those are the same number (the APK's versionName is read out of
crates/nzbfast/Cargo.toml at build time, and the bundled engine is built
from it), but in server mode a daemon older than the app would otherwise
tell a current app it is out of date. The mirror image is a known and
accepted gap: a stale APK pointed at an up-to-date daemon gets
`available: null` and learns nothing, and closing it would need a new
daemon field rather than a client change.

## Row 3 (`mode=history`) is still read, for one field

The Compose app polls row 16 and nothing else, with ONE exception since
TODO 281 AN3: the on-device export needs `storage`, the finished
payload's directory on disk, and row 16 deliberately does not carry a
path. It is a readiness call, and a phone has no use for a server's
filesystem - except in on-device mode, where that filesystem is the
phone's own. So the export path, and only the export path, fetches
`mode=history` when it has something to copy. Export is on-device only
for the same reason: a remote daemon's `storage` names a directory on
that machine.

## Not used yet (candidates for the next phase)

- `mode=stats` `files[]` (active job only) - per-file list for a job
  detail screen.
- `mode=get_cats` for a category picker (only if categories exist
  server-side).
- `mode=status` - SAB's compact poll. Superseded for these clients by
  `mode=playback` (row 16); still what push extensions probe.

## Recording the snapshots

```sh
ffmpeg -f lavfi -i testsrc=size=1280x720:rate=24:duration=20 \
  -f lavfi -i sine=frequency=440:duration=20 -c:v libx264 \
  -preset ultrafast -pix_fmt yuv420p -c:a aac movie.mkv
nzbfast chaos-serve --profile clean --port 8899 --media movie.mkv \
  --nzb job.nzb --size 2MB --files 1 --line 2MB
NZBFAST_NO_ENRICH=1 nzbfast --config config.json serve \
  --bind 127.0.0.1 --port 8877 --apikey snapkey --out ./complete
curl -F "nzbfile=@job.nzb" \
  "http://127.0.0.1:8877/api?mode=addfile&apikey=snapkey&output=json"
```

then curl each endpoint above into `app/src/test/resources/snapshots/`
(strip the host/port and the key from anything recorded). The iOS
shell has no test target yet; it reads the same fields, and this file
is the sync point between the two.

`playback_live_partial.json` needs a file too big to land whole, so a
client test can tell `ready` from `seekable` (the small-file recipe
above finishes before the poll can catch partial coverage - its `live`
snapshot shows pct 100 with tail_ok true):

```sh
ffmpeg -f lavfi -i "testsrc2=size=1280x720:rate=30" \
  -f lavfi -i "sine=frequency=440:sample_rate=48000" -t 60 \
  -c:v libx264 -preset veryfast -b:v 6M -pix_fmt yuv420p \
  -c:a aac -b:a 128k -shortest movie.mkv          # ~46 MB
nzbfast chaos-serve --profile clean --port 8899 --files 0 \
  --media movie.mkv --nzb job.nzb --line 800K
```

then poll `mode=playback` once a second while the job downloads and
keep a sample where `reason` is `live`, `tail_ok` is false and
`coverage.pct` is well under 100 (the committed one has pct 33.8 at
48% downloaded).

### The queue and history snapshots

`queue_downloading.json`, `queue_empty.json` and `history_completed.json`
come from a bigger corpus than the playback recipe above, because they
have to hold a slot open long enough to catch it mid-download. The
committed three were re-recorded on 25 Aug 2026 against a 1.2.3 daemon
with this rig, which reproduces the file byte for byte (93,018,817 bytes)
and therefore reproduces every figure the tests assert:

```sh
ffmpeg -f lavfi -i "testsrc2=size=1280x720:rate=30" \
  -f lavfi -i "sine=frequency=440:sample_rate=48000" -t 180 \
  -c:v libx264 -preset veryfast -b:v 4M -pix_fmt yuv420p \
  -c:a aac -b:a 128k -shortest \
  Chaos.Test.Pattern.2026.720p.WEB.x264-BENCH.mkv
nzbfast chaos-serve --profile clean --bind 127.0.0.1 --port 8899 \
  --files 0 --media Chaos.Test.Pattern.2026.720p.WEB.x264-BENCH.mkv \
  --nzb chaos-video.nzb --line 2M
NZBFAST_NO_ENRICH=1 nzbfast --config config.json serve \
  --bind 127.0.0.1 --port 8877 --apikey snapkey --out /tmp/snap/out
```

Record `mode=queue` once BEFORE the add for `queue_empty.json`, then add
`chaos-video.nzb` and poll `mode=queue` about four times a second: keep
the sample reading `percentage: "7"` with `mbleft: "84.25"`, which is
what `ParseSnapshotTest.queueDownloading` asserts. `mode=history` after
the job settles is `history_completed.json`. Give the daemon an `--out`
under a neutral path: the history row carries `path` and `storage` in
full, and a home directory or a worktree name would ship to the public
repo with the fixture.

### Drift audit, 25 Aug 2026

Every snapshot in the directory was compared, key by key and type by
type, against a fresh recording from a 1.2.3 daemon. A snapshot is
WRONG when the payload has retired a key it shows or changed a type it
shows; a snapshot that is merely missing keys ADDED since it was taken
is still a valid capture of a conforming payload, because the freeze
rule above lets the daemon add keys and a client must ignore what it
does not read.

Three were wrong and were re-recorded. `queue_downloading.json` and
`queue_empty.json` still carried `watch_picked`, `watch_upgraded`,
`giveup_tripped` and `auto_retried`, four seen-sets TODO 129 1b(b) moved
off `mode=queue` and onto the sequence-cursored event ring; both also had
`speedlimit_abs` as a number where the payload sends a string.
`history_completed.json` had `retry` as a number where the payload sends
a boolean.

`delete_kept` and `watch_failed` are still on the payload and are NOT
drift. The rule that separates them is worth keeping in mind before
adding anything to this call: a MOMENT (a watch folder picked something
up, a give-up tripped) belongs on the event ring, and a STATE that
describes something still on disk stays on the queue payload.

The event ring is NOT on `mode=queue`. It rides `mode=dashboard`, as
`events`, `events_seq` and `events_reset`, alongside a `queue` object of
the same shape row 2 answers with. That is why a faithful `mode=queue`
capture carries none of the three, and why neither client sees those
four cues today: no client polls `mode=dashboard`. Whether a phone
should consume the ring at all (the cues the dashboard turns into
toasts) is an open product question, not a gap in this file.

The rest were additive only and were left as recorded. `probe_live.json`
and `probe_disk.json` are two `codec_rfc6381` fields behind;
`get_config.json` is 69 keys behind, of which the app reads none.
`version.json`, `auth_wrong_key.json`, `addfile.json`,
`addnzblnk_bad.json`, `pause_all.json`, `resume_all.json`,
`job_pause_missing.json`, `stream_token.json`,
`stream_token_unknown.json` and `m3u.txt` answer with the same keys and
the same types a 1.2.3 daemon does. The only difference in any of them
is the `nzbfast` build string a 1.0.16 daemon stamped on `version.json`
and `auth_wrong_key.json`, which no client reads and which would be
stale again by the next release whatever it said.

**Do not re-record the four `playback_*.json`.** Their only gap is
`link_peak` and `link_peak_src`, and that gap is the subject of a test:
`playbackWithoutLinkPeakMeansNoAnchor` proves a pre-addition daemon's
answer still parses to no anchor, and `playbackLinkPeakParses` covers
the present case by splicing the two keys in. Re-recording deletes the
absent case and leaves the client untested against the daemons that
answer without it.
