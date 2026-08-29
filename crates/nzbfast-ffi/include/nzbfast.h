/* C ABI for the embedded nzbfast engine (libnzbfast_ffi.a).
 *
 * The engine runs inside the host process and serves the nzbfast API and
 * web dashboard on 127.0.0.1:<port>. Hand-written on purpose - three
 * functions do not earn a cbindgen step; keep in sync with src/lib.rs.
 */
#ifndef NZBFAST_H
#define NZBFAST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Start the engine on a background thread.
 * config_dir: writable directory (UTF-8); config, settings, the runtime
 *             record and the spool live under it.
 * out_dir:    where finished downloads land, or NULL for
 *             <config_dir>/downloads. They are separate arguments
 *             because iOS makes them separate: UIFileSharingEnabled
 *             exposes only Documents, so the payload has to be under it
 *             while the engine's own state must not be. See the
 *             nzbfast_start doc comment in src/lib.rs.
 * port:       TCP port to serve on (bound to 127.0.0.1 only). Pass 0 to
 *             let the OS pick and read the answer back out of
 *             <config_dir>/runtime.json.
 * apikey:     API key to require, or NULL for an open loopback API.
 * mem_limit_bytes:
 *             the engine's memory budget, or 0 for its own default of a
 *             quarter of physical RAM. THAT DEFAULT IS A DESKTOP FIGURE
 *             and a phone must not take it: on a 12 GB handset it is a
 *             3 GB budget for a process the platform is willing to kill
 *             for being large. It is an argument rather than an
 *             environment variable because it is a fact about the HOST
 *             PLATFORM, like out_dir and port, and one an embedder must
 *             not be able to forget silently - see the nzbfast_start doc
 *             comment in src/lib.rs. Clamped to the engine's 64 MB
 *             floor, never rejected; a saved mem_limit in settings.json
 *             still overrides it.
 * Returns 0 = started (asynchronously - poll the port for readiness),
 * -1 = already running, -2 = bad arguments, -3 = no configuration in
 * config_dir.
 *
 * -3 means config_dir holds neither config.local.json nor a sabnzbd.ini
 * you put there. It is refused rather than defaulted because the engine's
 * config loader answers a missing file by finding a SABnzbd install's ini
 * through $HOME - correct on a desktop, and on an embedded host it means
 * the app downloads through whatever server list the BOX has. Seed the
 * file before starting; {"servers":[]} is a valid empty one and is what
 * the shipped iOS app writes. See the nzbfast_start doc comment in
 * src/lib.rs.
 */
int32_t nzbfast_start(const char *config_dir, const char *out_dir,
                      uint16_t port, const char *apikey,
                      uint64_t mem_limit_bytes);

/* Stop the engine and release the port. Blocks until the engine thread
 * has finished, or for at most 12 seconds - whichever comes first.
 * Returns 0 = stopped, -1 = not running, -2 = still stopping.
 *
 * -2 is a STATE, not a failure to act on: the stop request is permanent
 * and the engine is still winding up. While that lasts nzbfast_is_up()
 * keeps answering 1 (poll it to learn when the old engine has gone) and
 * nzbfast_start() refuses with -1, so a second engine can never come up
 * underneath a live one. Calling nzbfast_stop() again is safe and is
 * how you wait longer; it answers 0 once the thread is really gone.
 * Nothing you can call will deadlock on a wedged engine. See the
 * `STOP_WAIT` note in src/lib.rs for where 12 seconds comes from. */
int32_t nzbfast_stop(void);

/* 1 while the engine thread is alive; readiness is the HTTP port. Also
 * 1 during the window after a nzbfast_stop() that answered -2. Takes
 * the same lock as start/stop, so a stop in flight delays it by at most
 * the stop bound above. */
int32_t nzbfast_is_up(void);

#ifdef __cplusplus
}
#endif

#endif /* NZBFAST_H */
