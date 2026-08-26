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
 * config_dir: writable directory (UTF-8); config, settings, spool and
 *             downloads live under it.
 * port:       TCP port to serve on (bound to 127.0.0.1 only).
 * apikey:     API key to require, or NULL for an open loopback API.
 * Returns 0 = started (asynchronously - poll the port for readiness),
 * -1 = already running, -2 = bad arguments.
 */
int32_t nzbfast_start(const char *config_dir, uint16_t port, const char *apikey);

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
