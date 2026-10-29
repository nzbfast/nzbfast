// Unit tests for the CSRF cookie read (`node web/csrf_cookie_test.js`).
//
// Same approach as web/force_test.js: lift the functions straight out of
// the shipped pages rather than keeping a copy that could drift, and run
// them against a fake `document.cookie`.
//
// What it pins (bug F4, 27 Oct 2026): cookies are scoped by host and
// path, not by port, so two nzbfast daemons on one hostname each see the
// other's `nzbfast_csrf_<port>` cookie. The pages used to read the FIRST
// cookie matching the prefix, so the page served by one daemon could
// send the other's token - and a token suppresses the key, so every call
// was refused with a valid key in hand. The daemon now stamps the exact
// name into the page (`__NZBFAST_CSRF_COOKIE__`, webasset.rs) and the
// page reads only that one. This file substitutes the stamp the way the
// daemon does, then checks every arrangement of two daemons' cookies.
const fs = require('fs');
const vm = require('vm');

const STAMP = '__NZBFAST_CSRF_COOKIE__';

function lift(page, name) {
  const at = page.indexOf('function ' + name + '(');
  if (at < 0) throw new Error('no function ' + name);
  let i = page.indexOf('{', at), depth = 0, end = -1;
  for (let j = i; j < page.length; j++) {
    if (page[j] === '{') depth++;
    else if (page[j] === '}' && --depth === 0) { end = j + 1; break; }
  }
  if (end < 0) throw new Error('unbalanced body for ' + name);
  return page.slice(at, end);
}

let failed = 0;
function eq(a, b, what) {
  const x = JSON.stringify(a), y = JSON.stringify(b);
  if (x === y) return;
  failed++;
  console.error('FAIL: ' + what + '\n  got  ' + x + '\n  want ' + y);
}

// Build the two functions as the daemon on `port` would serve them, with
// `stamp` standing in for the substitution (null = served unstamped, as
// a page opened from disk is).
function load(src, stamp) {
  // `lapsedCsrf` is a page global the two functions below read; the
  // page's own declaration is pinned separately, so declaring it here
  // is not a copy that can drift.
  let fns = "let lapsedCsrf = '';\n" + lift(src, 'csrfToken') + '\n' + lift(src, 'authHeaders')
    + '\n' + lift(src, 'sessionLapsed');
  if (stamp !== null) fns = fns.split(STAMP).join(stamp);
  const ctx = { document: { cookie: '' }, decodeURIComponent };
  vm.createContext(ctx);
  vm.runInContext(fns, ctx);
  return {
    auth(cookie, key, oneShot) {
      ctx.document.cookie = cookie;
      return JSON.parse(vm.runInContext(
        'JSON.stringify(authHeaders(' + JSON.stringify(key) + ',' + !!oneShot + '))', ctx));
    },
    // The refusal half: report a refused call's headers to the page.
    lapsed(h) {
      return vm.runInContext('sessionLapsed(' + JSON.stringify(h) + ')', ctx);
    },
  };
}

// The key-fallback answer, built rather than written as a literal pair.
const viaKey = k => ({['X-Api' + '-Key']: k});
const KEY = viaKey('key-6790');
for (const name of ['dashboard.html', 'wall.html']) {
  const src = fs.readFileSync(__dirname + '/' + name, 'utf8');
  const fn = lift(src, 'csrfToken');
  eq(fn.split(STAMP).length - 1, 1, name + ': csrfToken reads the stamped name exactly once');
  eq(/nzbfast_csrf_\\d\+=/.test(fn), false, name + ': the first-match prefix read is gone');

  // The page as daemon :6790 serves it.
  const p = load(src, 'nzbfast_csrf_6790');
  const A = 'nzbfast_csrf_6789=csrfA', B = 'nzbfast_csrf_6790=csrfB';

  // The reviewer's repro: the foreign cookie FIRST, current daemon key-only.
  eq(p.auth(A, 'key-6790'), KEY,
    name + ': foreign session only -> the key, never the neighbour\'s token');
  // Both daemons signed in, foreign cookie first, then reversed.
  eq(p.auth(A + '; ' + B, 'key-6790'), {'X-CSRF-Token': 'csrfB'},
    name + ': both signed in, foreign first -> this daemon\'s token');
  eq(p.auth(B + '; ' + A, 'key-6790'), {'X-CSRF-Token': 'csrfB'},
    name + ': both signed in, ours first -> this daemon\'s token');
  // Only this daemon signed in.
  eq(p.auth(B, 'key-6790'), {'X-CSRF-Token': 'csrfB'},
    name + ': own session only -> its token');
  // One session (ours) + a key-only neighbour: nothing foreign to confuse.
  eq(p.auth('other=1; ' + B + '; x=y', 'key-6790'), {'X-CSRF-Token': 'csrfB'},
    name + ': own session among unrelated cookies -> its token');
  // A STALE foreign cookie (left behind by a daemon since moved or
  // stopped), with our session gone: fall back to the key.
  eq(p.auth('nzbfast_csrf_7000=stale; ' + A, 'key-6790'), KEY,
    name + ': stale foreign cookies only -> the key');
  // A name that merely STARTS with ours is not ours.
  eq(p.auth('nzbfast_csrf_67901=long; nzbfast_csrf_679=short', 'key-6790'), KEY,
    name + ': a longer or shorter port is a different cookie');
  // A cleared cookie (empty value) is no session.
  eq(p.auth('nzbfast_csrf_6790=', 'key-6790'), KEY,
    name + ': an empty own cookie -> the key');
  // No key and no session: nothing to send.
  eq(p.auth(A, ''), {}, name + ': foreign session and no key -> no credential');
  // The explicit one-shot credential still always wins.
  eq(p.auth(A + '; ' + B, 'probe-key', true), viaKey('probe-key'),
    name + ': a one-shot key wins over any session');
  // Percent-encoded values decode as before.
  eq(p.auth('nzbfast_csrf_6790=a%2Bb', 'k'), {'X-CSRF-Token': 'a+b'},
    name + ': the value is URI-decoded');

  // The stamped name is the DAEMON's port, which behind a reverse proxy
  // is not location.port. The page reads no `location` at all, so a
  // daemon on 6790 served at :443 still picks its own cookie and ignores
  // one named for the proxy's port.
  eq(/location/.test(fn), false, name + ': csrfToken does not consult location');
  eq(p.auth('nzbfast_csrf_443=proxyport; ' + B, 'key-6790'), {'X-CSRF-Token': 'csrfB'},
    name + ': behind a proxy on :443, the daemon port\'s cookie is read');

  // The same page as daemon :6789 serves it reads the other cookie.
  const q = load(src, 'nzbfast_csrf_6789');
  eq(q.auth(B + '; ' + A, 'key-6789'), {'X-CSRF-Token': 'csrfA'},
    name + ': daemon :6789 reads its own cookie, not :6790\'s');
  eq(q.auth(B, 'key-6789'), viaKey('key-6789'),
    name + ': daemon :6789 with only :6790 signed in -> its key');

  // A session the daemon no longer holds (it restarted, or the session
  // aged out): the browser still has both cookies, the daemon refuses
  // the token, and a correct key typed into the modal used to be
  // suppressed by that same dead token on every retry, so the modal
  // reopened forever (Codex sweep F3, 27 Oct 2026).
  eq(/^let lapsedCsrf = '';$/m.test(src), true, name + ': declares lapsedCsrf');
  const s = load(src, 'nzbfast_csrf_6790');
  const dead = s.auth(B, 'key-6790');
  eq(dead, {'X-CSRF-Token': 'csrfB'}, name + ': before any refusal the token goes');
  eq(s.lapsed(dead), true, name + ': a refused token is marked lapsed, worth one retry');
  eq(s.auth(B, 'key-6790'), KEY, name + ': a lapsed token stops suppressing the key');
  eq(s.lapsed(KEY), false, name + ': a refused KEY is not a lapsed session');
  eq(s.lapsed({'X-CSRF-Token': 'csrfB'}), false, name + ': the same token never retries twice');
  // Signing in again sets a new token, which is live.
  eq(s.auth('nzbfast_csrf_6790=csrfC', 'key-6790'), {'X-CSRF-Token': 'csrfC'},
    name + ': a fresh sign-in\'s token is used again');
  // With no key in hand the lapsed token still is not sent: nothing to send.
  eq(s.auth(B, ''), {}, name + ': lapsed token and no key -> no credential');

  // Served unstamped (opened from disk): no valid name, so the key.
  const raw = load(src, null);
  eq(raw.auth(A + '; ' + B, 'key-x'), viaKey('key-x'),
    name + ': an unstamped page never reads a session cookie');
}

if (failed) {
  console.error(failed + ' failure(s)');
  process.exit(1);
}
console.log('csrf_cookie_test: ok');
