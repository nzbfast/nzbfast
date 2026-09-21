// Unit tests for a queue row's time left (`node web/eta_test.js`).
//
// Same approach as web/fmt_test.js: the two functions are lifted straight
// out of web/dashboard.html, so a copy here cannot drift from the one
// that ships.
//
// What they pin: a downloading row's ETA is its OWN bytes over its OWN
// rate (`job_bps`), never over the whole line's. The line adds the
// successor's bytes to a job still draining behind it, so a job crawling
// at 1.7 MB/s beside a successor at 110 MB/s read "3 seconds left", then
// "0s" with 33 MiB still to fetch, for minutes (21 Sep 2026). A job whose
// own rate is nothing is stalled and says so, and only a QUEUED row is
// estimated from the line.
const fs = require('fs');

const page = fs.readFileSync(__dirname + '/dashboard.html', 'utf8');

function lift(name) {
  const at = page.indexOf('function ' + name + '(');
  if (at < 0) throw new Error('no function ' + name + ' in dashboard.html');
  let i = page.indexOf('{', at), depth = 0, end = -1;
  for (let j = i; j < page.length; j++) {
    if (page[j] === '{') depth++;
    else if (page[j] === '}' && --depth === 0) { end = j + 1; break; }
  }
  if (end < 0) throw new Error('unbalanced body for ' + name);
  return page.slice(at, end);
}

const fmtEta = new Function('return (' + lift('fmtEta') + ')')();
const jobEta = new Function('return (' + lift('jobEta') + ')')();

let failed = 0;
function is(got, want, what) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) return;
  failed++;
  console.error(`FAIL ${what}\n  expected ${w}\n  got      ${g}`);
}

const MiB = 1048576;

// --- the reported case ------------------------------------------------
// Job A: 33 MiB left, crawling at 1.7 MB/s. Job B is taking the line at
// 110 MB/s, so the LINE reads ~112 MB/s. A's own ETA is ~20 s; over the
// line it was 0.3 s, which rounds to "0s".
const A = { status: 'Downloading', mbleft: '33.00', job_bps: 1_700_000, activity: 'fetching' };
const line = 112; // MB/s, decimal, as the header's kbpersec resolves
const est = jobEta(A, line, 33);
is(est.kind, 'eta', 'a downloading row with a rate has an ETA');
is(Math.round(est.secs), 20, "A's ETA is its own bytes over its own rate (~20 s), not over the line");
is(fmtEta(33 / line), '1s', 'and the line-rate figure this replaces would have said 0s - never below 1s');

// --- stalled: an honest word, not a countdown ------------------------
is(jobEta({ ...A, job_bps: 0 }, line, 33), { kind: 'stalled' },
  'own rate 0 while downloading is a stall, whatever the line is doing');
is(jobEta({ ...A, job_bps: 0, activity: 'waiting' }, line, 33), { kind: 'stalled' },
  'a flatline the daemon names is still a stall');
is(jobEta({ ...A, job_bps: 0, activity: 'connecting' }, line, 33), { kind: 'unknown' },
  'a job still connecting has no rate YET and is not called stalled');

// --- no rate to read -------------------------------------------------
is(jobEta({ status: 'Downloading', mbleft: '33.00' }, line, 33), { kind: 'unknown' },
  'a payload with no job_bps says unknown, and never borrows the line');
is(jobEta({ ...A, job_bps: null }, line, 33), { kind: 'unknown' },
  'null job_bps (not on the wire) is unknown');

// --- queued: everything ahead, over the line --------------------------
const Q = { status: 'Queued', mbleft: '100.00' };
const q = jobEta(Q, 100, 6000);
is(q.kind, 'eta', 'a queued row is estimated from the backlog ahead of it');
is(Math.round(q.secs), 60, '...over the whole line rate');
is(jobEta(Q, 0, 6000), { kind: 'unknown' }, 'a queued row with no line rate has no estimate');
is(jobEta(Q, 100, null), { kind: 'unknown' }, '...nor without a backlog figure');

// --- fmtEta never claims a finished countdown ------------------------
is(fmtEta(0.2), '1s', 'a sub-second wait is 1s, not 0s');
is(fmtEta(0), '-', 'nothing is a dash');
is(fmtEta(Infinity), '-', 'no rate is a dash');
is(fmtEta(59.6), '1m 0s', 'the rollover still carries');
is(fmtEta(3661), '1h 1m', 'hours');

if (failed) { console.error(failed + ' failed'); process.exit(1); }
console.log('eta_test: ok');
