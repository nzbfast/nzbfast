// Unit tests for the server row's cap chip (`node web/capchip_test.js`).
//
// Same approach as web/fmt_test.js and web/densepack_test.js: the
// dashboard is one hand-rolled file with no build step and no test
// runner, so this lifts `capChip` straight out of web/dashboard.html
// rather than keeping a copy that could drift from the one that ships.
//
// What it pins: this chip is the evidence a user sends their provider,
// so every number in it has to have been observed, and - the plainer
// lesson - the ledger it reads is ABSENT on nearly every install, since
// a server only gains one by being refused a connection. Reading a
// field off it unconditionally threw a TypeError that blanked the whole
// server list and aborted the rest of Settings with it.
//
// A companion Rust test (serve/assets.rs) holds the same line in CI,
// where node is not assumed.
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

// The page globals the chip calls: `t` renders the English default with
// its placeholders filled, which is what a browser with no catalogue
// does too.
const t = (k, d, v) => String(d).replace(/\{(\w+)\}/g, (m, n) => (v && n in v) ? v[n] : m);
const escA = s => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
const capChip = new Function('t', 'escA', 'return (' + lift('capChip') + ')')(t, escA);

let failed = 0;
function ok(cond, what) {
  if (cond) return;
  failed++;
  console.error('FAIL: ' + what);
}

const TODAY = 20100;
const UNKNOWN = Number.MAX_SAFE_INTEGER;   // conntune::DAY_LO_UNKNOWN

// The commonest shape on earth: a server nobody has ever refused. It has
// no tuner entry at all, so there is no ledger to read (Codex sweep 7,
// H1). Anything but a quiet empty string here took the whole Settings
// panel down with it.
{
  let threw = null;
  try { ok(capChip(undefined, 40, TODAY) === '', 'no ledger says nothing'); }
  catch (e) { threw = e; }
  ok(!threw, 'no ledger must not throw: ' + threw);
}
// Probed by the connection ladder, never refused: an entry exists, the
// `capped` field does not.
{
  let threw = null;
  try { ok(capChip(null, 40, TODAY) === '', 'a tuner entry with no cap ledger says nothing'); }
  catch (e) { threw = e; }
  ok(!threw, 'a tuner entry with no cap ledger must not throw: ' + threw);
}
// A ledger whose every day has aged out of the 30 day window.
{
  const old = { days: [TODAY - 200], day_lo: [10], granted_lo: 10 };
  ok(capChip(old, 40, TODAY) === '', 'a ledger with no day in the window says nothing');
}

// Modern aligned data: the number is the lowest of the days the sentence
// is actually about, not the lifetime low from outside the window.
{
  const cl = { days: [TODAY - 100, TODAY - 2, TODAY], day_lo: [10, 38, 34], granted_lo: 10 };
  const chip = capChip(cl, 40, TODAY);
  ok(chip.includes('capped at 34 on 2 of the last 3 days'),
    'the low comes from the window the count comes from: ' + chip);
  ok(!chip.includes('capped at 10'), 'the out-of-window lifetime low is not the answer');
}

// One day, on its own, gets the singular sentence.
{
  const chip = capChip({ days: [TODAY], day_lo: [21], granted_lo: 21 }, 40, TODAY);
  ok(chip.includes('capped at 21 today'), 'a one day record reads as today: ' + chip);
}

// A ledger written before the per-day column existed. There is no figure
// for those days and the lifetime one is not it, so the sentence keeps
// the count and drops the number (Codex sweep 7, H1b).
{
  const legacy = { days: [TODAY - 4, TODAY - 1], granted_lo: 10 };      // no day_lo at all
  const chip = capChip(legacy, 40, TODAY);
  ok(chip.includes('capped on 2 of the last 5 days'), 'the count survives: ' + chip);
  ok(!/capped at \d/.test(chip), 'no invented figure: ' + chip);
  ok(!chip.includes('>10<') && !chip.includes(' 10,'), 'the lifetime low is not shown: ' + chip);
}
// The same ledger after conntune aligned the column: the old days are
// marked unknown, and a later real day is not.
{
  const mixed = { days: [TODAY - 4, TODAY], day_lo: [UNKNOWN, 38], granted_lo: 10 };
  const chip = capChip(mixed, 40, TODAY);
  ok(chip.includes('capped at 38 on 2 of the last 5 days'),
    'a known day answers for a window that also holds unknown ones: ' + chip);
}
{
  const allUnknown = { days: [TODAY], day_lo: [UNKNOWN], granted_lo: 10 };
  const chip = capChip(allUnknown, 40, TODAY);
  ok(chip.includes('capped today') && !/capped at \d/.test(chip),
    'one unknown day reads as a day, not as a number: ' + chip);
}

if (failed) { console.error(failed + ' capChip assertion(s) failed'); process.exit(1); }
console.log('capChip: all assertions passed');
