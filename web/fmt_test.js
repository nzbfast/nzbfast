// Unit tests for the dashboard's byte formatters (`node web/fmt_test.js`).
//
// The dashboard is one hand-rolled file with no build step and no test
// runner, so these lift the formatter definitions straight out of
// web/dashboard.html and exercise them. That is deliberate: a copy of the
// functions here could drift from the ones that ship, and drift is the
// exact bug being tested for.
//
// What they pin (UX §14): every 1024-based figure says MiB/GiB/TiB and
// every 1000-based one says MB/GB/TB. fmtMB used to divide by 1024 and
// print "GB", so a 100 GiB job read "100.00 GB" in its own queue row
// while contributing "107.4 GB" to the decimal disk-space banner
// directly above it - the same download, two numbers, both called GB.
// The base is the right one for release sizes and stays; the label was
// the bug.
//
// A companion Rust test (assets.rs) keeps the same invariant under
// CI, where node is not assumed.
const fs = require('fs');

const page = fs.readFileSync(__dirname + '/dashboard.html', 'utf8');

function lift(name) {
  // Function bodies are brace-balanced; scan from the declaration.
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

// The formatters call unit() for the symbol and num() for the digits;
// both are page globals. unit() falls back to the English table when a
// locale has no override, which is what these tests exercise.
const UNIT_EN = eval('(' + page.match(/const UNIT_EN=(\{[^\n]*\});?/)[1] + ')');
const scope = {
  UNIT_EN,
  unit: k => UNIT_EN[k],
  num: (v, d) => Number(v).toFixed(d),
};
for (const f of ['fmtBytes', 'fmtSize', 'fmtMB', 'fmtGB']) {
  scope[f] = new Function('unit', 'num', 'fmtMB', 'return (' + lift(f) + ')')(
    scope.unit, scope.num, (...a) => scope.fmtMB(...a));
}
const { fmtBytes, fmtSize, fmtMB, fmtGB } = scope;

let failed = 0;
function is(got, want, what) {
  if (got === want) return;
  failed++;
  console.error(`FAIL ${what}\n  expected ${JSON.stringify(want)}\n  got      ${JSON.stringify(got)}`);
}

const KiB = 1024, MiB = 1024 * 1024, GiB = MiB * 1024, TiB = GiB * 1024;

// --- release sizes: 1024, labelled 1024 -----------------------------
// The number a user checks against their indexer and against the same
// release in SABnzbd. Both are binary, so this base is load-bearing.
is(fmtMB(1024), '1.00 GiB', 'fmtMB at exactly 1 GiB');
is(fmtMB(1048576), '1.00 TiB', 'fmtMB at exactly 1 TiB');
is(fmtMB(700), '700.0 MiB', 'fmtMB under a gibibyte');
is(fmtMB(3.4), '3.40 MiB', 'fmtMB keeps two decimals for small par2 volumes');
is(fmtMB(0.35), '0.35 MiB', 'fmtMB below 10 MiB does not round to 0');
is(fmtMB('1727.39'), '1.69 GiB', 'fmtMB parses the API string form');
is(fmtMB('nonsense'), '-', 'fmtMB refuses a value it cannot read');
// The exact case from the audit: 100 GiB of job, beside a decimal banner.
is(fmtMB(100 * 1024), '100.00 GiB', 'a 100 GiB job says GiB');
is(fmtBytes(100 * GiB), '107.4 GB', '...and the decimal readout of the same bytes says GB');

// fmtSize is fmtMB over raw bytes and must agree with it exactly.
is(fmtSize(GiB), fmtMB(1024), 'fmtSize agrees with fmtMB');
is(fmtSize(42.2 * GiB), '42.20 GiB', 'a 42.2 GiB release reads as its indexer quoted it');
is(fmtSize(Infinity), '-', 'fmtSize refuses a non-finite size');

// --- machine readouts: 1000, labelled 1000 --------------------------
// Disk free, RAM, the database file: what the operating system reports.
is(fmtBytes(1e9), '1.0 GB', 'fmtBytes at exactly 1 GB');
is(fmtBytes(1e12), '1.00 TB', 'fmtBytes at exactly 1 TB');
is(fmtBytes(5e6), '5 MB', 'fmtBytes rounds machine megabytes whole');
is(fmtGB(1e9), '1.00 GB', 'fmtGB at exactly 1 GB');
is(fmtGB(1e12), '1.00 TB', 'fmtGB at exactly 1 TB');
is(fmtGB(5e6), '5.0 MB', 'fmtGB below a gigabyte');

// --- the invariant itself -------------------------------------------
// No formatter may pair one base with the other's label. Checked on the
// source, so a future edit that swaps a unit key is caught even if it
// happens to round to the same string on these samples.
for (const [name, body] of [['fmtMB', lift('fmtMB')], ['fmtSize', lift('fmtSize')]]) {
  for (const wrong of ['MB', 'GB', 'TB']) {
    is(body.includes(`unit('${wrong}')`), false,
      `${name} is 1024-based and must not reach for unit('${wrong}')`);
  }
}
for (const [name, body] of [['fmtBytes', lift('fmtBytes')], ['fmtGB', lift('fmtGB')]]) {
  for (const wrong of ['MiB', 'GiB', 'TiB']) {
    is(body.includes(`unit('${wrong}')`), false,
      `${name} is 1000-based and must not reach for unit('${wrong}')`);
  }
}
// Every symbol a formatter asks for has to exist in the English table,
// or the fallback renders "undefined" for every locale without an
// override.
for (const k of ['MB', 'GB', 'TB', 'MiB', 'GiB', 'TiB']) {
  is(typeof UNIT_EN[k], 'string', `UNIT_EN carries ${k}`);
}

console.log(failed ? `${failed} FAILED` : 'all formatter tests passed');
process.exit(failed ? 1 : 0);
