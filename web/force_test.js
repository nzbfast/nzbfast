// Unit tests for the forced-row helpers (`node web/force_test.js`).
//
// Same approach as web/capchip_test.js: the dashboard is one hand-rolled
// file with no build step, so this lifts the pure helpers straight out of
// web/dashboard.html rather than keeping a copy that could drift.
//
// What it pins: Force priority runs even while the queue is paused, and
// the page's job is to SAY so (a "forced" badge on the row, the pause
// pill naming the jobs it did not stop) and to offer the way out. The
// helpers decide only which rows count as forced and what the pill's
// tooltip names; both have to survive the shapes a real queue payload
// has - a row past the paging window, a row with no display name, an
// empty or absent `pause_exempt`.
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

const t = (k, d, v) => String(d).replace(/\{(\w+)\}/g, (m, n) => (v && n in v) ? v[n] : m);
const escA = s => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;');
const isForced = new Function('return (' + lift('isForced') + ')')();
const exemptNames = new Function('return (' + lift('exemptNames') + ')')();
const forcePillTitle = new Function('t', 'exemptNames',
  'return (' + lift('forcePillTitle') + ')')(t, exemptNames);
const forcedTip = new Function('t', 'return (' + lift('forcedTip') + ')')(t);
const forceChip = new Function('t', 'esc', 'escA', 'isForced', 'forcedTip',
  'return (' + lift('forceChip') + ')')(t, esc, escA, isForced, forcedTip);
const forceBlock = new Function('t', 'esc', 'escA', 'isForced', 'forcedTip',
  'return (' + lift('forceBlock') + ')')(t, esc, escA, isForced, forcedTip);

let failed = 0;
function ok(cond, what) {
  if (cond) return;
  failed++;
  console.error('FAIL: ' + what);
}
function eq(a, b, what) {
  ok(JSON.stringify(a) === JSON.stringify(b),
    what + ': got ' + JSON.stringify(a) + ', want ' + JSON.stringify(b));
}

// ---- isForced: the SAB word is the whole test ---------------------------
ok(isForced({ priority: 'Force' }), 'Force is forced');
ok(!isForced({ priority: 'High' }), 'High is not');
ok(!isForced({ priority: 'Normal' }), 'Normal is not');
ok(!isForced({ priority: 'Low' }), 'Low is not');
ok(!isForced({}), 'a row with no priority is not');
ok(!isForced(undefined), 'no row at all is not, and does not throw');
ok(!isForced(null), 'null is not, and does not throw');

// ---- exemptNames --------------------------------------------------------
const rows = [
  { nzo_id: 'a', filename: 'Show.S01E01.1080p.WEB-GRP' },
  { nzo_id: 'b', name: 'only-a-name' },
  { nzo_id: 'c', filename: 'Third.One' },
  { nzo_id: 'x', filename: 'x'.repeat(200) },
];
eq(exemptNames(rows, ['a'], 3, 48), { names: ['Show.S01E01.1080p.WEB-GRP'], more: 0 },
  'one job, named');
eq(exemptNames(rows, ['b'], 3, 48), { names: ['only-a-name'], more: 0 },
  'falls back to name when there is no filename');
eq(exemptNames(rows, ['a', 'b', 'c'], 2, 48), { names: ['Show.S01E01.1080p.WEB-GRP', 'only-a-name'], more: 1 },
  'past the cap the rest are counted, not dropped');
eq(exemptNames(rows, ['zzz'], 3, 48), { names: [], more: 1 },
  'an id whose row is past the paging window still counts');
eq(exemptNames(rows, ['a', 'zzz'], 3, 48), { names: ['Show.S01E01.1080p.WEB-GRP'], more: 1 },
  'named and unnamed mixed');
eq(exemptNames(rows, [], 3, 48), { names: [], more: 0 }, 'empty list');
eq(exemptNames(rows, undefined, 3, 48), { names: [], more: 0 }, 'absent list does not throw');
eq(exemptNames(undefined, ['a'], 3, 48), { names: [], more: 1 }, 'absent rows do not throw');
const clipped = exemptNames(rows, ['x'], 3, 48).names[0];
ok(clipped.length === 48 && clipped.endsWith('…'), 'a long name is clipped to the limit with an ellipsis');

// ---- the pill's tooltip -------------------------------------------------
{
  const title = forcePillTitle({ slots: rows, pause_exempt: ['a'] });
  ok(title.includes('Show.S01E01.1080p.WEB-GRP'), 'the tooltip names the job: ' + title);
  ok(/forced/i.test(title) && /paused/i.test(title), 'and says why: ' + title);
  ok(/stop forcing/i.test(title), 'and how to stop it: ' + title);
  const many = forcePillTitle({ slots: rows, pause_exempt: ['a', 'b', 'c'] });
  ok(many.includes('and 1 more'), 'the overflow is counted: ' + many);
  // Nothing on this page to name: the generic sentence, not "names: ".
  const bare = forcePillTitle({ slots: [], pause_exempt: ['zzz'] });
  ok(!/\{names\}/.test(bare) && bare.length > 20, 'no rows, no placeholder left in the text: ' + bare);
  const none = forcePillTitle(undefined);
  ok(none.length > 20 && !/undefined/.test(none), 'no payload at all does not throw or leak: ' + none);
}

// ---- the badge and the drawer block -------------------------------------
{
  const chip = forceChip({ nzo_id: 'SABnzbd_nzo_abc', priority: 'Force' });
  ok(chip.includes('class="qbadge force"'), 'a forced row wears the badge');
  ok(chip.includes("unforceJobs(['SABnzbd_nzo_abc'])"), 'and one click stops forcing it');
  ok(chip.includes('stopPropagation'), 'without folding the row open as well');
  ok(/title="[^"]*queue is paused[^"]*"/.test(chip), 'the tooltip says what Force does');
  eq(forceChip({ nzo_id: 'n', priority: 'Normal' }), '', 'a Normal row wears nothing');

  const blk = forceBlock({ nzo_id: 'n1', priority: 'Force', held_for: '' });
  ok(blk.includes('unforceJobs') && !blk.includes('reholdJob'),
    'an ordinary forced row offers Normal and no hold');
  const dup = forceBlock({ nzo_id: 'n2', priority: 'Force', held_for: 'SABnzbd_nzo_orig' });
  ok(dup.includes('unforceJobs') && dup.includes("reholdJob('n2')"),
    'a released duplicate offers Normal AND the way back to its hold');
  eq(forceBlock({ nzo_id: 'n3', priority: 'Normal', held_for: 'x' }), '',
    'a row that is not forced has no block, whatever it was held for');
}

if (failed) {
  console.error(failed + ' failure(s)');
  process.exit(1);
}
console.log('force_test: ok');
