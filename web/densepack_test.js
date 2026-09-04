// Unit tests for the dense layout packer (`node web/densepack_test.js`).
//
// Same approach as web/fmt_test.js: the dashboard is one hand-rolled file
// with no build step and no test runner, so this lifts `densePack`
// straight out of web/dashboard.html rather than keeping a copy that
// could drift from the one that ships.
//
// What it pins (§6e card stacking): a saved stack is a promise the page
// made out loud - the context menu says "Unstack", and announce() has
// already told a screen reader that this card sits under that one. The
// packer has to honour a chain of those in whatever DOM order the user's
// Move up / Move down presses left behind, because reordering rewrites
// the order list and never the pins.
//
// A companion Rust test (assets.rs) holds the same line in CI,
// where node is not assumed.
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

const densePack = new Function('return (' + lift('densePack') + ')')();

let failed = 0;
function ok(cond, what) {
  if (cond) return;
  failed++;
  console.error('FAIL: ' + what);
}

const card = id => ({ id, span: 20 });

// The shape three Move down presses produce: the pins still say B under
// A and C under B, but the DOM now reads C, B, A. A single drain pass
// met C while B was still waiting and auto-placed it, so the card sat in
// whichever column was shortest while the menu still offered "Unstack"
// (Codex sweep 7, M9).
{
  const p = densePack([card('C'), card('B'), card('A')], 2, { B: 'A', C: 'B' }).placed;
  ok(p.B.col === p.A.col, 'B stays in A\'s column');
  ok(p.B.row >= p.A.end, 'B sits below A');
  ok(p.C.col === p.B.col, 'C stays in B\'s column through a two-level chain');
  ok(p.C.row >= p.B.end, 'C sits below B');
}

// Forward DOM order was already fine and must stay fine.
{
  const p = densePack([card('A'), card('B'), card('C')], 2, { B: 'A', C: 'B' }).placed;
  ok(p.C.col === p.A.col && p.C.row >= p.B.end, 'a forward chain is unchanged');
}

// A four-deep chain in fully reversed order: one relaxation step per
// round, so this needs three of them.
{
  const ids = ['D', 'C', 'B', 'A'];
  const p = densePack(ids.map(card), 3, { B: 'A', C: 'B', D: 'C' }).placed;
  ok(p.D.col === p.A.col && p.C.col === p.A.col && p.B.col === p.A.col,
    'a four-deep chain lands in one column');
  ok(p.B.row >= p.A.end && p.C.row >= p.B.end && p.D.row >= p.C.end,
    'a four-deep chain stays in order');
}

// A cycle has no fixpoint and must still terminate, placing every card.
{
  const r = densePack([card('A'), card('B')], 2, { A: 'B', B: 'A' });
  ok(r.placed.A && r.placed.B, 'a pin cycle degrades to auto placement rather than hanging');
}

// A card pinned to an anchor that is not on the page at all is not a
// chain at all: it must place immediately, not wait for a round.
{
  const r = densePack([card('A'), card('B')], 2, { B: 'gone' });
  ok(r.placed.B, 'a pin to a missing anchor auto-places');
}

if (failed) { console.error(failed + ' densePack assertion(s) failed'); process.exit(1); }
console.log('densePack: all assertions passed');
