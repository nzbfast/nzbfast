# i18n toolchain (§5)

All scripts are run **from the repo root**. English is the source
language and lives inline in the pages (`data-i18n` markup + `t()`
call-site defaults) - it ships no catalogue.

## Files
- `en.reference.json` - the extracted English key→string reference
  (regenerated; do not hand-edit).
- `<lang>.json` - translated UI catalogues, embedded in the binary via
  `include_str!` and served at `/i18n/<lang>.json`. Shipped locales (27,
  + en inline): ar bg cs da de el es fa fi fr he hr hu it ja nb nl pl pt
  ro ru sk sl sr sv tr uk. Three are RTL (ar fa he). `check.py`
  auto-discovers this set from `web/i18n/*.json`, so it is the list that
  cannot go stale - re-derive from there rather than trusting this line.

## Key order (the trap)

The two file kinds sort DIFFERENTLY, and rewriting one with the other's
comparator churns hundreds of untouched lines into your diff:

- `en.reference.json` - plain `Object.keys().sort()` (code-point order,
  so `status.Idle` sorts before `status.idle`). That is what `extract.js`
  writes; never hand-edit it, just rerun the script.
- `<lang>.json` - `Object.keys().sort((a,b)=>a.localeCompare(b))`
  localeCompare order (re-verified byte-for-byte against all 27 shipped
  files on 7 Aug 2026: localeCompare re-serializes every file
  identically, plain code-point sort churns ~19 lines per file). Do not
  trust a claim here without re-running the byte-identity test.
- Since 22 Aug 2026 `check.py` ENFORCES both orders (a pure-python
  reproduction of localeCompare for the ASCII key alphabet, verified
  against node on every shipped key). Appending keys without re-sorting
  now turns the gate red and names the first key out of place.

Both use `JSON.stringify(obj, null, 1)` plus a trailing newline. To add
keys to every catalogue, merge them in and re-serialize with the matching
comparator - this rewrites all 27 files byte-identically apart from your
additions:

```js
const s={}; for(const k of Object.keys(d).sort((a,b)=>a.localeCompare(b))) s[k]=d[k];
fs.writeFileSync(p, JSON.stringify(s,null,1)+'\n');
```

Also note: regenerating `en.reference.json` picks up every `t()` default
added to the pages since the last run, so a UI string someone landed
without regenerating turns `check.py` red the moment you regenerate for
your own keys. Translate those too (or the gate ships red on your
commit) - and check whether the strings arrived on origin/main first, so
you are not duplicating an in-flight session's work.

## Strings that must stay English

**A placeholder on a PARSED input is a worked example of a grammar, not
prose. Its literals stay English in every catalogue.** Translate one and
the hint tells the user to type something the daemon refuses, which is
strictly worse than leaving the whole string English - the user cannot
fill the field in from the only hint the UI gives them. The input's
*label* and *tooltip* are ordinary prose and stay translated; it is the
example inside the box that is machine vocabulary.

`sched.days.ph` (`all · mon-fri · sat,sun`) is the case that shipped
broken. That input is parsed by `parse_days` in
`crates/nzbfast/src/serve/sched.rs`, which accepts `all` and the literal
ASCII names `mon..sun` and nothing else; twenty of the twenty-seven
catalogues had localized it into day tokens the parser rejects (de
`alle · mo-fr · sa,so`, ru `все · пн-пт · сб,вс`, …) - TODO 259.
`sched.days.title`, the tooltip, stayed translated throughout.

Since 23 Aug 2026 `check.py` ENFORCES this, so it is a gate rather than
a convention someone has to remember at translation time. It was
prose-only before, which is how the twenty got localized with every gate
green.

**The declared arm.** `MUST_STAY_ENGLISH` in the script pins keys whose
value must be byte-identical to the reference in every catalogue; a
locale that differs turns the gate red naming locale, key and the
offending value (`MUST-STAY-ENGLISH de.json sched.days.ph: ...`). To pin
another key, add it there with a one-line comment naming the parser that
reads it - and only when the WHOLE value is something the user types
verbatim. An `e.g. 20G` style hint is not a candidate: its "e.g."
translates legitimately, and the arms below hold the token instead.

**The discovery arms**, because a pinned list cannot see the next
placeholder somebody writes and not knowing the rule existed was the
whole defect. These derive the same judgement from the string itself,
over every key bound to a `placeholder` in the two pages (plus every
`*.ph` key, since some are reached through a helper the scan cannot
follow):

- **all-token** - two or more `·`-separated fields with nothing but
  machine tokens in them (`all · mon-fri · sat,sun`) is a grammar
  example by construction. Its keys are handed to the pinned arm and
  report through it, so one defect prints one line; it finds
  `sched.days.ph` on its own with the pin emptied, and the pin holds the
  line on its own with this scan deleted.
- **digit literals** - a run carrying a digit is an address, a size or a
  rate, never a word (`4M`, `20G`, `127.0.0.1:1080`, `HMAC-SHA256`), and
  must survive verbatim while the prose around it is translated as
  usual: `e.g. 4M · 0` is correctly `z. B. 4M · 0` in German. This is
  what lets those eight keys stay OUT of `MUST_STAY_ENGLISH`, which pins
  a whole value and would wrongly freeze the lead-in.
- **accepted-value list** - `<label>: tok, tok, tok` is the house way of
  spelling out what an input takes (`events: completed, failed,
  repaired, disk, quota`), and those tokens are the parser's.

A hit that is genuinely prose despite its shape goes in the script's
`PH_WAIVE` with a reason. Do NOT silence one by rewording the English
placeholder so its shape stops matching; if the input really is parsed,
the fix is to put the reference literal back in the catalogue that moved
it. And do not go the other way either - teaching the parser localized
tokens would make a catalogue change alter what an already-stored
setting means.

Two neighbours that look like this class and are not, so nobody
re-derives them: `set.disk.outperm.ph` (`off`) reads like a token but
`set_out_umask` in `crates/nzbfast/src/serve/settings_setters.rs` takes
an octal or an empty string - `off` describes the empty state rather
than naming a value, so it is prose and every catalogue localizes it
correctly. `grp.search.ph`'s `try auto, movies, flac, 1080…` is a list of
example SEARCH TERMS, not of accepted values, and a translator may
localize those; the accepted-value arm is colon-anchored so it does not
reach them.

## Scripts
- `extract.js` - `node web/i18n/extract.js` regenerates
  `en.reference.json` from `web/dashboard.html` + `web/wall.html`
  (data-i18n attrs, `t()/tn()` defaults, plus the hand-maintained
  dynamic-key families for `status.*` / `err.*` / `bench.bn.*` /
  `snd.ev.*`).
- `check.py` - `python3 web/i18n/check.py` validates every `<lang>.json`
  against the reference: key parity, placeholder parity, markup parity,
  JSON validity. **Auto-discovers** locales from `web/i18n/*.json`.
  Since 21 Aug 2026 this is a **CI gate** ("i18n catalogue gate" in
  ci-private.yml), together with a regen-and-diff of `en.reference.json`
  - so the standing rule below is enforced rather than remembered. It
  was hand-run before that, which is how v1.2.1 shipped with all 27
  catalogues 39-51 keys behind. It also reads `web/dashboard.html` and
  `web/wall.html` - that is the parsed-placeholder arm from "Strings
  that must stay English" - so run it from the repo root; `--selftest`
  first, house convention.
- `nav-regen.py` - regenerates the language picker + hreflang alternates
  on **all ten** `website/*.html` bases (widened from the four core
  marketing pages on 23 Aug 2026, the day its picker arm went live; the
  six that joined were already byte-identical to its output, so the
  widening rewrote nothing - see its docstring for the census) and the switcher on every manual
  (`docs/MANUAL.html` + `docs/i18n/MANUAL.*.html`) to the full locale set.
  Adding a locale means its `LANGS` list **and** its `NATIVE` map (the
  picker names each language in that language); an assert refuses one
  without the other. Then run it. `--check` writes nothing and exits 1 if
  the committed output has drifted from what the script would produce, and
  since 23 Aug 2026 it is a **CI gate** ("nav staleness gate"), for the
  same reason as `site-crosslink.py` below - generated output nothing
  verifies is output that rots. Fix a red by running the script with no
  arguments, never by editing one page.
  It was wired a day later than its sibling, because measuring it found
  one of its three arms DEAD: `web_picker` wrote a `<span class="langsw">`
  of uppercase locale codes and the pages have carried a `<select
  class="langsw">` of native names with a `selected` option for some time,
  so that arm matched nothing on all 64 pages, for however long the markup
  has been a select. Gating on it then would have reported every picker
  current while checking no picker at all. `web_picker(base, lang)` now
  emits the select - `lang` because `selected` is per-page - and a census
  of all 160 pickers on the site found none had drifted while the arm was
  inert. Luck, not a reason; nothing had checked. Its docstring carries the
  whole finding. With the arm live, `BASES` was widened the same day from
  the four core pages to all **ten** families, so the gate holds 160 pages
  rather than 64; regenerating rewrote nothing, because the census that
  preceded the widening had already fixed the one live defect in those 90
  pages (75 localized `explained*` pages whose `hreflang="en"` and
  `x-default` pointed back at the localized page - the right 17 entries,
  two hrefs wrong, hand-made on 11 Aug and live on gh-pages for twelve
  days).
  Two guards came out of that widening, neither of them visible by reading
  pages. Every arm counts its own substitutions and dies on the wrong
  count, because a regex that matches nothing rewrites nothing - the file
  then equals itself and `--check` calls it current, which is how the span
  arm passed for months, and widening `BASES` only made an inert arm report
  160 pages clean instead of 64. And `BASES` is now held to the tree by an
  assert: a base with a localized sibling on disk and no entry there fails
  the run by name, because a list is a gate that cannot see the eleventh
  family, which is exactly how those six sat uncovered. Add a family to it
  only **after** translating the full locale set - the picker names every
  locale in `LANGS`, so a half-translated one would get options pointing at
  files that do not exist.
- `site-crosslink.py` - rewrites internal cross-page links (nav + body
  CTAs) on every localized `website/*.<lang>.html` to its same-language
  sibling, so a visitor stays in one language. Its `BASES` covers all
  **ten** families since 23 Aug 2026, up from the four core marketing
  pages; the six that joined were measured fully in-language already, so
  the widening moved no byte of any page and took the gate from 60 pages
  to 150. Protects the picker span
  and hreflang block (they keep the bare + explicit-per-language names).
  Idempotent; run after translating website pages. Since 23 Aug 2026
  `--check` is a **CI gate** ("cross-link staleness gate"), because
  committed generator output that nothing verifies is committed output
  that rots: a hand-patched `href` is undone by the next regeneration
  without a word. Fix a red by running the script with no arguments,
  never by editing one page.
- `site-check.py` - structural parity for localized website pages vs
  their English base (id sets, tag counts, byte-identical `<code>`, lang
  attr, a full **nav census** of the picker and the hreflang block) + an
  **anonymity grep** for leaked
  city/provider names on every page that cites a measurement, the
  English base included. Since 23 Aug 2026 a **CI gate** ("site parity
  gate"), the last of the three parity scripts here to be wired. The
  anonymity half is why it matters more than its siblings: `website/` is
  published, so a hit there is a disclosure rather than a typo, and one
  a revert does not take back. That arm fires on nothing today, which is
  what a broken one also looks like - so `--selftest` is the gate here,
  not the convention: the ban list is a list of (fragment, sample) pairs
  the regex is BUILT from, every entry is driven at its own sample, both
  word anchors and the roster size are pinned, and the tag census runs
  off a frozen roster so a tag dropped from the census cannot take its
  own test with it. Do not collapse either list back into a literal.
  Fix a parity hit by translating; fix an anonymity hit by
  de-anonymizing. Never by deleting the English element, and never by
  dropping a name from the ban list.
  The **nav census** was widened on 23 Aug 2026 from "a picker and an
  hreflang block are present somewhere in the page" to the picker's
  targets plus its `selected` option, and the hreflang block's
  (hreflang, target) PAIRS, against the family's full locale set - on
  the ten English bases as well as the 150 translations, which is why
  the run is 160 report lines and not 156. Present-is-not-complete is
  not a hypothetical: all 75 localized `explained*` pages had shipped
  with `hreflang="en"` and `hreflang="x-default"` pointing back at the
  localized page (the right 17 entries, two hrefs wrong, so counting
  could not see it either), hand-made on 11 Aug and live on gh-pages
  for twelve days. `LANGS_EXPECTED` pins the locale roster the census
  derives from, because a locale deleted from `LANGS` would otherwise
  take its own test with it and pass every page one locale short. Fix a
  nav hit by putting the missing locale or the right target back; never
  by shortening `LANGS`.
- `manual-check.py` - structural parity for translated manuals vs
  `docs/MANUAL.html`: a FULL 18-tag census (whole-file AND per section,
  the file split on `<h2 id="`), id/anchor sets, byte-identical `<code>`,
  lang, switcher. Widened from five tag counts on 22 Aug 2026, because
  an English-only block made of `<p>`, `<li>`, `<b>`, `<div>` or `<tr>`
  was invisible to the old list unless it happened to carry a `<code>`,
  and that shipped untranslated copy three times (28 Jul, 3 Aug, 22
  Aug). Fifteen structural tags fail the run; `b`, `em` and `span` are a
  warning tier, since a translator may legitimately fold or split inline
  emphasis. A locale with any delta gets the per-section breakdown
  printed under it (`wall {'li': -2, 'b': -7}`), so the chapter to read
  is named rather than hunted. A **CI gate** since 23 Aug 2026 ("manual
  parity gate"). `--selftest` first, house convention.
- `pullsearch/port.py` - the pattern for adding a NEW manual section to
  all 16 languages at once, kept as a worked example. The blocks live one
  file per locale (`pullsearch/<lang>.html`, marked off with
  `<!--BLOCK name-->`), rendered from `pullsearch/en.html` so only the
  prose differs; `port.py --check` compares the tag stream, `href=` and
  `<code>` content of every block against English BEFORE writing, and
  each insertion anchors on an `id=` or a byte-identical `<code>` and
  asserts a single match. Hand-writing the locale pages instead is what
  puts `manual-check.py` red at gate time.

## Adding a locale (Latin / simple plural)
1. `web/i18n/<tag>.json` - translate from `en.reference.json`.
2. `crates/nzbfast/src/serve/uilocales.rs`: add the tag to `UI_LOCALES`.
   Then `crates/nzbfast/src/serve/assets.rs`: an `i18n_catalog()` arm (and
   a `manual_i18n()` arm once a manual exists, else it falls back to
   English). This used to be one `serve.rs`; the daemon is a module tree
   under `src/serve/` now, and the tag list sits one module below the
   assets because the settings boundary reads it with `dashboard` off.
3. `web/dashboard.html` + `web/wall.html`: add to the `LOCALES` array, plus
   one `LOCALE_NAMES` line in dashboard.html (`[native, English]` - both
   Settings selects are generated from it at boot).
4. Website/manual (optional): seed English copies, add tag to
   `nav-regen.py` LANGS **and** its NATIVE map (the native language name)
   + `site-crosslink.py`/`site-check.py`/`manual-check.py`, run nav-regen,
   translate, run site-crosslink, validate.
5. `node --check` the inline JS, `cargo build --release -p nzbfast`,
   live-verify on a scratch daemon (its own port + scratch dirs), commit
   per safe-git.

Multi-plural locales need no engine work - `tn()` is category-generic. A
locale whose grammar adds CLDR categories just ships the extra keys and
declares them in `check.py`: `SLAVIC_FEW` (ru/pl/cs/uk/sk/hr/sr add
`base.few`) or `DUAL_TWO` (sl adds `base.two` **and** `base.few`). Any
category a catalogue doesn't stock falls back to `.many` at runtime.
