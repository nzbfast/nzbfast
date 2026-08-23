#!/usr/bin/env python3
"""Validate translated catalogues against the English reference:
key parity, placeholder parity, markup preservation, JSON validity,
and per-locale plural-category completeness. Locales are auto-discovered
from web/i18n/*.json (adding a new one is translation-only - this picks
it up).

Plurals: the English reference carries the two CLDR categories English
uses - base.one and base.many (".many" is the historical suffix for the
non-one bucket, CLDR 'other'). At runtime tn() selects via
Intl.PluralRules. Locales whose grammar needs a distinct 2-4 form
(Russian, Polish, Czech, Ukrainian, Slovak, Croatian, Serbian) must ADD a
base.few key to every plural family; Czech's 5+/0 form lands in .many
through the runtime category->many fallback, so it needs no separate
.other. Slovenian and Hebrew add a dual (base.two); Slovenian also takes
base.few (one/two/few/many). Arabic takes all six categories
(base.zero/.two/.few on top of .one/.many). Two-form locales (the Latin
scripts, Greek, Hungarian, Bulgarian, Persian, and CJK such as Japanese)
keep just .one/.many and must NOT ship a stray .few. This script enforces
exactly that per locale."""
import json, re, sys, glob, os

# Key ORDER (README.md "Key order (the trap)"). en.reference.json is
# plain `Object.keys().sort()` (code-point order); every <lang>.json is
# `sort((a,b)=>a.localeCompare(b))`, which is ICU root collation and a
# genuinely different order (~19 lines per file differ). Nothing held
# either until 22 Aug 2026: db463185d appended two set.disk.cats.groups.*
# keys to all 27 catalogues without re-sorting, every gate stayed green,
# and the next session to re-serialise properly (TODO 193) silently
# moved them, putting 54 lines of unrelated churn into its diff.
#
# localeCompare is reproduced here rather than shelled out to node so
# the gate stays a dependency-free python script. For the alphabet the
# keys actually use (ASCII: the err.* keys are whole sentences, with
# spaces and punctuation) ICU root collation is: every punctuation mark
# and space sorts before every digit, digits before letters, letters
# case-insensitively at the primary level with lowercase winning only
# as a whole-string tiebreak (so `err.a valid...` < `err.POST...`, and
# `status.idle` < `status.Idle`). The punctuation order below is CLDR
# root's. Verified against node's localeCompare on the union of all
# 2,997 shipped keys and on 15,200 random strings over this whole table
# (22 Aug 2026); a character outside the table is refused, not guessed
# at - extend LC_PUNCT after checking the new character against node.
LC_PUNCT = " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$"


def lc_key(k):
    """Sort key reproducing JS `a.localeCompare(b)` for ASCII keys."""
    prim, tert = [], []
    for c in k:
        if c in LC_PUNCT:
            prim.append((0, LC_PUNCT.index(c))); tert.append(0)
        elif c.isascii() and c.isdigit():
            prim.append((1, int(c))); tert.append(0)
        elif c.isascii() and c.isalpha():
            prim.append((2, ord(c.lower()))); tert.append(c.isupper())
        else:
            raise ValueError(f'key {k!r}: character {c!r} is outside the '
                             'collation table (LC_PUNCT); verify its ICU '
                             'order against node and extend the table')
    return (prim, tert)


def order_error(keys, want, label, how):
    """None if `keys` is already in `want` order, else a message naming
    the first key that sits out of place."""
    if keys == want:
        return None
    for i, (a, b) in enumerate(zip(keys, want)):
        if a != b:
            return (f'{label}: keys are not in {how} order: {a!r} at '
                    f'position {i} should be {b!r} (re-serialise per README.md)')
    return f'{label}: key order differs in length'

# Keys whose VALUE must stay byte-identical to en.reference.json in every
# catalogue (README.md "Strings that must stay English"). These are worked
# examples of a grammar the daemon PARSES back, not prose: a localized one
# tells the user to type tokens the parser rejects. Twenty of 27
# catalogues had localized sched.days.ph (de `alle . mo-fr . sa,so`, ru in
# Cyrillic) and every gate stayed green - TODO 259, fixed d99ee5a6d. The
# rule lived only in README prose until 23 Aug 2026; this pins it.
#
# Surveyed before seeding (23 Aug 2026): every other `.ph` whose value
# carries parser tokens (sched.value.ph `e.g. 4M · 0`, set.db.cap.ph,
# set.srv.socks.ph, set.notify.events.ph, set.notify.body.ph) is prose
# AROUND a token - "e.g." / "events:" is legitimately translated and the
# tokens are already held by placeholder parity or survive untouched - and
# ladder.n.ph `auto` / set.disk.outperm.ph `off` describe what an EMPTY
# box means, they are not typed. prov.backbones.one/many, set.srv.retention,
# usage.sub and set.notify.title were judged legitimately translated in
# the TODO 259 writeup; do NOT pin them. Pin a key here only when the
# whole value is something the user is meant to type verbatim.
MUST_STAY_ENGLISH = {
    # parse_days, crates/nzbfast/src/serve/sched.rs: `all` + ASCII mon..sun
    'sched.days.ph',
}


def stay_english_errors(lang, d, reference=None, keys=None):
    """Messages for every pinned key whose value differs from the
    reference (missing keys are reported by the parity arm, not here).
    `keys` defaults to the hand-pinned set; the caller passes it the
    union with what the ALL-TOKEN scan below found, so a placeholder
    whose shape gives it away needs no entry in MUST_STAY_ENGLISH."""
    reference = ref if reference is None else reference
    keys = MUST_STAY_ENGLISH if keys is None else keys
    out = []
    for k in sorted(keys):
        if k in d and k in reference and d[k] != reference[k]:
            out.append(f'MUST-STAY-ENGLISH {lang}.json {k}: {d[k]!r} '
                       f'must equal the reference {reference[k]!r} '
                       '(README.md "Strings that must stay English")')
    return out


# ---- Finding the parsed-input placeholders MUST_STAY_ENGLISH does not
# name (README.md "Strings that must stay English"; TODO 259). The pinned
# set above is the declared arm and stays the answer for a parsed
# placeholder whose shape gives nothing away. It cannot see the NEXT
# placeholder somebody writes, though, and the whole defect was that
# nobody knew the rule existed - so these arms derive the same judgement
# from the string itself, over every key bound to a `placeholder` in the
# two pages plus every `*.ph` key (the pages reach some of them through a
# helper the scan cannot follow, e.g. `sched.value.ph`). Each was
# measured against all 27 shipped catalogues on 23 Aug 2026 with zero
# false positives:
#
#   A  ALL-TOKEN. A value that is two or more `·`-separated fields and
#      contains nothing but machine tokens is a grammar example by
#      construction - prose does not look like that. Its keys are handed
#      to stay_english_errors, so it reports through the pinned arm
#      rather than beside it: one defect, one line. One key today,
#      sched.days.ph, which is why MUST_STAY_ENGLISH would still hold
#      the line if this scan were deleted.
#   B  DIGIT LITERALS. A whitespace-delimited run carrying a digit is an
#      address, a size or a rate, never a word: `4M`, `20G`,
#      `127.0.0.1:1080`, `HMAC-SHA256`. It must survive verbatim, while
#      the prose around it is translated as usual - `e.g. 4M · 0` is
#      correctly `z. B. 4M · 0` in German. Eight keys today. This is what
#      lets those keys stay OUT of MUST_STAY_ENGLISH, which pins a WHOLE
#      value and would wrongly freeze their lead-in.
#   C  ACCEPTED-VALUE LIST. `<label>: tok, tok, tok` is the house way of
#      spelling out what an input accepts, and the tokens after the colon
#      are the parser's, not English. Each must survive verbatim. One key
#      today: set.notify.events.ph (completed/failed/repaired/disk/quota).
#      Colon-anchored on purpose - a bare comma run also matches
#      `try auto, movies, flac` in grp.search.ph, which is a list of
#      example SEARCH TERMS and a translator may reasonably localize it.
#
# A hit that is genuinely prose despite its shape goes in PH_WAIVE with a
# reason. Do NOT silence one by editing the English placeholder to hide
# its shape - if the input really is parsed, the fix is to put the
# reference string back in the catalogue that moved it.
PH_WAIVE = {
    # (key, token or '*'): why this looks parsed but is not.
}

_PH_BIND = re.compile(
    r'data-i18n-placeholder="([\w.]+)"'
    r'|placeholder="\$\{[^"]*?\bt\(\s*[\'"]([\w.]+)[\'"]'
    r'|\.placeholder\s*=\s*t\(\s*[\'"]([\w.]+)[\'"]')
_TOKEN = re.compile(r'[a-z0-9]+(?:[-,.:/][a-z0-9]+)*')
_DIGIT_RUN = re.compile(r'\S*\d\S*')
_ACCEPTS = re.compile(r':\s*([a-z]{2,}(?:,\s*[a-z]{2,}){2,})')


def placeholder_keys(pages, keys):
    """Keys bound to an input placeholder: scanned out of the pages,
    union the `*.ph` naming convention (some are reached through a
    helper the scan cannot follow, and `ladder.ph.*` are phase strings
    rather than placeholders, so the suffix must be the LAST segment)."""
    found = {k for k in keys if k.endswith('.ph')}
    for src in pages:
        for m in _PH_BIND.finditer(src):
            found.add(next(g for g in m.groups() if g))
    return found & set(keys)


def parsed_literals(en):
    """(arm, want) pairs a translation of `en` must satisfy. arm 'A'
    wants byte-identity; 'B'/'C' want the token present verbatim."""
    out = []
    fields = [f for f in re.split(r'\s*[\u00b7|]\s*', en) if f]
    if len(fields) >= 2 and all(_TOKEN.fullmatch(f) for f in fields):
        out.append(('A', en))
    for run in _DIGIT_RUN.findall(en):
        tok = run.strip('.,;:()"\'\u2026\u201c\u201d')
        if tok:
            out.append(('B', tok))
    m = _ACCEPTS.search(en)
    if m:
        out += [('C', t.strip()) for t in m.group(1).split(',')]
    return out


def all_token_keys(ref_map, pages):
    """Placeholder keys arm A judges to be pure grammar examples. Union
    these into MUST_STAY_ENGLISH: byte-identity is the same demand, so
    they are reported by the same arm rather than twice."""
    return {k for k in placeholder_keys(pages, ref_map)
            if any(arm == 'A' for arm, _ in parsed_literals(ref_map[k]))
            and (k, ref_map[k]) not in PH_WAIVE and (k, '*') not in PH_WAIVE}


def placeholder_errors(ref_map, cats, pages):
    """[(lang, key, arm, want)] for arms B and C - the literals that ride
    INSIDE a placeholder whose prose is translated normally. Arm A is not
    reported here; its keys go through stay_english_errors. `cats` is
    {lang: catalogue}."""
    bad = []
    for k in sorted(placeholder_keys(pages, ref_map)):
        for arm, want in parsed_literals(ref_map[k]):
            if arm == 'A':
                continue
            if (k, want) in PH_WAIVE or (k, '*') in PH_WAIVE:
                continue
            for lang in sorted(cats):
                tr = cats[lang].get(k)
                if tr is None:
                    continue  # already reported as missing
                if want not in tr:
                    bad.append((lang, k, arm, want))
    return bad


def selftest():
    # Frozen from node: [...].sort((a,b)=>a.localeCompare(b)) on 22 Aug 2026.
    lc = ['err.POST required', 'err.a valid email address is required',
          'err.connect timed out (12 s)', 'err.connect-timed', 'err.connect_x',
          'err.connect1', 'err.connectA', 'err.connecta', 'status.Idle',
          'status.idle', 'status.idle2']
    want = ['err.a valid email address is required',
            'err.connect timed out (12 s)', 'err.connect_x', 'err.connect-timed',
            'err.connect1', 'err.connecta', 'err.connectA', 'err.POST required',
            'status.idle', 'status.Idle', 'status.idle2']
    assert sorted(lc, key=lc_key) == want, sorted(lc, key=lc_key)
    assert sorted(lc) != want, 'code-point sort must differ, or the arm is moot'
    assert order_error(want, want, 'x', 'lc') is None
    bad = want[:3] + [want[4], want[3]] + want[5:]
    msg = order_error(bad, want, 'fx', 'localeCompare')
    assert msg and "'err.connect1' at position 3 should be 'err.connect-timed'" in msg, msg
    try:
        lc_key('caf\u00e9'); raise AssertionError('non-ASCII must be refused')
    except ValueError:
        pass

    # Parsed-input placeholders. Arm A fires on the shape that shipped
    # broken; B and C on the two literal shapes that ride inside prose.
    days = 'all \u00b7 mon-fri \u00b7 sat,sun'
    assert parsed_literals(days) == [('A', days)], parsed_literals(days)
    assert ('A', 'e.g. 4M \u00b7 0') not in parsed_literals('e.g. 4M \u00b7 0'), \
        'a prose lead-in must not read as an all-token grammar example'
    assert parsed_literals('e.g. 4M \u00b7 0') == [('B', '4M'), ('B', '0')]
    assert parsed_literals('e.g. 127.0.0.1:1080') == [('B', '127.0.0.1:1080')]
    ev = 'events: completed, failed, disk - empty = every download'
    assert parsed_literals(ev) == [('C', 'completed'), ('C', 'failed'),
                                   ('C', 'disk')], parsed_literals(ev)
    # Prose that must stay quiet: no digits, no colon-anchored run, and a
    # single field can never be arm A.
    for prose in ('off', 'depth (optional)', 'match: regex or keyword',
                  'Search names and descriptions - try auto, movies, flac'):
        assert parsed_literals(prose) == [], (prose, parsed_literals(prose))
    ref_x = {'sched.days.ph': days, 'set.disk.outperm.ph': 'off'}
    pages = ['<input data-i18n-placeholder="set.disk.outperm.ph">']
    assert placeholder_keys(pages, ref_x) == set(ref_x)
    de_x = {'sched.days.ph': 'alle \u00b7 mo-fr \u00b7 sa,so',
            'set.disk.outperm.ph': 'aus'}
    # Arm A discovers the key WITHOUT it being pinned, and reports it
    # through the pinned arm - one defect, one line, not two.
    assert all_token_keys(ref_x, pages) == {'sched.days.ph'}
    assert placeholder_errors(ref_x, {'de': de_x}, pages) == [], \
        'arm A must not report beside stay_english_errors'
    errs = stay_english_errors('de', de_x, ref_x, all_token_keys(ref_x, pages))
    assert len(errs) == 1 and 'sched.days.ph' in errs[0], errs
    assert stay_english_errors('de', de_x, ref_x, set()) == [], \
        'set.disk.outperm.ph is prose - nothing may pin it'
    PH_WAIVE[('sched.days.ph', days)] = 'selftest'
    assert all_token_keys(ref_x, pages) == set()
    del PH_WAIVE[('sched.days.ph', days)]
    # MUST_STAY_ENGLISH must FIRE on a localized value, not merely run.
    r = {'sched.days.ph': 'all · mon-fri · sat,sun', 'sched.days.title': 'Days'}
    assert stay_english_errors('en', dict(r), r) == []
    ok = dict(r, **{'sched.days.title': 'Tage'})  # prose may translate
    assert stay_english_errors('de', ok, r) == []
    bad = dict(r, **{'sched.days.ph': 'alle · mo-fr · sa,so'})
    errs = stay_english_errors('de', bad, r)
    assert len(errs) == 1 and "de.json sched.days.ph: 'alle · mo-fr · sa,so'" in errs[0], errs
    assert 'sched.days.ph' in MUST_STAY_ENGLISH, 'seed key must stay pinned'
    print('check.py selftest: OK')


if '--selftest' in sys.argv:
    selftest(); sys.exit(0)

ref = json.load(open('web/i18n/en.reference.json'))
PH = re.compile(r'\{[a-z]+\}')
TAGS = re.compile(r'</?(?:b|code|a|i|br)\b')

# Plural families: bases carrying BOTH English categories. extract.js
# guarantees .one/.many always come as a pair (its pairing self-check),
# so this reconstructs the family set without a hand-maintained list.
PLURAL_BASES = sorted(k[:-4] for k in ref if k.endswith('.one')
                      and k[:-4] + '.many' in ref)

# Locales that add a CLDR 'few' (2-4) category to every plural family.
SLAVIC_FEW = {'ru', 'pl', 'cs', 'uk', 'sk', 'hr', 'sr', 'sl'}
# Locales that add a CLDR 'two' (dual) category - Hebrew (phase 2b) and
# Slovenian (phase 2a-ext, one/two/few/many; sl is also in SLAVIC_FEW,
# so the two sets together give it both .two and .few).
DUAL_TWO = {'he', 'sl'}
# Arabic (phase 2b) uses all six CLDR categories. The runtime tn() falls
# back to .many for any category with no stored key, so 'other' rides
# .many and Arabic must supply .zero/.two/.few on top of .one/.many.
ARABIC_PLURALS = {'ar'}


def expected_keys(lang):
    """Reference key set adjusted for this locale's plural categories."""
    keys = set(ref)
    if lang in SLAVIC_FEW:
        keys |= {b + '.few' for b in PLURAL_BASES}
    if lang in DUAL_TWO:
        keys |= {b + '.two' for b in PLURAL_BASES}
    if lang in ARABIC_PLURALS:
        keys |= {b + suf for b in PLURAL_BASES
                 for suf in ('.zero', '.two', '.few')}
    return keys


def en_for(k):
    """The reference English a translated key is checked against. A .two
    (dual) is a specific-number form like the singular, so it mirrors .one
    for placeholder parity; the plural-quantity forms (.few/.zero) mirror
    the .many bucket they augment."""
    if k in ref:
        return ref[k]
    base, _, cat = k.rpartition('.')
    if cat == 'two':
        return ref.get(base + '.one')
    if cat in ('few', 'zero'):
        return ref.get(base + '.many')
    return None


LOCALES = sorted(os.path.basename(p)[:-5] for p in glob.glob('web/i18n/*.json')
                 if not p.endswith('en.reference.json'))
fail = 0
# Parsed-input placeholders must keep the reference's literals (see the
# PH_WAIVE block above). The pages are read here rather than a key list
# being maintained, so a new placeholder input is covered the day it
# lands; if a page is missing the arms stand down loudly rather than
# passing silently.
PAGES = []
for page in ('web/dashboard.html', 'web/wall.html'):
    try:
        PAGES.append(open(page, encoding='utf-8').read())
    except OSError as e:
        fail += 1
        print(f'  PARSED-PH cannot read {page}: {e} (run from the repo root)')
# What the byte-identity arm holds: the hand-pinned keys plus every
# placeholder arm A recognised as a pure grammar example on its own.
PH_PINNED = MUST_STAY_ENGLISH | all_token_keys(ref, PAGES)
CATS = {}
for lang in LOCALES:
    path = f'web/i18n/{lang}.json'
    try:
        d = json.load(open(path))
    except Exception as e:
        print(f'{lang}: INVALID JSON: {e}'); fail += 1; continue
    CATS[lang] = d
    exp = expected_keys(lang)
    try:
        err = order_error(list(d), sorted(d, key=lc_key), f'{lang}.json',
                          'localeCompare')
    except ValueError as e:
        err = str(e)
    if err:
        fail += 1; print(f'  ORDER {err}')
    for msg in stay_english_errors(lang, d, ref, PH_PINNED):
        fail += 1; print(f'  {msg}')
    missing = exp - set(d)
    extra = set(d) - exp
    ph_bad, tag_bad, empty = [], [], []
    for k, tr in d.items():
        en = en_for(k)
        if en is None:
            continue  # unexpected key - already reported under 'extra'
        if not isinstance(tr, str) or not tr.strip():
            empty.append(k); continue
        if sorted(PH.findall(en)) != sorted(PH.findall(tr)):
            ph_bad.append(k)
        if len(TAGS.findall(en)) != len(TAGS.findall(tr)):
            tag_bad.append(k)
    ident = sum(1 for k in d
                if en_for(k) is not None and d[k] == en_for(k) and len(en_for(k)) > 12
                and not k.startswith(('bench.bn.', 'status.')))
    print(f'{lang}: {len(d)} keys · missing {len(missing)} · extra {len(extra)} · '
          f'placeholder-mismatch {len(ph_bad)} · markup-mismatch {len(tag_bad)} · '
          f'empty {len(empty)} · left-English(>12ch) {ident}')
    for name, lst in (('missing', sorted(missing)), ('extra', sorted(extra)),
                      ('ph', ph_bad), ('tags', tag_bad), ('empty', empty)):
        if lst:
            fail += 1
            print(f'  {name}: {lst[:12]}{" …" if len(lst) > 12 else ""}')
PH_BAD = {}
for lang, k, arm, want in placeholder_errors(ref, CATS, PAGES):
    PH_BAD.setdefault((lang, k, arm), []).append(want)
PH_ARM = {'B': 'must keep the literal(s)', 'C': 'must keep the token(s)'}
for (lang, k, arm), wants in PH_BAD.items():
    fail += 1
    print(f'  PARSED-PH {lang}.json {k}: arm {arm}, {PH_ARM[arm]} '
          f'{wants[0]!r}' if len(wants) == 1 else
          f'  PARSED-PH {lang}.json {k}: arm {arm}, {PH_ARM[arm]} {wants}')
    print(f'    got {CATS[lang][k]!r} - that input is PARSED (web/i18n/'
          'README.md "Strings that must stay English")')

# House copy rules, enforced (they were memory-and-sweep before, which
# is how two Cyrillic em-dashes and a 28-locale "streaming app" string
# shipped): no em-dash anywhere; no "streaming"/"media server"/"wall
# time" in user-facing values ("in-stream" as a pipeline-stage modifier
# is exempt; key NAMES are not user-facing).
BANNED = re.compile(
    r'\u2014'
    r'|(?<!in-)\bstream(?:ing|ovac\u00ed|ovac\u00ed)?\b'
    r'|\bmedia server\b|\bwall time\b'
    r'|\u0441\u0442\u0440\u0438\u043c\u0438\u043d\u0433'  # cyrillic "striming"
    r'|\u30b9\u30c8\u30ea\u30fc\u30df\u30f3\u30b0',        # katakana "sutoriimingu"
    re.IGNORECASE)
ALLOW_VALUE = ('in-stream', 'in the stream')
for fp in sorted(glob.glob('web/i18n/*.json')):
    d = json.load(open(fp, encoding='utf-8'))
    fname = os.path.basename(fp)
    for k, v in d.items():
        if not isinstance(v, str):
            continue
        hit = BANNED.search(v)
        if hit and not any(a in v.lower() for a in ALLOW_VALUE):
            fail += 1
            print(f'  BANNED-COPY {fname} {k}: {hit.group(0)!r} in {v[:60]!r}')

err = order_error(list(ref), sorted(ref), 'en.reference.json', 'code-point')
if err:
    fail += 1; print(f'  ORDER {err}')

sys.exit(1 if fail else 0)
