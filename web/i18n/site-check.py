#!/usr/bin/env python3
"""Structural parity for the localized website pages vs their English base:
identical id= sets, tag counts, byte-identical <code> content, lang attr, a
full NAV census of the picker and the hreflang block, and (on the pages that
cite a measurement) an ANONYMITY grep for leaked city and provider names. Run
BEFORE the cross-link rewrite (structure only).

TWO DIMENSIONS, AND ONE OF THEM IS SILENT. The parity half is ordinary
translation hygiene and it fails loudly the moment a locale drifts: an id
only English has, a <li> that did not survive the translation, a <code> ref
somebody localized. You find out because the page you just touched goes red.

The ANONYMITY half is different in kind. `website/` is published to
gh-pages, so a bench box's city or a provider's name left in one of these
pages is not a typo, it is a disclosure, and it is a disclosure that a
`git revert` does not take back. That arm fires on NOTHING today - which is
precisely what a BROKEN one looks like. A mistyped alternation, a `\\b`
against a name that starts with punctuation, a lost re.I, an accidental
`re.escape` of the whole list: every one of those reads exactly like a clean
tree, forever, and the day it matters is the day it was already wrong.

That is what `--selftest` is for here, and why the ban half of it is not a
spot check. BANNED below is a LIST of (fragment, sample) pairs and BAN is
built from it, so the selftest can drive every entry at a sample of its own.
Adding a name without a sample, or deleting one, is a failing selftest and
not a quiet pass. Do NOT collapse BANNED back into a literal regex: the
single-source list is the only thing standing between this arm and a rubber
stamp.

PRESENT IS NOT THE SAME AS COMPLETE. Until 23 Aug 2026 the nav half of this
script asked only whether the strings `langsw` and `hreflang` appeared
anywhere in the page. That floor is what let all 75 localized `explained*`
pages ship with `hreflang="en"` and `hreflang="x-default"` pointing back at
the localized page - the right seventeen entries with two of the hrefs wrong,
so a census by COUNT would not have seen it either. Twelve days on gh-pages,
on six families no generator has ever touched, with every gate green. The nav
arms now hold the picker's targets and its `selected` option, and the
hreflang block's (hreflang, target) PAIRS, to the family's full locale set -
see `nav_problems`. This is the invariant nav-regen.py cannot carry: its
website picker arm is inert (its docstring says why) and it is not a CI gate,
so it went here, where all ten families already are.

BOTH SIDES ARE SCANNED. The anonymity grep runs on the ENGLISH base page as
well as on the 15 translations. A leak enters through the page somebody
WROTE, and the English one ships to gh-pages exactly as the translations do;
scanning only the translations would have caught the copy of a leak and not
the original. Verified 23 Aug 2026: all six English pages that carry the arm
are clean, so this costs nothing today and closes the hole that matters.

WHAT IS DELIBERATELY NOT SCANNED. <code>, <pre>, <script> and <style> bodies
are blanked before the grep. A worked example may legitimately carry a
hostname-shaped token, and the parity arm already holds every <code> body
byte-identical between English and each translation, so a name that reached
a code block reached it in English first and is a review question rather
than a translation defect. Attributes ARE scanned: `title=`, `alt=` and
`href=` publish just as loudly as prose does.

NO BASELINE. Verified 23 Aug 2026: 150 localized pages plus all ten English
bases, all OK, exit 0 - the ten because the nav census runs on an English
base too, where the six-base anonymity grep alone used to. Do not add a baseline to silence a
hit. A parity hit is missing copy - translate it. An anonymity hit is a
disclosure - de-anonymize the sentence. Neither is fixed by deleting the
English element or by dropping the entry from BANNED.

A PAGE NOBODY DECLARED IS THE THIRD FAILURE OF THIS DIRECTORY. Both of the
drifts above are the same shape twice: a page family that shipped without
anybody putting it on a list. `indexer` shipped 15 locales and "was never
listed" here, so all 15 translations were missing the #limits section for
weeks (found by hand, 9cc729700). The five `explained*` families landed
hand-made and no generator ever touched them, which is how the x-default
defect above got twelve days on gh-pages. Nothing reported either one,
because every script in this directory walks its own BASES and the pages
outside it are not skipped so much as never seen - nav-regen.py globs
`website/*.html` and then FILTERS on BASES, so it walks past an undeclared
family in silence, and its own tree assert only judges bases that already
have a localized sibling. `roster_problems` closes that from the other end:
the glob is the population and BASES is held to it, so a base in neither
BASES nor ENGLISH_ONLY fails the run BY NAME. Measured 23 Aug 2026,
website/ holds twelve bases - the ten families and synology.html and
unraid.html, which carry no picker, no hreflang block and no localized
sibling, and are the reason ENGLISH_ONLY exists rather than being a hole.

A ROSTER HIT IS FIXED BY DECLARING THE PAGE, on one of the two lists,
deliberately. Never by narrowing the glob to exclude it, and never by
declaring a translated family English-only to quieten it - that is the one
edit that would silently drop 16 pages out of the parity half, and it is
refused: an ENGLISH_ONLY entry with a localized sibling on disk is itself a
red. The expected set is the two hand-written lists and is NEVER derived
from the glob it validates; a roster that reads its own subject is the
rubber stamp the whole family of gates keeps growing to refuse (nav-regen's
picker arm reported 64 pages current for weeks while matching none of them).

House gate conventions: `--selftest` runs the fixture cases below and is the
first thing to run if this script ever reads suspiciously quiet; no build,
no toolchain, about a third of a second for the full run. CI's NINETEENTH
gate since 23 Aug 2026 - `size-gate.yml` on every branch, and a step of
ci-private's `i18n-gate` beside its two siblings. This script lives in
web/i18n/ beside check.py and manual-check.py rather than in tools/ because
it is part of the translation workflow documented in web/i18n/README.md.

    python3 web/i18n/site-check.py --selftest
    python3 web/i18n/site-check.py
"""

import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

LANGS = ['fr', 'de', 'it', 'es', 'nl', 'pt', 'sv', 'da', 'nb', 'fi', 'tr', 'ro',
         'he', 'ar', 'fa']
# Pinned for the same reason BANNED_EXPECTED is, and it guards a wider arm:
# the nav census below derives what a picker and an hreflang block must name
# FROM this list, so a locale dropped from here takes its own case with it and
# every page then passes a census one locale short of the set it ships. Raise
# it when a locale is added; lowering it is a claim that a locale has been
# withdrawn from the site, not a way to quieten a red run.
LANGS_EXPECTED = 15

# The tag census. Narrower than manual-check.py's, because these pages are
# hand-built marketing layout rather than one long document: <p> and <div>
# counts move legitimately when a translator re-wraps a hero paragraph, and
# failing on those trains the reader to wave the gate through. What is here
# is the structure that CARRIES something - a section, a table row, a
# heading, a link, a bullet.
TAGS = ['section', 'table', 'tr', 'h1', 'h2', 'h3', 'pre', 'a', 'span', 'li']

# (pattern fragment, a sample that must match it). One sample per fragment,
# driven by the selftest, so a fragment that stops matching is a FAILING
# selftest rather than a clean tree. See the docstring - this list is the
# whole defence of the arm that never fires.
BANNED = [
    ('Miami', 'Miami'),
    ('London', 'London'),
    ('Natasha', 'Natasha'),
    ('Amsterdam', 'Amsterdam'),
    ('Frankfurt', 'Frankfurt'),
    ('Ashburn', 'Ashburn'),
    ('Newark', 'Newark'),
    ('Eweka', 'Eweka'),
    ('Newshosting', 'Newshosting'),
    ('Usenetserver', 'UsenetServer'),
    ('Tweaknews', 'TweakNews'),
    ('XS ?News', 'XSNews'),
    ('Giganews', 'Giganews'),
]
BAN = re.compile(r'\b(' + '|'.join(f for f, _ in BANNED) + r')\b', re.I)
# The roster is pinned by COUNT as well as driven entry-by-entry in the
# selftest, because a single-source list has exactly one hole: deleting an
# entry deletes its test along with it, silently, and the arm then reads as
# clean for one more name than it covers. Changing this number is a
# deliberate act on the record. Raise it when you add a name; think hard
# before lowering it, because a name leaves this list only when it has
# stopped being private, never because a page tripped over it.
BANNED_EXPECTED = 13


def ids(s):
    return sorted(re.findall(r'\bid="([^"]+)"', s))


def tagc(s, t):
    return len(re.findall(rf'<{t}\b', s))


def codes(s):
    return re.findall(r'<code[^>]*>(.*?)</code>', s, re.S)


def prose(s):
    """The page with <script>/<style>/<code>/<pre> bodies removed - what is
    left is visible copy plus the attributes around it, which is what the
    anonymity grep judges. See the docstring for why those four are out."""
    return re.sub(r'<(script|style|code|pre)[^>]*>.*?</\1>', '', s, flags=re.S)


def ban_hits(s):
    return sorted(set(m.group(0) for m in BAN.finditer(prose(s))))


def picker(s):
    """The langsw element's targets, and whichever one it marks selected.

    Both shapes are read. The pages carry a `<select class="langsw">` whose
    options hold `value="index.fr.html"`; the generator that was supposed to
    write them still emits a `<span class="langsw">` of anchors, which is the
    drift that left its picker arm inert (see nav-regen.py's docstring). This
    census judges the markup that is THERE, so it keeps working whichever of
    the two the site settles on. `None, None` means no picker at all; a span
    reports `None` for the selection, since anchors cannot carry one.
    """
    m = re.search(r'<select class="langsw".*?</select>', s, re.S)
    if m:
        return (re.findall(r'<option value="([^"]*)"', m.group(0)),
                re.findall(r'<option value="([^"]*)"[^>]*\sselected[^>]*>', m.group(0)))
    m = re.search(r'<span class="langsw".*?</span>', s, re.S)
    if m:
        return re.findall(r'href="([^"]*)"', m.group(0)), None
    return None, None


def alternates(s):
    return [(h, os.path.basename(u)) for h, u in
            re.findall(r'<link rel="alternate"[^>]*hreflang="([^"]+)"'
                       r'[^>]*href="([^"]*)"', s)]


def nav_problems(s, base, lang):
    """Hold one page's picker and hreflang block to the FULL locale set of its
    own family. Present-and-plausible is not the same as complete: this script
    asked only whether the strings `langsw` and `hreflang` appeared anywhere in
    the page until 23 Aug 2026, and under that floor all 75 localized
    `explained*` pages shipped with `hreflang="en"` AND `hreflang="x-default"`
    pointing at the localized page itself - telling a crawler that the English
    edition of the French page IS the French page, and that the fallback for
    every unmatched language is French. Twelve days on gh-pages, on a family no
    generator has ever touched, with every gate green. Counts alone would not
    have seen it either: those blocks carried the right SEVENTEEN entries with
    two of the hrefs wrong, so the census is of (hreflang, target) pairs.

    Pure over the page text plus its family and locale, so the selftest drives
    it on fixtures. `lang='en'` judges an English base, whose own entry is the
    bare filename."""
    probs = []
    me = f'{base}.html' if lang == 'en' else f'{base}.{lang}.html'

    want = [f'{base}.html'] + [f'{base}.{l}.html' for l in LANGS]
    targets, selected = picker(s)
    if targets is None:
        probs.append('picker missing')
    else:
        got = [os.path.basename(t) for t in targets]
        if got != want:
            missing = [w for w in want if w not in got]
            extra = [g for g in got if g not in want]
            probs.append(f'picker names {len(got)} of this family\'s {len(want)} '
                         f'pages: missing={missing} unexpected={extra}'
                         if (missing or extra) else
                         f'picker names the right {len(want)} pages out of order')
        if selected is not None and selected != [me]:
            probs.append(f'picker marks {selected or "nothing"} selected, not {me}')

    want_alt = ([('en', f'{base}.html')]
                + [(l, f'{base}.{l}.html') for l in LANGS]
                + [('x-default', f'{base}.html')])
    got_alt = alternates(s)
    if not got_alt:
        probs.append('hreflang missing')
    elif got_alt != want_alt:
        missing = [f'{h}->{u}' for h, u in want_alt if (h, u) not in got_alt]
        extra = [f'{h}->{u}' for h, u in got_alt if (h, u) not in want_alt]
        probs.append(f'hreflang block is not this family\'s {len(want_alt)}: '
                     f'missing={missing} unexpected={extra}'
                     if (missing or extra) else
                     f'hreflang block names the right {len(want_alt)} out of order')
    return probs


def analyse(en, tr, lang, anon=False, base='x'):
    """Return the list of problems with one translated page. Empty list = OK.
    Pure: takes the two documents as strings, reads no files, so the selftest
    below can drive it on fixtures."""
    probs = []
    if ids(en) != ids(tr):
        probs.append(f'id mismatch only-en={set(ids(en))-set(ids(tr))} '
                     f'only-tr={set(ids(tr))-set(ids(en))}')
    for t in TAGS:
        if tagc(en, t) != tagc(tr, t):
            probs.append(f'<{t}> {tagc(en,t)} vs {tagc(tr,t)}')
    if codes(en) != codes(tr):
        probs.append(f'<code> content differs ({len(codes(en))} vs {len(codes(tr))})')
    if f'lang="{lang}"' not in tr:
        probs.append(f'missing lang="{lang}"')
    probs += nav_problems(tr, base, lang)
    if anon:
        hits = ban_hits(tr)
        if hits:
            probs.append(f'ANONYMITY LEAK: {hits}')
    return probs


def report(path, probs):
    print(f'{path}: {"OK" if not probs else "PROBLEMS"}')
    for p in probs:
        print('   -', p)
    return bool(probs)


def check(en_rel, tr_rel, lang, base, anon=False):
    with open(os.path.join(ROOT, en_rel), encoding='utf-8') as f:
        en = f.read()
    with open(os.path.join(ROOT, tr_rel), encoding='utf-8') as f:
        tr = f.read()
    return report(tr_rel, analyse(en, tr, lang, anon=anon, base=base))


def check_english(en_rel, base, anon):
    """The arms that do not need a comparison, on the English base itself.
    There is nothing to hold it against - it IS the base - so the parity half
    is out and two things are left: the anonymity grep, on the families that
    cite a measurement, and the nav census, on all ten. The nav half runs
    everywhere because an English base carries the same picker and the same
    hreflang block as its translations and is just as capable of losing a
    locale from either; leaving the ten bases out would have gated 150 pages
    against a set of ten nobody was checking."""
    with open(os.path.join(ROOT, en_rel), encoding='utf-8') as f:
        en = f.read()
    probs = nav_problems(en, base, 'en')
    if anon:
        hits = ban_hits(en)
        if hits:
            probs.append(f'ANONYMITY LEAK: {hits}')
    return report(en_rel, probs)


# `indexer` shipped 15 locales but was never listed here, and the whole
# `explained` family landed English-first; an ungated family is one that
# drifts silently, which is the failure this script exists to prevent.
BASES = ['index', 'features', 'download', 'benchmarks', 'indexer',
         'explained', 'explained-onepass', 'explained-damaged',
         'explained-method', 'explained-numbers']
# The anonymity grep belongs on every page that cites a measurement, not just
# the benchmarks table: the Explained pages quote the same rounds in prose.
ANON = {'benchmarks', 'explained', 'explained-onepass', 'explained-damaged',
        'explained-method', 'explained-numbers'}

# The other half of the roster: pages that ship in English ONLY, each with the
# reason on the record. A page under website/ is one or the other, and a page
# that is neither is a red - see `roster_problems` and the docstring. This is
# a waiver list, so an entry is a claim somebody made on purpose, and the
# reason is what a later reader needs to overturn it.
ENGLISH_ONLY = {
    'synology': 'Container Manager install guide, added 22 Jul 2026 '
                '(df5ab151a) in English only. That commit localized the 15 '
                'download pages to LINK to it and never translated the page '
                'itself, so no `synology.<lang>.html` has ever existed. '
                'Whether it should become family 11 is a content decision, '
                'open as of 23 Aug 2026 and not taken; until it is, a reader '
                'on download.fr.html who clicks through lands on a page with '
                'no picker at all.',
    'unraid': 'Unraid install guide, added 30 Jul 2026 (304aa3200) the same '
              'way and under the same open question. Linked from the '
              'localized download pages and from the update panel: 30 bare '
              'English hrefs across 15 localized pages, against 15 for the '
              'Synology guide (measured 23 Aug 2026).',
}
# Pinned for the reason LANGS_EXPECTED and BANNED_EXPECTED are, and it covers
# the one roster edit the live run cannot see. Everything else here is
# self-checking against the tree: an undeclared page is found by the glob, and
# a family demoted into ENGLISH_ONLY is caught by its own localized siblings
# still being on disk. RETIRING a family is different - the entry and its 16
# pages go together, both lists get shorter, the glob agrees, and the run is
# green. The per-entry loop in the selftest cannot see it either, because a
# deleted entry deletes its own case. Raise this when a page family is added;
# lowering it is a claim that a family has been withdrawn from the site.
ROSTER_EXPECTED = 12


def page_bases(names):
    """Map website/*.html FILENAMES to {base: [locales on disk]}.

    Pure over a list of names rather than over the directory, so the selftest
    can drive it on fixtures instead of on the tree it exists to judge. A
    suffix that is not a known locale is NOT folded into its base - it becomes
    a base of its own, so `index.xx.html` is reported by name rather than
    silently counted as one more `index` page."""
    found = {}
    for n in names:
        if not n.endswith('.html') or n == '.html':
            continue
        stem = n[: -len('.html')]
        base, dot, suf = stem.rpartition('.')
        if dot and base and suf in LANGS:
            found.setdefault(base, []).append(suf)
        else:
            found.setdefault(stem, [])
    return found


def roster_problems(found, bases=None, english_only=None):
    """Hold the two hand-written rosters to the pages actually on disk.

    `found` is `page_bases`' mapping - the population, globbed and unfiltered.
    `bases`/`english_only` default to the module lists and are parameters only
    so the selftest can drive this on fixture rosters; they are NEVER derived
    from `found`, which is the whole point of the arm (see the docstring)."""
    bases = BASES if bases is None else bases
    english_only = ENGLISH_ONLY if english_only is None else english_only
    probs = []
    declared = set(bases) | set(english_only)

    for b in sorted(set(bases) & set(english_only)):
        probs.append(f'{b!r} is in BASES and in ENGLISH_ONLY - it is one or '
                     'the other')
    for b in sorted(found):
        if b not in declared:
            probs.append(
                f'website/{b}.html is a page nobody declared: put {b!r} in '
                'BASES (having translated the full locale set first) or in '
                'ENGLISH_ONLY with a reason. Do not narrow the glob.')
    for b in sorted(set(english_only) & set(found)):
        if found[b]:
            probs.append(
                f'{b!r} is declared English-only but ships '
                f'{len(found[b])} localized page(s) ({", ".join(sorted(found[b]))}) '
                '- move it to BASES so the parity and nav arms cover them')
    for b in sorted(english_only):
        if not str(english_only[b] or '').strip():
            probs.append(f'{b!r} is declared English-only with no reason - a '
                         'waiver nobody can overturn is not a waiver')
    for b in sorted(declared - set(found)):
        probs.append(f'{b!r} is declared but website/{b}.html is not on disk')
    return probs


# --- selftest ---------------------------------------------------------------

def fixture_picker(lang, base='x', drop=None, wrong_base=None, selects=None):
    """The picker the real pages carry: a `<select class="langsw">` naming the
    English base and all 15 locales, with the page's own option `selected`.
    The knobs are the defect shapes - `drop` loses one locale, `wrong_base`
    points every option at another family, `selects` marks the wrong one."""
    langs = [l for l in LANGS if l != drop]
    tb = wrong_base or base
    opts = [(f'{tb}.html', 'English', (selects or lang) == 'en')]
    opts += [(f'{tb}.{l}.html', l.upper(), l == (selects or lang)) for l in langs]
    return ('<select class="langsw" aria-label="Language">'
            + ''.join(f'<option value="{v}"{" selected" if sel else ""}>{n}</option>'
                      for v, n, sel in opts)
            + '</select>')


def fixture_alts(base='x', drop=None, en_self=None, xd_self=None):
    """The hreflang block the real pages carry. `en_self`/`xd_self` are the
    shape that actually shipped: the entry a crawler reads as "the English
    edition of this page" pointing back at the localized page itself."""
    out = [('en', en_self or f'{base}.html')]
    out += [(l, f'{base}.{l}.html') for l in LANGS if l != drop]
    out.append(('x-default', xd_self or f'{base}.html'))
    return '\n'.join(f'<link rel="alternate" hreflang="{h}" href="{u}">'
                      for h, u in out)


def page(lang, body, langsw=True, hreflang=True, base='x', picker_kw=None,
         alt_kw=None):
    """A minimal website page: a head carrying the hreflang alternates and a
    <style> the census must survive, an optional picker, then the body."""
    alt = (fixture_alts(base, **(alt_kw or {})) + '\n') if hreflang else ''
    # When the picker is "missing" the select is still there, only without its
    # langsw class. A fixture that deletes the element outright would be
    # caught by the <span>/<a> census instead, and the picker arm would then
    # be passing on somebody else's evidence.
    sw = fixture_picker(lang, base, **(picker_kw or {}))
    if not langsw:
        sw = sw.replace('class="langsw"', 'class="nav"', 1)
    return (f'<!doctype html>\n<html lang="{lang}">\n<head>'
            f'<style>a{{color:red}}</style>\n{alt}</head><body>\n'
            f'{sw}\n{body}\n</body></html>\n')


EN_BODY = """
<section id="speed">
<h1>Fast</h1>
<h2>How fast</h2>
<h3>On one connection</h3>
<p>See the <a href="benchmarks.html">numbers</a>, measured on a rented box.</p>
<ul>
<li>One pass over the wire.</li>
<li>No second read from disk.</li>
</ul>
<table><tr><td>Tool</td><td>GB/min</td></tr><tr><td>nzbfast</td><td><span class="num">9.1</span></td></tr></table>
<pre><code>nzbfast get file.nzb --host news.eweka.example</code></pre>
</section>
"""

FAITHFUL = (EN_BODY
            .replace('<h1>Fast</h1>', '<h1>Rapide</h1>')
            .replace('<li>One pass over the wire.</li>',
                     '<li>Un seul passage sur le r&eacute;seau.</li>'))

# The census roster the selftest drives, frozen here rather than read out of
# TAGS. Dropping a tag from TAGS is the one edit that narrows this gate
# without any page changing, and a loop over TAGS cannot see it because the
# missing tag takes its own case with it. Removing an entry here is a claim
# that a translator may legitimately lose that element - a claim about the
# copy, not about the script - so make it deliberately or not at all.
CENSUS_ROSTER = ['section', 'table', 'tr', 'h1', 'h2', 'h3', 'pre', 'a',
                 'span', 'li']

# (name, want_problem, translated body, kwargs for page(), anon)
SELFTEST = [
    ('a faithful translation', False, FAITHFUL, {}, False),
    # The parity arms, one shape each. Every one of these is a translation
    # that lost something the English page carries.
    ('an id lost', True, FAITHFUL.replace(' id="speed"', ''), {}, False),
    ('an id invented', True,
     FAITHFUL.replace('<h2>How fast</h2>', '<h2 id="extra">How fast</h2>'), {}, False),
    ('a <li> bullet condensed away', True,
     FAITHFUL.replace('<li>No second read from disk.</li>\n', ''), {}, False),
    ('a table row dropped', True,
     FAITHFUL.replace('<tr><td>nzbfast</td><td><span class="num">9.1</span></td></tr>', ''), {}, False),
    ('a link dropped', True,
     FAITHFUL.replace('<a href="benchmarks.html">numbers</a>', 'les chiffres'),
     {}, False),
    ('a <code> body translated', True,
     FAITHFUL.replace('nzbfast get', 'nzbfast obtenir'), {}, False),
    ('the lang attribute missing', True, FAITHFUL, {'lang_is_en': True}, False),
    ('the picker lost its langsw class', True, FAITHFUL,
     {'langsw': False}, False),
    ('the hreflang alternates missing', True, FAITHFUL, {'hreflang': False}, False),
    # The anonymity arm. This is the half whose failure mode is silence, so
    # it is pinned from four directions: it fires in prose, it fires in an
    # attribute, it is case-insensitive, and it is SCOPED - a page that does
    # not cite a measurement is not scanned, and a code block is exempt on
    # purpose (see the docstring).
    ('a city name in visible prose, on a measured page', True,
     FAITHFUL.replace('a rented box', 'a rented box in Frankfurt'), {}, True),
    ('the same page, not a measured one', False,
     FAITHFUL.replace('a rented box', 'a rented box in Frankfurt'), {}, False),
    ('a provider name in an attribute', True,
     FAITHFUL.replace('<a href="benchmarks.html">',
                      '<a href="benchmarks.html" title="vs Newshosting">'), {}, True),
    ('a banned name in lower case', True,
     FAITHFUL.replace('a rented box', 'a rented box in miami'), {}, True),
    # EN_BODY's worked example carries a provider name on purpose. A faithful
    # translation of it must stay silent under the anonymity arm...
    ('a banned name inside <code> is exempt', False, FAITHFUL, {}, True),
    # ...and the SAME name one element out, in prose, must not be.
    ('the same name a line further out, in prose', True,
     FAITHFUL.replace('a rented box', 'a rented box at news.eweka.example'),
     {}, True),
    # A name that merely CONTAINS a banned one is not a hit: `\b` on both
    # ends is what keeps this arm quiet enough to be read, and each anchor
    # gets its own case because losing one of the two is invisible from the
    # other side. The trade is stated rather than hidden - a leak spelled as
    # one word with a city glued onto it walks through, and that is the
    # price of an arm nobody switches off.
    ('a longer word STARTING with a banned one', False,
     FAITHFUL.replace('a rented box', 'a rented Londonderry box'), {}, True),
    ('a longer word ENDING with a banned one', False,
     FAITHFUL.replace('a rented box', 'a rented box in NewLondon'), {}, True),
    # The NAV census. Present-and-plausible was the whole floor until 23 Aug
    # 2026, and the first four of these are the shapes that floor waved
    # through. The second of them is not hypothetical: it is what all 75
    # localized `explained*` pages actually shipped, for twelve days on
    # gh-pages, with every gate green.
    ('a picker one locale short', True, FAITHFUL,
     {'picker_kw': {'drop': 'ro'}}, False),
    ('hreflang="en" pointing back at the localized page', True, FAITHFUL,
     {'alt_kw': {'en_self': 'x.fr.html'}}, False),
    ('x-default pointing back at the localized page', True, FAITHFUL,
     {'alt_kw': {'xd_self': 'x.fr.html'}}, False),
    ('an hreflang block one locale short', True, FAITHFUL,
     {'alt_kw': {'drop': 'ro'}}, False),
    # A picker copied from the family next door: every option resolves, every
    # count is right, and every one of them walks the reader off this page.
    ('a picker pointing at another family', True, FAITHFUL,
     {'picker_kw': {'wrong_base': 'y'}}, False),
    ('a picker marking the wrong locale selected', True, FAITHFUL,
     {'picker_kw': {'selects': 'de'}}, False),
]


def selftest():
    en = page('en', EN_BODY)
    bad = 0
    cases = 0

    for name, want, body, kw, anon in SELFTEST:
        kw = dict(kw)
        lang = 'en' if kw.pop('lang_is_en', False) else 'fr'
        tr = page(lang, body, **kw)
        got = bool(analyse(en, tr, 'fr', anon=anon))
        cases += 1
        if got != want:
            print(f'  selftest FAIL: {name}: problem={got} (want {want})',
                  file=sys.stderr)
            for x in analyse(en, tr, 'fr', anon=anon):
                print('      ', x, file=sys.stderr)
            bad += 1

    # Every census tag, at a case of its own, driven from CENSUS_ROSTER
    # rather than from TAGS. The hand-written shapes above cover the ones a
    # translator actually loses, but they leave most of the census resting
    # on the assumption that the loop reads the list - and a loop over TAGS
    # would take its own test away with any tag dropped from TAGS, which is
    # the one edit that silently narrows this gate. Renaming one opening tag
    # is the smallest edit that moves exactly one count and nothing else:
    # class attributes, ids and <code> bodies all survive it, so a failure
    # here can only have come from the census.
    for t in sorted(set(TAGS) - set(CENSUS_ROSTER)):
        cases += 1
        print(f'  selftest FAIL: <{t}> is censused but has no roster case - '
              'add it to CENSUS_ROSTER and give the fixture body one',
              file=sys.stderr)
        bad += 1
    for t in CENSUS_ROSTER:
        cases += 1
        tr = page('fr', FAITHFUL.replace(f'<{t}', f'<x-{t}', 1))
        if not analyse(en, tr, 'fr'):
            print(f'  selftest FAIL: a missing <{t}> passes the census - '
                  f'either it left TAGS or the fixture no longer has one',
                  file=sys.stderr)
            bad += 1

    # Every ban entry, at a sample of its own. An entry with no sample, or a
    # sample its own fragment cannot match, is the rubber-stamp failure this
    # whole selftest exists to refuse.
    for frag, sample in BANNED:
        cases += 1
        if not BAN.fullmatch(sample):
            print(f'  selftest FAIL: ban entry {frag!r} does not match its own '
                  f'sample {sample!r}', file=sys.stderr)
            bad += 1
            continue
        tr = page('fr', FAITHFUL.replace('a rented box', f'a box in {sample}'))
        if not analyse(en, tr, 'fr', anon=True):
            print(f'  selftest FAIL: {sample!r} passes the anonymity grep',
                  file=sys.stderr)
            bad += 1
    cases += 1
    if len(BANNED) != BANNED_EXPECTED:
        print(f'  selftest FAIL: the ban roster is {len(BANNED)} entries, '
              f'BANNED_EXPECTED says {BANNED_EXPECTED}. A name was added or '
              'removed; the loop above only tests the entries that are still '
              'there, so this line is the only thing that can see a deletion.',
              file=sys.stderr)
        bad += 1
    # The optional-space spelling of the two-word provider, which the sample
    # above cannot cover from one side.
    cases += 1
    if not (BAN.fullmatch('XS News') and BAN.fullmatch('XSNews')):
        print('  selftest FAIL: the two-word provider is matched in only one '
              'of its two spellings', file=sys.stderr)
        bad += 1

    # Every locale, at a case of its own, on BOTH halves of the nav census.
    # The shapes above drop one locale each and that is enough to prove the
    # comparison runs - but the set it compares against is derived from LANGS,
    # so a locale deleted from LANGS deletes its own case and leaves a census
    # that passes every page at fourteen. This loop plus the pin below is what
    # holds the arm at the set the site actually ships.
    for l in LANGS:
        cases += 2
        if not analyse(en, page('fr', FAITHFUL, picker_kw={'drop': l}), 'fr'):
            print(f'  selftest FAIL: a picker missing {l!r} passes the census',
                  file=sys.stderr)
            bad += 1
        if not analyse(en, page('fr', FAITHFUL, alt_kw={'drop': l}), 'fr'):
            print(f'  selftest FAIL: an hreflang block missing {l!r} passes '
                  'the census', file=sys.stderr)
            bad += 1
    cases += 1
    if len(LANGS) != LANGS_EXPECTED:
        print(f'  selftest FAIL: LANGS is {len(LANGS)} locales, LANGS_EXPECTED '
              f'says {LANGS_EXPECTED}. The nav census derives what every '
              'picker and hreflang block must name from LANGS, so a deletion '
              'there silently narrows the gate on all 160 pages at once; the '
              'loop above only tests the locales that are still in the list.',
              file=sys.stderr)
        bad += 1

    # An ENGLISH base goes through nav_problems directly rather than through
    # analyse, and its own entry is the bare filename - so it needs its own
    # case, or the ten bases ride on the translations' evidence.
    cases += 2
    if nav_problems(page('en', FAITHFUL), 'x', 'en'):
        print('  selftest FAIL: a correct English base fails the nav census',
              file=sys.stderr)
        bad += 1
    if not nav_problems(page('en', FAITHFUL, picker_kw={'selects': 'fr'}),
                        'x', 'en'):
        print('  selftest FAIL: an English base whose picker marks a '
              'translation selected passes the nav census', file=sys.stderr)
        bad += 1

    # The ROSTER arm, on fixture rosters. `roster_problems` takes both lists
    # as parameters precisely so these cases never touch the real website/ -
    # an arm that derived its expectations from the directory it judges would
    # pass every tree ever written.
    FIX_BASES = ('alpha', 'beta')
    FIX_ENGLISH = {'gamma': 'a fixture reason'}
    FIX_NAMES = (['alpha.html', 'beta.html', 'gamma.html']
                 + [f'alpha.{l}.html' for l in LANGS]
                 + [f'beta.{l}.html' for l in LANGS])

    def rp(names, bases=FIX_BASES, eo=FIX_ENGLISH):
        return roster_problems(page_bases(names), bases, eo)

    # (name, want_problem, a base the message must NAME or None, the call)
    roster_cases = [
        ('a fully declared roster', False, None, lambda: rp(FIX_NAMES)),
        # The shape this arm exists for: a page family lands and nobody puts
        # it on a list. Both of this directory's known drifts were this.
        ('an undeclared page', True, 'delta',
         lambda: rp(FIX_NAMES + ['delta.html'])),
        ('an undeclared FAMILY, locales and all', True, 'delta',
         lambda: rp(FIX_NAMES + ['delta.html']
                    + [f'delta.{l}.html' for l in LANGS])),
        # A base dropped from BASES is exactly as invisible as one that was
        # never added, so it is the same red and it names the base.
        ('a base dropped from BASES', True, 'beta',
         lambda: rp(FIX_NAMES, bases=('alpha',))),
        # The demotion that would quietly drop 16 pages out of the parity
        # half. Its localized siblings are still on disk, so it is refused.
        ('a family demoted into ENGLISH_ONLY', True, 'beta',
         lambda: rp(FIX_NAMES, bases=('alpha',),
                    eo=dict(FIX_ENGLISH, beta='quiet please'))),
        ('an English-only page that grew a translation', True, 'gamma',
         lambda: rp(FIX_NAMES + ['gamma.fr.html'])),
        ('an English-only entry with no reason', True, 'gamma',
         lambda: rp(FIX_NAMES, eo={'gamma': ''})),
        ('an English-only entry whose reason is blank space', True, 'gamma',
         lambda: rp(FIX_NAMES, eo={'gamma': '   '})),
        ('a base on both lists', True, 'gamma',
         lambda: rp(FIX_NAMES, bases=FIX_BASES + ('gamma',))),
        ('a declared page that is not on disk', True, 'gamma',
         lambda: rp([n for n in FIX_NAMES if n != 'gamma.html'])),
    ]
    for name, want, names_it, call in roster_cases:
        cases += 1
        probs = call()
        if bool(probs) != want:
            print(f'  selftest FAIL: roster: {name}: problem={bool(probs)} '
                  f'(want {want})', file=sys.stderr)
            for x in probs:
                print('      ', x, file=sys.stderr)
            bad += 1
        elif names_it and not any(names_it in x for x in probs):
            print(f'  selftest FAIL: roster: {name}: went red without naming '
                  f'{names_it!r} - a roster hit that does not say which page '
                  'cannot be acted on', file=sys.stderr)
            bad += 1

    # Filename -> base, including the shape that must NOT be folded away.
    cases += 1
    if page_bases(['index.html', 'index.fr.html', 'synology.html']) != {
            'index': ['fr'], 'synology': []}:
        print('  selftest FAIL: roster: page_bases does not split a locale '
              'suffix off its base', file=sys.stderr)
        bad += 1
    cases += 1
    if page_bases(['index.xx.html']) != {'index.xx': []}:
        print('  selftest FAIL: roster: an unknown locale suffix is folded '
              'into its base, so a stray page would never be named',
              file=sys.stderr)
        bad += 1

    # Every real roster entry, at a case of its own: dropping it must go red
    # AND name it. The rest of the roster is left declared, so nothing else
    # can be supplying the red.
    real_found = {b: list(LANGS) for b in BASES}
    real_found.update({b: [] for b in ENGLISH_ONLY})
    for b in list(BASES) + sorted(ENGLISH_ONLY):
        cases += 1
        probs = roster_problems(
            real_found,
            tuple(x for x in BASES if x != b),
            {k: v for k, v in ENGLISH_ONLY.items() if k != b})
        if not any(b in x for x in probs):
            print(f'  selftest FAIL: roster: dropping {b!r} from the roster '
                  'passes, or goes red without naming it', file=sys.stderr)
            bad += 1
    cases += 1
    if len(BASES) + len(ENGLISH_ONLY) != ROSTER_EXPECTED:
        print(f'  selftest FAIL: the roster is '
              f'{len(BASES) + len(ENGLISH_ONLY)} bases, ROSTER_EXPECTED says '
              f'{ROSTER_EXPECTED}. A page family was added or RETIRED; the '
              'loop above only tests the entries that are still there, and a '
              'retirement takes its pages with it, so the live run agrees and '
              'this line is the only thing that can see it.', file=sys.stderr)
        bad += 1

    if bad:
        print(f'\nsite-check: {bad} selftest case(s) failed - this script is '
              'not doing its job, and its anonymity arm fails SILENTLY.',
              file=sys.stderr)
        return 1
    print(f'site-check: selftest ok ({cases} cases, {len(TAGS)} tags, '
          f'{len(BANNED)} ban entries, {len(LANGS)} locales, '
          f'{len(BASES) + len(ENGLISH_ONLY)} bases)')
    return 0


def main():
    if '--selftest' in sys.argv:
        return selftest()
    # The glob is the POPULATION and it is not filtered by BASES - filtering
    # here is how the other scripts in this directory walk past an undeclared
    # family in silence. Run first, so a base listed but missing from disk is
    # a named red rather than a traceback out of the loop below.
    found = page_bases(sorted(os.path.basename(x) for x in
                              glob.glob(os.path.join(ROOT, 'website', '*.html'))))
    roster = roster_problems(found)
    report('website/ roster', roster)

    fail = 0
    for base in BASES:
        if base not in found:
            continue          # already named by the roster arm above
        anon = base in ANON
        fail += check_english(f'website/{base}.html', base, anon)
        for l in LANGS:
            fail += check(f'website/{base}.html', f'website/{base}.{l}.html',
                          l, base, anon=anon)
    sys.stdout.flush()
    if roster:
        print(f'\nsite-check: {len(roster)} problem(s) with the website/ '
              'roster. Every page under website/ is either a translated '
              'family in BASES or a deliberately English-only page in '
              'ENGLISH_ONLY with a reason; a page in neither is one nothing '
              'checks, which is how `indexer` and the `explained*` family '
              'each drifted. Declare it on the list it belongs on - never by '
              'narrowing the glob, and never by calling a translated family '
              'English-only.', file=sys.stderr)
    if fail:
        print(f'\nsite-check: {fail} page(s) differ structurally from their '
              'English base, name an incomplete locale set in a picker or an '
              'hreflang block, or carry a name that must not be published. '
              'Translate the missing element where it belongs, put the missing '
              'locale back in the nav, or de-anonymize the sentence; do not '
              'delete the English element, do not shorten LANGS, and do not '
              'drop the entry from BANNED.', file=sys.stderr)
    return 1 if (fail or roster) else 0


if __name__ == '__main__':
    sys.exit(main())
