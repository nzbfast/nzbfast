#!/usr/bin/env python3
"""Structural parity for the localized website pages vs their English base:
identical id= sets, tag counts, byte-identical <code> content, lang attr, a
full NAV census of the picker and the hreflang block, a BY-VALUE comparison of
every figure in every table cell, and (on the pages that cite a measurement) an
ANONYMITY grep for leaked city and provider names. Run BEFORE the cross-link
rewrite (structure only).

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

THE NUMBERS WERE THE HOLE, AND THEY ARE THE CONTENT. Everything above is
structure: a translation could move a decimal point through every one of those
arms untouched, and on a benchmarks page the figures ARE the claim. Three
lanes localizing number formatting on their own initiative - two of them
reporting in their own summaries that they had NOT - shipped one file holding
`2.444`, `2,444` and `1.515` at once, all green here. `number_problems` is the
arm that closes it, with the reasoning and the stated limit at its own site.

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
import html
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


# --- number parity ----------------------------------------------------------
#
# THE NUMBERS ARE THE CONTENT. On a benchmarks page every claim the reader can
# check is a figure in a table cell, and until 25 Aug 2026 nothing in this
# directory looked at a single one of them: the arms above hold ids, tag
# counts, <code> bodies, the lang attribute and the nav census, and a
# translation could move a decimal point through all of them untouched.
#
# It was not hypothetical. The project decided on 25 Aug 2026 that translated pages
# carry numbers in FULL LOCAL CONVENTION, because an English "2,444
# CPU-seconds" left in a comma-decimal locale reads as two-point-four-four-four
# seconds - a 1000x misreading of a headline figure, in the one place on the
# site where a wrong number is indistinguishable from a lie. Three translating
# lanes then localized on their own initiative, TWO OF THEM REPORTING IN THEIR
# OWN SUMMARIES THAT THEY HAD NOT, and one (tr) did it to the prose only. That
# file held `2.444` (Turkish thousands), `2,444` (English thousands) and
# `1.515` (English decimal) at once, so the single pattern `\d{1,3}\.\d{3}`
# meant two different numbers in one document. All three passed this script
# green.
#
# WHAT IS COMPARED, and why it is a VALUE and not a string. The population is
# the numeric table cells - `<td>`/`<th>` whose English text is a figure rather
# than a sentence - taken in document order and compared BY INDEX. Every
# numeric token in the cell is parsed on each side under that side's own
# convention and the FLOATS are compared, so `1,814` and `1.814` and `1 814`
# are all the same measurement and `13.9` against `13.97` is not. A string
# comparison would call the correct localization a defect and would call a
# transposed digit a match.
#
# THE CONVENTION IS DETECTED PER PAGE, NOT ASSERTED FROM THE LOCALE, and this
# is the one design decision worth reading twice. Judging every twin strictly
# under its locale's convention is what the decision wants and is NOT what this
# arm can do today: the twelve comma-locale benchmark pages on main are
# half-localized right now (measured 25 Aug 2026 - benchmarks.de.html carries
# 14 local decimals in its prose and 27 English thousands groups), so a strict
# arm would land red for every lane on the tree. What this arm asserts instead
# is the property that actually protects the reader: the page must mean the
# same numbers as the English base under ONE convention, its own or English,
# consistently. A page half-converted in its TABLES - which is what the tr
# incident produced and what a hand-punctuating translator produces - fits
# NEITHER and is refused. A value that moved fits neither either, whatever the
# punctuation.
#
# PROSE IS IN SCOPE SINCE 25 Aug 2026, and it was the larger half. This arm
# read TABLE CELLS only for its first day, on the stated ground that main's
# twins were half-converted and a wider arm would have landed red for every
# lane. Both halves of that were then done: `ec2b8b44a` re-cut all fifteen
# twins, `39a8ae80b` fixed the 232 figures the cell arm found still English in
# them, and 335 more were converted in the sentences AROUND those tables - the
# population nothing had ever looked at. What was live there is the argument
# for the whole widening: benchmarks.fr.html said "une E/S disque mesuree de
# 1,00-1.03x", both conventions inside ONE range, in one sentence, three
# characters apart, and a French reader took two different meanings from two
# numbers written three characters apart. `1,10-1.20x` said it again a
# paragraph later.
#
# The prose half is compared BY SHAPE and the cell half BY VALUE. That is not
# an inconsistency, it is the only comparison a sentence supports - the
# reasoning, the three measured false-positive shapes it avoids, and the value
# arm that was built and rejected are all at `prose_problems`.
#
# THE STATED LIMIT, rather than left to be discovered: the convention is still
# DETECTED per page rather than asserted from the locale. A page written
# consistently in English convention still passes, and 100 of the 150 are -
# `download`, `indexer` and the five `explained*` families are one convention
# or the other throughout. Tightening this to the locale outright is the next
# step and it is a CONTENT decision, not a code one: whether the 25 Aug ruling
# reaches past the benchmarks family is a question nobody has put to the
# project yet, and asserting it unasked would land red on 100 pages that no
# decision covers. When that
# answer comes, the tightening is deleting the second candidate below - the
# tree is now converted far enough that nothing else has to move first.
#
# Do not widen either half by loosening something here.
#
# There is NO baseline, deliberately: an entry would be a claim that some
# specific figure is fine to have wrong, which is never true of a number on a
# benchmarks page.

# (decimal separator, thousands separator) per locale. This table is the new
# configuration the arm needs and it lives HERE, next to the code that reads
# it, rather than in a comment somewhere else - the set was first written down
# in a one-off converter that no longer exists.
#
# he/ar/fa are English-shaped ON PURPOSE and are not an oversight: written with
# WESTERN numerals, as these pages are, those locales conventionally read a
# point decimal and a comma group, so "localizing" them would be the corruption
# this arm exists to catch. The four space-thousands locales use a real space
# character, and all three of the ones the pages actually carry (no-break,
# narrow no-break, thin) are accepted - a translator's editor picks one and the
# reader cannot tell them apart.
EN_CONV = ('.', ',')
NUMBER_CONV = {
    'de': (',', '.'), 'it': (',', '.'), 'es': (',', '.'), 'nl': (',', '.'),
    'pt': (',', '.'), 'da': (',', '.'), 'tr': (',', '.'), 'ro': (',', '.'),
    'fr': (',', ' '), 'sv': (',', ' '), 'nb': (',', ' '), 'fi': (',', ' '),
    'he': EN_CONV, 'ar': EN_CONV, 'fa': EN_CONV,
}
# Pinned for the reason LANGS_EXPECTED and BANNED_EXPECTED are: the selftest
# drives every entry in this table at a case of its own, so a DELETED entry
# takes its own test with it and the arm then skips that locale in silence -
# and skipping is exactly what a page with a moved decimal point wants.
NUMBER_CONV_EXPECTED = 15

# The spaces that count as a thousands group in the four locales that use one.
THIN_SPACES = '    '

# The cell population. A cell is a FIGURE if it carries a digit and almost no
# letters - the few that are left are the unit ("65-69 s", "1,814-2,022 MB",
# "~1,400 MB/s", "32.5 GB (1.0x)"). The threshold keeps prose OUT, and prose is
# where every false positive lives: a sentence reorders under translation, a
# date reformats ("23 Aug 2026" -> "23.8.2026", four English tokens against
# one Finnish one), and a product name drags its version along. Measured 25 Aug
# 2026 over both trees: 4 letters admits every real figure cell and no prose
# cell in any of the ten families.
CELL_MAX_LETTERS = 4

_CELL_RE = re.compile(r'<(td|th)\b[^>]*>(.*?)</\1>', re.S)
# A composite date. Its two shapes cannot be told apart from a number by value
# - Finnish `23.8.2026` is a date and `23.8` would be a decimal - so a cell
# carrying one is skipped whole and counted, never guessed at.
#
# THE SEPARATORS MUST MATCH, and that backreference is the whole of what made
# this rule safe to point at prose. A date writes one separator twice; a RANGE
# writes two different ones, and a rule that accepts a mixed pair reads the
# `12.7-18` inside `12.7-18.5` as a date and skips the span. In a cell that
# costs nothing - measured 25 Aug 2026, the only thing this matches in any cell
# on the site is the one real date, `23.8.2026`. In PROSE it was the entire
# game: the six things the loose rule matched were `1.00-1.03`, `1.10-1.20`,
# `12.7-18.5`, `13.9-20.3`, `12.8-13.1` and `2.75-3.75`, every one of them a
# range and not one of them a date. Reusing it as it stood would have blinded
# the new arm to the exact sentence that arm was written for.
_DATE_RE = re.compile(r'\d{1,2}([./-])\d{1,2}\1\d{2,4}')

# A NAME GLUED TO A VERSION-SHAPED NUMBER: `GPL-3.0`, `RAR 1.5`, `WinRAR 3.00`.
# An identifier is not a measurement, and it is held out as a SPAN the way a
# date is.
#
# DELIBERATELY NOT FOLDED INTO _PRODUCTS, and this is the decision to read
# twice. That set is matched by STRING - `cell_value_problems` and the prose
# arm both ask `t in vers` - so protecting a name there protects every token
# that HAPPENS TO BE SPELLED THE SAME anywhere on the page. Every one of these
# three collides with a real figure on the page it appears on: `3.0` is six
# measurements on benchmarks.html ("~2.4-3.0 Gbps", "at 3.0x", and the footer's
# own GPL-3.0), and `3.00` is a rarpar timing in one of its cells. Folding the
# names in would have blinded BOTH arms to all of those at once, quietly, which
# is a worse defect than the one it fixes.
#
# Measured 25 Aug 2026: these are every identifier of this shape on the site,
# and holding them out is not a nicety. Without it the prose arm reports eight
# CORRECTLY localized pages red - index and features in de/nl/pt/nb, whose only
# English-shaped figure is the `GPL-3.0` in the footer they all share. Those
# eight were counted as defects by the survey that commissioned this widening;
# they never were.
_IDENTS = ('GPL', 'LGPL', 'AGPL', 'WinRAR', 'RAR')
# Pinned for the reason every other roster here is: the selftest drives each
# entry at a case of its own, so a DELETED entry takes its own test with it and
# the arm then reports a licence footer as a defect on every page that carries
# one.
_IDENTS_EXPECTED = 5
_IDENT_RE = re.compile(r'\b(?:' + '|'.join(_IDENTS) + r')[- ]v?\d+(?:\.\d+)+')

# ONE SEPARATOR, EXACTLY THREE DIGITS BEHIND IT. This is the only spelling that
# is well-formed under BOTH conventions and means two different things: `2,444`
# is two thousand four hundred and forty-four in English and two-point-four-
# four-four in German, a 1000x error that no shape test can see, because both
# readings are legal. It is also the exact shape the 25 Aug 2026 decision was
# taken about. Any other ambiguity is smaller than a factor of a thousand or
# does not exist: `12.7` is not a number at all under a point-thousands
# convention, and a token with two separators mixes them and is refused.
_AMBIG_RE = re.compile(r'\d{1,3}[.,]\d{3}')

# Product names, for the version derivation below. No bare `v`: as an
# alternative it matches the tail of ordinary words and drags the following
# number into the protected set.
_PRODUCTS = (r'nzbfast|NZBGet|SABnzbd|rustnzb|Weaver|Newsbin(?: Pro)?|MultiPar|'
             r'par2cmdline(?:-turbo)?|turbo|rarpar|unrar|ParPar|macOS|Windows')
# A number followed by a UNIT is a measurement even when a product name sits in
# front of it. Without this, "NZBGet 12.7-18.5 GB of disk I/O" reads as a
# version - three real disk figures per page, found on the live page and not
# imagined.
_UNIT_AFTER = re.compile(
    r'^[-–]?[\d.,]*\s*(?:GB|MB|GiB|MiB|KB|TB|s\b|ms\b|%|Gbps|Mbps|Mbit|'
    r'Gbit|MB/s|GB/s|cores?|CPU|connections?|blocks?|articles?|seconds?)')


def table_cells(s):
    """Every <td>/<th> body in document order, tags stripped and entities
    decoded, so `&ndash;` and `&times;` do not read as letters."""
    return [html.unescape(re.sub(r'<[^>]+>', ' ', m.group(2)))
            for m in _CELL_RE.finditer(s)]


def is_figure_cell(text):
    """Is this cell a figure rather than a sentence? See CELL_MAX_LETTERS."""
    if not any(c.isdigit() for c in text):
        return False
    return sum(1 for c in text if c.isalpha()) <= CELL_MAX_LETTERS


_PROSE_DROP = re.compile(r'<(script|style|code|pre)[^>]*>.*?</\1>', re.S)


def page_prose(s):
    """The page's SENTENCES: script/style/code/pre bodies dropped, <td>/<th>
    bodies dropped, tags stripped, entities decoded.

    The cells come out because they are the other arm's population and are held
    to the English base BY VALUE there. What is left is the copy around them,
    which nothing in this directory looked at until 25 Aug 2026 - and which on
    benchmarks.fr.html carried "une E/S disque mesuree de 1,00-1.03x", both
    conventions inside one range, in one sentence, three characters apart.

    Attributes go with the tags, which is `visible`'s choice and is made here
    for the same reason: a figure a reader cannot see is not a claim. It also
    keeps the `viewBox='0 0 100 100'` inside every inline SVG data URI on these
    pages out of the population, which is not a small thing - it is a run of
    bare integers no translator will ever localize.
    """
    return html.unescape(re.sub(r'<[^>]+>', ' ',
                                _CELL_RE.sub(' ', _PROSE_DROP.sub(' ', s))))


def _number_re(conv):
    """The token pattern for `conv`. Every group is non-capturing, because
    `number_tokens` returns whole matches through `findall`.

    A SPACE GROUP BELONGS TO THE INTEGER PART AND CANNOT FOLLOW A DECIMAL, and
    that clause is what prose needed and cells never did. Until 25 Aug 2026 the
    grammar allowed the two in any order, so on the four space-thousands
    locales a decimal standing next to a three-digit number glued into one
    ill-formed token: the Finnish page's "145,6 150:sta" - English's "145.6 of
    150" with the preposition dropped, as Finnish drops it - read as a single
    figure and would have been reported as a defect on a correct translation. A
    sentence puts two numbers side by side; a table cell does not, which is why
    this only surfaced when the population widened.
    """
    thou = conv[1]
    intp = (r'(?:\d{1,3}(?:[' + THIN_SPACES + r']\d{3}(?!\d))+|\d+)'
            if thou in THIN_SPACES else r'\d+')
    return re.compile(r'(?<![\w.,])' + intp + r'(?:[.,]\d+)*')


def number_tokens(text, conv):
    """The numeric tokens in one span of text, read under `conv`.

    The token is GREEDY and carries no trailing word-boundary guard, which is
    what makes `2.1x` read as 2.1 and `5.1.0RC2` read as 5.1.0. The leading
    guard is what keeps `&sup1;`'s digit and the `2` of `RC2` out. A space is a
    group separator only for the locales that use one, and only before EXACTLY
    three digits, so `32 cores, 4 GB` cannot glue into one number.
    """
    return [m.group(0) for m in _number_re(conv).finditer(text)]


def parse_number(tok, conv):
    """`tok` as a float under `conv`, or None if it is not well-formed there.

    Well-formed is the whole point: `12.7` is a number in English and is NOT
    one under a point-thousands convention, because a group is exactly three
    digits. That refusal is what tells a half-converted page from a converted
    one - both parse, only one parses under a single convention."""
    dec, thou = conv
    t = tok
    if thou in THIN_SPACES:
        t = re.sub('[' + THIN_SPACES + ']', ' ', t)
        thou = ' '
    if t.count(dec) > 1:
        return None
    ip, _, fp = t.partition(dec)
    if dec in t and not re.fullmatch(r'\d+', fp):
        return None
    if thou in ip:
        if not re.fullmatch(r'\d{1,3}(?:' + re.escape(thou) + r'\d{3})+', ip):
            return None
        ip = ip.replace(thou, '')
    if not re.fullmatch(r'\d+', ip):
        return None
    return float(ip + ('.' + fp if fp else ''))


def version_strings(en):
    """Every numeric token the ENGLISH page uses as a version. Derived, never
    hand-listed, so it cannot age past the products on the page.

    Two arms, and the guards on both are scar tissue. Any dotted token with
    three or more parts is a version wherever it stands - the trailing
    `(?![\\d.])` is load-bearing, because a greedy version pattern pulled
    `13.9` out of the MEASUREMENT `13.97`. A two-part token is a version only
    behind a product name and only when no unit follows it, which is what
    separates "SABnzbd 5.1.1" and "NZBGet 26.3-testing" from the disk-I/O
    figures "NZBGet 12.7-18.5 GB" and "rustnzb 12.8-13.1 GB"."""
    # DECODE ENTITIES, KEEP THE TAGS. `&ndash;` between a figure and its unit
    # is what the unit lookahead has to see: on the raw page,
    # "NZBGet 12.7&ndash;18.5 GB" put the disk figure 12.7 into the protected
    # set (measured 25 Aug 2026), which is trap 2 walking back in through an
    # entity. Stripping the tags as well is the tempting next step and is
    # WRONG - `<td>nzbfast</td><td>9.1</td>` collapses to "nzbfast 9.1", so
    # every figure in the column beside a product name would be protected as
    # a version and never checked again.
    en = html.unescape(en)
    out = set()
    for m in re.finditer(r'(?<![\d.])\d+\.\d+\.\d+(?![\d.])', en):
        out.add(m.group(0))
    for m in re.finditer(r'(?:' + _PRODUCTS + r')\s+v?(\d+(?:\.\d+)+)(?![\d.])', en):
        if not _UNIT_AFTER.match(en[m.end():m.end() + 25]):
            out.add(m.group(1))
    return out


def visible(s):
    """The page's visible text: script/style bodies dropped, tags stripped,
    entities decoded. Attributes go with the tags, so a version counted here
    is one a reader can see rather than one in an href."""
    return html.unescape(
        re.sub(r'<[^>]+>', ' ',
               re.sub(r'<(script|style)[^>]*>.*?</\1>', '', s, flags=re.S)))


def mangled_versions(vers, conv):
    """Every way `conv` could have re-punctuated a version string.

    This is trap 3 made explicit. `\\d+\\.\\d+` matches the `1.2` inside the
    version `1.2.2`, because the character that follows is a dot rather than a
    word character, so a converter that localizes what it matches turns the
    version into `1,2.2` - and nineteen per locale shipped that way before a
    count caught it. Nothing compares versions by value (`5.1.0` is not a
    number), so what stands behind them is this: the mangled spellings must not
    appear on the page at all.
    """
    dec, thou = conv
    out = set()
    seps = {dec, thou} - {'.'}
    if thou in THIN_SPACES:
        seps = {dec}
    for v in vers:
        parts = v.split('.')
        # THREE PARTS OR MORE, and the bound is measured. A mangled two-part
        # version is spelled exactly like an ordinary localized decimal:
        # `5.1` becomes `5,1`, which is also how the Portuguese page writes
        # the multiplier "5,1x mais rapido". Scanning for it reported that
        # sentence as a re-punctuated version (25 Aug 2026). A three-part
        # version cannot collide - `1,2.2` mixes both separators and is not a
        # number in any convention on this list.
        if len(parts) < 3:
            continue
        for sep in seps:
            for i in range(1, len(parts)):
                out.add('.'.join(parts[:i]) + sep + '.'.join(parts[i:]))
    return out


def mangled_idents(en, conv):
    """Every way `conv` could have re-punctuated an IDENTIFIER's version.

    `GPL-3.0` is not a number, and a number pass that respells it `GPL-3,0` has
    broken a licence name. The version arm above cannot reach this one: it
    needs THREE parts before a mangled spelling is safe to scan for, because a
    two-part `5.1` mangles to `5,1`, which is also how the Portuguese page
    writes the multiplier "5,1x mais rapido". These identifiers have two.

    Anchoring on the NAME is what makes two parts safe here - `GPL-3,0` is
    unambiguous where a bare `3,0` is the German spelling of a real
    measurement. Every dot position is generated, not just the last, because a
    converter mangles whichever one its pattern happened to match.
    """
    dec = conv[0]
    out = set()
    if dec == '.':
        return out
    for m in _IDENT_RE.finditer(html.unescape(en)):
        v = m.group(0)
        out |= {v[:i] + dec + v[i + 1:] for i, c in enumerate(v) if c == '.'}
    return out


def version_problems(en, tr, conv):
    """Refuse a version string that has been re-punctuated by a number pass.

    WHY THIS IS A SCAN FOR THE BROKEN SPELLING AND NOT A COUNT OF THE GOOD ONE.
    A count is what found trap 3 in the one-off converter, and it does not
    survive contact with a translation: measured 25 Aug 2026 over the twelve
    comma-locale benchmark twins on main, a count arm reported all fifteen
    pages red for prose that legitimately says the version list one more time
    than English does ("Gemessen gegen NZBGet 26.2, SABnzbd 5.0.4, Weaver
    v0.7.5 und rustnzb ..." repeated as one caption where English spells three
    different ones), and the Persian page names `1.3.4` seventeen times against
    English's twenty-two with nothing re-punctuated anywhere. A gate that is
    red for a reason nobody can act on is one that gets waved through. The
    mangled spelling, by contrast, is never legitimate: `1,2.2` is not a
    version in any locale."""
    body = visible(tr)
    probs = []
    for bad in sorted(mangled_versions(version_strings(en), conv)):
        if bad in body:
            probs.append(f'version string re-punctuated: {bad!r} is on this '
                         'page. A version is not a number - it must survive a '
                         'number pass byte for byte.')
    for bad in sorted(mangled_idents(en, conv)):
        if bad in body:
            probs.append(f'identifier re-punctuated: {bad!r} is on this page. '
                         'A licence or a format name is not a number - it must '
                         'survive a number pass byte for byte.')
    return probs


def cell_value_problems(ec, tc, vers, conv):
    """The value comparison for ONE candidate convention. Returns
    (problems, cells reached, values reached, cells skipped as dates).

    THE COMPARISON WITHIN A CELL IS BY MULTISET, NOT BY POSITION, and that is
    measured rather than lazy: `77 GB 4K` is `4K de 77 GB` in French, so a
    positional read calls a correct translation two defects. Word order is the
    one thing a translator is certainly allowed to move. The trade is stated
    rather than hidden - two figures SWAPPED inside one cell read as equal -
    and it buys the arm the right to run on every cell instead of on the ones
    whose grammar happens to survive."""
    probs, cells_seen, vals, skipped = [], 0, 0, 0
    for i, (a, b) in enumerate(zip(ec, tc)):
        if not is_figure_cell(a):
            continue
        if _DATE_RE.search(a) or _DATE_RE.search(b):
            skipped += 1
            continue
        cells_seen += 1
        where = f'cell {i} ({a.strip()[:44]!r} vs {b.strip()[:44]!r})'
        at = number_tokens(a, EN_CONV)
        bt = number_tokens(b, conv)
        av = sorted(t for t in at if t in vers)
        bv = sorted(t for t in bt if t in vers)
        if av != bv:
            probs.append(f'{where}: version strings {av} vs {bv}')
        an = [t for t in at if t not in vers]
        bn = [t for t in bt if t not in vers]
        vals += len(an)
        bad = [t for t in bn if parse_number(t, conv) is None]
        if bad:
            probs.append(f'{where}: {bad} is not a well-formed number under '
                         'this reading')
            continue
        ea = sorted(parse_number(t, EN_CONV) for t in an
                    if parse_number(t, EN_CONV) is not None)
        if len(ea) != len(an):
            probs.append(f'{where}: the ENGLISH cell carries a number this '
                         'script cannot read - fix the base page')
            continue
        eb = sorted(parse_number(t, conv) for t in bn)
        if ea != eb:
            only_en = [x for x in ea if x not in eb]
            only_tr = [x for x in eb if x not in ea]
            probs.append(f'{where}: English says {only_en or ea} where this '
                         f'page says {only_tr or eb}')
    return probs, cells_seen, vals, skipped


def page_values(en):
    """Every value the ENGLISH page states, cells and prose alike.

    Both, deliberately: a translation routinely restates in a sentence a figure
    the base states only in a table, and a prose-only set calls that a defect.
    """
    vers = version_strings(en)
    text = _IDENT_RE.sub(' ', _DATE_RE.sub(' ', html.unescape(
        re.sub(r'<[^>]+>', ' ', _PROSE_DROP.sub(' ', en)))))
    return {parse_number(t, EN_CONV) for t in number_tokens(text, EN_CONV)
            if t not in vers and parse_number(t, EN_CONV) is not None}


def prose_problems(text, conv, vers, envals):
    """Hold one page's PROSE figures to a single convention, BY SHAPE - and the
    one spelling shape cannot judge, BY VALUE.

    Returns (problems, tokens reached).

    WHY SHAPE HERE AND VALUE THERE, which is the decision to read twice. The
    cell arm compares floats against the English base because a cell HAS a
    counterpart: the same index in the same table, and a table whose length
    disagrees is refused rather than run. A sentence has no such counterpart,
    and all three of the reasons were measured on the real pages rather than
    imagined. Word order moves ("77 GB 4K" is "4K de 77 GB"), so a positional
    read calls a correct translation a defect. A translation legitimately says
    a figure a different NUMBER of times from English - the same shape that
    reported all fifteen pages red when the version arm was tried as a count -
    so a multiset read over a whole page fails the same way. And a paragraph
    merges or splits under translation, so there is not even a stable unit to
    align. What survives is the weaker question, and it is the one that catches
    the defect that was actually shipping: is every figure in this page's prose
    well-formed under the convention the rest of the page is written in?

    IT CATCHES THE PAGE, NOT ALWAYS THE FIGURE, and that limit is stated rather
    than left to be discovered. `1,400` is a well-formed Dutch decimal and a
    1000x misreading of English `1,400`; shape alone cannot separate them, and
    only a value comparison could. A set-containment value arm WAS built and
    measured on 25 Aug 2026 before this one was settled on: against the English
    prose it left 20 unexplained figures across four pages, on pages that are
    legitimately all-English as well as on half-converted ones, because a
    translation restates figures the English base states only in a table. A
    gate red for a reason nobody can act on is one that gets waved through.
    Shape, by contrast, was measured to catch every mixed page on the tree with
    ZERO false positives once dates and identifiers are held out - which is the
    bar the rest of this file is held to.

    THE ONE EXCEPTION IS `_AMBIG_RE`, AND IT IS WORTH THE NARROWNESS. `2,444`
    left in a German sentence is a well-formed German decimal and a 1000x
    misreading of the English figure, so shape passes it - measured, by
    reverting one converted figure on the real page and watching the run stay
    green. For that ONE spelling the value is looked up in the English base,
    which is the only thing that separates the two readings. It is safe to ask
    only here: the broad set-containment arm that was rejected asked it of
    EVERY figure and left 20 unexplained across four pages, while this shape
    was measured at ZERO on all 150 - a translation restates a figure the base
    states in a table, but it does not invent one with a thousands group.

    So a defect that is well-formed under the page's own convention AND is not
    of that shape survives this arm alone - and does not survive the page,
    because the same edit that introduces it almost never introduces only it.
    What tightening this to the locale outright would buy, and what it needs
    first, is at `number_problems`.
    """
    text = _IDENT_RE.sub(' ', _DATE_RE.sub(' ', text))
    probs, seen = [], 0
    for m in _number_re(conv).finditer(text):
        tok = m.group(0)
        if tok in vers:
            continue
        seen += 1
        ctx = re.sub(r'\s+', ' ',
                     text[max(0, m.start() - 44):m.end() + 24]).strip()
        val = parse_number(tok, conv)
        if val is None:
            probs.append(f'{tok!r} is not a well-formed number under this '
                         f'reading: ...{ctx}...')
        elif _AMBIG_RE.fullmatch(tok) and val not in envals:
            probs.append(f'{tok!r} reads as {val} under this convention, and '
                         'the English base states no such figure - this is the '
                         'one spelling that is legal under both and means a '
                         f'THOUSAND times more under the other: ...{ctx}...')
    return probs, seen


def number_problems(en, tr, lang, stats=None):
    """Hold one translated page's table numbers to the English base BY VALUE.

    Pure over the two documents and the locale, so the selftest drives it on
    fixtures. `stats`, when given, accumulates what was REACHED - a scanner
    that has quietly stopped matching reads as a clean tree forever, so main()
    prints those totals and refuses a zero."""
    conv = NUMBER_CONV.get(lang)
    if conv is None:
        return [f'{lang!r} has no entry in NUMBER_CONV - a locale whose '
                'number convention nobody has written down is one whose '
                'figures nothing checks']
    probs = list(version_problems(en, tr, conv))
    ec, tc = table_cells(en), table_cells(tr)
    if len(ec) != len(tc):
        probs.append(f'table cells: {len(ec)} in English, {len(tc)} here - the '
                     'value arm compares cells BY INDEX, so it is refused '
                     'rather than run against a shifted table')
        return probs
    vers = version_strings(en)
    # Two candidates, deduped for the locales whose convention IS English. The
    # page must fit ONE of them completely; the report comes from whichever
    # fits best, so a half-converted page is described in the terms of the
    # convention it was mostly converted to.
    #
    # CELLS AND PROSE ARE SCORED TOGETHER, ON ONE CANDIDATE, and that is the
    # whole point of widening rather than bolting a second arm on the side. The
    # promise this arm makes is that the page means the same numbers as English
    # under ONE convention, consistently; until 25 Aug 2026 it kept that promise
    # for the tables alone, so a page whose prose disagreed with its own tables
    # about the convention was invisible - and main shipped exactly that on
    # twelve pages. Scoring them separately would let a page pick English for
    # its cells and the locale for its sentences and pass both halves.
    tp, envals = page_prose(tr), page_values(en)
    cands = [conv] + ([] if conv == EN_CONV else [EN_CONV])
    best = None
    for c in cands:
        got = cell_value_problems(ec, tc, vers, c)
        pgot = prose_problems(tp, c, vers, envals)
        score = len(got[0]) + len(pgot[0])
        if best is None or score < best[3]:
            best = (c, got, pgot, score)
    c, (cprobs, cells_seen, vals, skipped), (pprobs, ptoks), _ = best
    if stats is not None:
        stats['cells'] = stats.get('cells', 0) + cells_seen
        stats['values'] = stats.get('values', 0) + vals
        stats['dates'] = stats.get('dates', 0) + skipped
        stats['prose'] = stats.get('prose', 0) + ptoks
        stats['pages'] = stats.get('pages', 0) + 1
    shape = ('the local convention' if c != EN_CONV else
             'English convention (point decimal, comma thousands)')
    if cprobs:
        head = (f'NUMBER PARITY: {len(cprobs)} of {vals} table value(s) do not '
                f'match the English base, read under {shape} - the reading '
                'that fits this page best. A page that fits NEITHER convention '
                'is half-converted; a value that fits neither has moved.')
        probs.append(head)
        probs += ['   ' + p for p in cprobs[:8]]
        if len(cprobs) > 8:
            probs.append(f'   ... and {len(cprobs) - 8} more (not truncated '
                         'silently - fix these and rerun)')
    if pprobs:
        head = (f'NUMBER PARITY (prose): {len(pprobs)} of {ptoks} figure(s) in '
                f'this page\'s sentences are not written in {shape} - the '
                'reading the rest of the page fits best. A page that punctuates '
                'its tables one way and its prose the other means two different '
                'numbers by one spelling; fix the FIGURE, in the convention the '
                'rest of the page uses.')
        probs.append(head)
        probs += ['   ' + p for p in pprobs[:8]]
        if len(pprobs) > 8:
            probs.append(f'   ... and {len(pprobs) - 8} more (not truncated '
                         'silently - fix these and rerun)')
    return probs


def analyse(en, tr, lang, anon=False, base='x', stats=None):
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
    probs += number_problems(en, tr, lang, stats=stats)
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


def check(en_rel, tr_rel, lang, base, anon=False, stats=None):
    with open(os.path.join(ROOT, en_rel), encoding='utf-8') as f:
        en = f.read()
    with open(os.path.join(ROOT, tr_rel), encoding='utf-8') as f:
        tr = f.read()
    return report(tr_rel, analyse(en, tr, lang, anon=anon, base=base,
                                  stats=stats))


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
    'arr': 'Sonarr/Radarr/Prowlarr setup guide, added 28 Aug 2026 in English only, the same way and under the same open question as the synology and unraid guides below. It is a settings walkthrough whose load-bearing content is field names the *arrs themselves render in English regardless of the reader locale (Settings, Download Clients, SABnzbd, Test, Category) plus code spans that must stay byte-identical anyway, so a translated twin would carry a handful of connecting sentences around an English UI. Linked from the Sonarr / Radarr card on all 16 index pages as a bare English href, which is exactly what the two guides below already do from the localized download pages. Whether it should become a translated family is the same content decision, still open.',
    'benchmark-nested-archives': 'Data appendix for the nested-archive '
                'section of the benchmarks page: ten archive shapes against '
                'seven downloaders, eight tables of figures and three '
                'charts. English only DELIBERATELY, and not by the same '
                'open question as the two below - it is almost entirely '
                'numbers, unit labels and client names, so a translated '
                'twin would be fifteen copies of the same tables held to '
                'byte-identical <code> and figure parity for the sake of a '
                'few hundred words of caption. The prose that a reader has '
                'to understand to read the figures lives in the benchmarks '
                'page section that links here, and THAT page is a '
                'translated family. Revisit if the appendix grows prose '
                'rather than tables.',
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
    'benchmarks-data': 'Raw-data twin of the benchmarks page, added 24 Aug '
                       '2026 by decision: the client download rounds '
                       'as plain unhighlighted tables, deliberately carrying '
                       'no site chrome, no picker and no branding outside the '
                       'client rows. English only by decision at creation; '
                       'whether it grows locale twins is open, and until it '
                       'does the anonymity grep on this entry is the whole '
                       'coverage.',
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
ROSTER_EXPECTED = 15


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
<p>See the <a href="benchmarks.html">numbers</a>, measured on a rented box: 2.5x the payload on 4,096 MB of RAM, 2.75-3.75 s per pass, on 23 Aug 2026, under GPL-3.0.</p>
<ul>
<li>One pass over the wire.</li>
<li>No second read from disk.</li>
</ul>
<table>
<tr><td>Tool</td><td>GB/min</td><td>peak RSS</td><td>disk</td></tr>
<tr><td>nzbfast</td><td><span class="num">9.1</span></td><td class="num">1,814 MB</td><td class="num">32.5 GB (1.0&times;)</td></tr>
<tr><td>rustnzb 1.2.2</td><td class="num">13.97</td><td class="num">2,022 MB</td><td class="num">77 GB 4K</td></tr>
<tr><td>NZBGet 26.3-testing</td><td class="num">12.7&ndash;18.5 GB</td><td class="num">~1,400 MB/s</td><td>23 Aug 2026</td></tr>
</table>
<pre><code>nzbfast get file.nzb --host news.eweka.example --min-free 12.5</code></pre>
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

def fixture_localize(body, lang):
    """Rewrite the figures of a fixture body into `lang`'s convention - the
    FIGURE cells, and the PROSE around them.

    Never a date cell, never a version, never an identifier, so the fixtures
    exercise the same boundaries the arm draws rather than tidier ones - a
    version string in a prose cell (`rustnzb 1.2.2`), a reformatted date and
    the `GPL-3.0` in the copy all have to survive this untouched, which is what
    makes the 'correctly localized' case worth anything.

    THE PROSE HALF ARRIVED WITH THE PROSE ARM, 25 Aug 2026, and it had to: a
    correctly localized page localizes its sentences too, so a fixture that
    converted its tables alone would make this arm's own green case a
    half-converted page - and the green case is the one that says the arm is
    not simply red about everything."""
    dec, thou = NUMBER_CONV[lang]

    # The pages carry a NARROW NO-BREAK space, not an ASCII one, and
    # NUMBER_CONV spells the separator as a plain space because THIN_SPACES
    # normalizes all four. Writing the real character here is what proves the
    # arm reads it rather than only the tidy one.
    group = '\u202f' if thou == ' ' else thou

    def one(mo):
        t = mo.group(0)
        if ',' in t:
            return t.replace(',', group)
        if '.' in t:
            return t.replace('.', dec)
        return t

    def cell(mo):
        text = html.unescape(re.sub(r'<[^>]+>', ' ', mo.group(2)))
        if not is_figure_cell(text) or _DATE_RE.search(text):
            return mo.group(0)
        body2 = re.sub(r'(?<![\w.,])\d+(?:[.,]\d+)*', one, mo.group(2))
        return mo.group(0)[:mo.start(2) - mo.start(0)] + body2 + '</' + mo.group(1) + '>'

    # What a number pass must not touch when it walks the copy: a tag and its
    # attributes, an entity, a date, a three-part version, an identifier, and a
    # code or style body.
    skips = (_DATE_RE, _IDENT_RE, _PROSE_DROP, re.compile(r'<[^>]+>'),
             re.compile(r'&[a-zA-Z#][a-zA-Z0-9]*;'),
             re.compile(r'\d+\.\d+\.\d+'))

    def around(txt):
        held = [(m.start(), m.end()) for r in skips for m in r.finditer(txt)]

        def maybe(mo):
            if any(a <= mo.start() and mo.end() <= b for a, b in held):
                return mo.group(0)
            return one(mo)

        return re.sub(r'(?<![\w.,])\d+(?:[.,]\d+)*', maybe, txt)

    out, prev = [], 0
    for mo in _CELL_RE.finditer(body):
        out.append(around(body[prev:mo.start()]))
        out.append(cell(mo))
        prev = mo.end()
    out.append(around(body[prev:]))
    return ''.join(out)


# The French twin as it should look once its numbers are localized: a decimal
# comma and a narrow no-break space for the thousands group. The space is the
# real character the pages carry, not an ASCII one, and it is here so the
# fixture proves the arm reads it.
LOCALIZED_FR = fixture_localize(FAITHFUL, 'fr')

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
     FAITHFUL.replace('<tr><td>rustnzb 1.2.2</td><td class="num">13.97</td>'
                      '<td class="num">2,022 MB</td>'
                      '<td class="num">77 GB 4K</td></tr>\n', ''), {}, False),
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
    # --- number parity. The arms above are all STRUCTURE: a translation
    # could move a decimal point through every one of them untouched, and on
    # a benchmarks page the figures are the whole claim.
    ('the figures correctly localized', False, LOCALIZED_FR, {}, False),
    # The defect the 25 Aug 2026 decision is about: an English thousands group
    # left in a comma-decimal locale reads as a number a THOUSAND times
    # smaller, and it reads as one silently.
    ('an English thousands group left in a localized table', True,
     LOCALIZED_FR.replace('1\u202f814', '1,814'), {}, False),
    # The tr incident, in miniature: one cell converted and the rest not, so
    # the page fits NEITHER convention.
    ('a half-localized table', True,
     FAITHFUL.replace('>32.5 GB (1.0&times;)<', '>32,5 GB (1,0&times;)<'),
     {}, False),
    ('a figure whose value moved', True,
     FAITHFUL.replace('>13.97<', '>13.79<'), {}, False),
    ('a figure whose value moved in a localized table', True,
     LOCALIZED_FR.replace('>13,97<', '>13,79<'), {}, False),
    ('a figure dropped from a cell', True,
     FAITHFUL.replace('12.7&ndash;18.5 GB', '18.5 GB'), {}, False),
    ('a whole table cell dropped', True,
     FAITHFUL.replace('<td class="num">~1,400 MB/s</td>', ''), {}, False),
    # Trap 3, and the reason versions get an arm of their own: a number pass
    # matches the `1.2` inside `1.2.2`, because what follows is a dot rather
    # than a word character. Nineteen per locale shipped that way.
    ('a version string re-punctuated by a number pass', True,
     LOCALIZED_FR.replace('rustnzb 1.2.2', 'rustnzb 1,2.2'), {}, False),
    # ...and the other side of it: a correctly localized page must leave every
    # version, and every date, exactly as English spells it.
    ('a version left alone in a localized table', False, LOCALIZED_FR, {}, False),
    # Trap 4. `23.8.2026` is a date, not a decimal, and English spells the same
    # day with two numeric tokens where Finnish spells it with one. The cell is
    # skipped whole rather than guessed at.
    ('a date reformatted for the locale', False,
     LOCALIZED_FR.replace('23 Aug 2026', '23.8.2026'), {}, False),
    # Word order is the one thing a translator is certainly allowed to move,
    # so the comparison inside a cell is by multiset. `77 GB 4K` really is
    # `4K de 77 GB` on the French page today.
    ('the word order inside a figure cell', False,
     FAITHFUL.replace('77 GB 4K', '4K de 77 GB'), {}, False),
    # --- number parity in PROSE. The same question asked of the sentences
    # AROUND the tables, which nothing asked until 25 Aug 2026 - and which is
    # where main was shipping "1,00-1.03x", both conventions inside one range.
    ('an English prose figure left on a localized page', True,
     LOCALIZED_FR.replace('2,5x', '2.5x'), {}, False),
    # The 1000x misreading, in prose this time, and it is the case SHAPE
    # CANNOT SEE: `4,096` is a well-formed French decimal. Only the value,
    # looked up in the English base, separates 4096 from 4.096. The figure is
    # deliberately one no CELL carries - with a cell value here the case would
    # pass off the cell arm's evidence and prove nothing about prose.
    ('an English thousands group left in localized prose', True,
     LOCALIZED_FR.replace('4\u202f096 MB', '4,096 MB'), {}, False),
    # Trap 1. A sentence REORDERS under translation far more freely than a
    # cell does, so prose is compared by SHAPE and never by position. This is
    # the case that would be red if anybody ever aligned prose positionally.
    ('a reordered prose sentence', False,
     LOCALIZED_FR.replace('2,5x the payload on 4\u202f096 MB of RAM',
                          'sur 4\u202f096 MB de RAM, 2,5x la charge utile'),
     {}, False),
    # Trap 2. A translation legitimately says a figure a different NUMBER of
    # times from English - the shape that reported all fifteen pages red when
    # the version arm was tried as a count. A multiset over a page fails the
    # same way; shape does not count at all.
    ('a prose figure repeated more times than English', False,
     LOCALIZED_FR.replace('2,5x the payload',
                          '2,5x la charge utile - 2,5x, mesuree deux fois'),
     {}, False),
    # Trap 3. A date reformats to a shape that is not a number in any
    # convention: English spells this day with two numeric tokens and the
    # localized page with one.
    ('a prose date reformatted for the locale', False,
     LOCALIZED_FR.replace('23 Aug 2026', '23.8.2026'), {}, False),
    # ...and the other half of that, which is the case the whole widening
    # turned on. `75-3.75` sits inside `2.75-3.75`, so a date rule that
    # accepts a MIXED separator masks the span - and an English `3.75` left in
    # localized prose passed. Six such ranges were live on the real pages and
    # not one of them was a date.
    ('an English figure inside a range in localized prose', True,
     LOCALIZED_FR.replace('2,75-3,75', '2,75-3.75'), {}, False),
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

    # Every NUMBER_CONV entry, at a case of its own. The table is the arm's
    # only configuration and a DELETED entry takes its own test with it, so
    # the loop is driven from the table and the pin below is the only thing
    # that can see a deletion - the same shape as BANNED/BANNED_EXPECTED.
    for lang in NUMBER_CONV:
        cases += 2
        good = page('fr', fixture_localize(FAITHFUL, lang))
        if number_problems(en, good, lang):
            print(f'  selftest FAIL: a correctly localized {lang!r} table is '
                  'reported as a defect', file=sys.stderr)
            for x in number_problems(en, good, lang):
                print('      ', x, file=sys.stderr)
            bad += 1
        moved = page('fr', fixture_localize(
            FAITHFUL.replace('>13.97<', '>13.79<'), lang))
        if not number_problems(en, moved, lang):
            print(f'  selftest FAIL: a moved figure passes under {lang!r} - '
                  'this locale is not being read at all', file=sys.stderr)
            bad += 1
    cases += 1
    if len(NUMBER_CONV) != NUMBER_CONV_EXPECTED:
        print(f'  selftest FAIL: NUMBER_CONV is {len(NUMBER_CONV)} locales, '
              f'NUMBER_CONV_EXPECTED says {NUMBER_CONV_EXPECTED}. A locale '
              'without an entry has its figures skipped, and the loop above '
              'only tests the entries that are still there.', file=sys.stderr)
        bad += 1
    cases += 1
    if sorted(NUMBER_CONV) != sorted(LANGS):
        print(f'  selftest FAIL: NUMBER_CONV and LANGS name different locales '
              f'({sorted(set(LANGS) - set(NUMBER_CONV))} have no convention, '
              f'{sorted(set(NUMBER_CONV) - set(LANGS))} are not shipped)',
              file=sys.stderr)
        bad += 1

    # THE CELLS CANNOT ALWAYS CHOOSE THE CONVENTION, and when they tie it is
    # the PROSE that says which one the page is written in. A table of bare
    # integers reads identically under both candidates, so a scorer that
    # weighs cells alone keeps whichever it tried first and then reports the
    # sentences under it - calling a correct all-English page a defect. This
    # is the case that says the two populations are scored as ONE page.
    _TIE = ('<section id="tie"><p>Measured at 2.5x on 1,814 MB.</p>'
            '<table><tr><td>tool</td><td class="num">32 s</td></tr></table>'
            '</section>')
    cases += 1
    probs = analyse(page('en', _TIE), page('fr', _TIE), 'fr')
    if probs:
        print('  selftest FAIL: an all-English page whose cells fit both '
              'conventions is reported as a defect - prose is not being '
              'scored into the choice of convention', file=sys.stderr)
        for x in probs:
            print('      ', x, file=sys.stderr)
        bad += 1

    # THE ENGLISH VALUE SET MUST INCLUDE THE CELLS. A translation routinely
    # restates in a sentence a figure the base states only in a table, and a
    # prose-only set calls that restatement a defect. Driven on a
    # point-thousands locale because that is where the ambiguous shape lives:
    # `2.022` is a well-formed German thousands group, and 2022 is a number
    # EN_BODY carries in a cell and never in a sentence.
    cases += 1
    _de = fixture_localize(FAITHFUL, 'de')
    probs = analyse(en, page('de', _de.replace(
        '2,75-3,75 s per pass', '2,75-3,75 s per pass, also 2.022 MB')), 'de')
    if probs:
        print('  selftest FAIL: a translation restating a figure the English '
              'base states only in a TABLE is reported as a defect - the '
              'English value set is prose-only', file=sys.stderr)
        for x in probs:
            print('      ', x, file=sys.stderr)
        bad += 1

    # Every _IDENTS entry, at a case of its own, and BOTH directions of it.
    # An identifier held out must not be read as a measurement, and the same
    # identifier RE-PUNCTUATED must still be refused - the second is the only
    # arm that can see it, because `GPL-3,0` is well-formed under every one of
    # these locales and shape therefore cannot. The English fixture carries the
    # name too, since the mangled spelling is derived from the base.
    for name in _IDENTS:
        cases += 2
        body = FAITHFUL.replace('under GPL-3.0', f'under {name} 4.0')
        en_i = page('en', EN_BODY.replace('under GPL-3.0', f'under {name} 4.0'))
        loc = fixture_localize(body, 'fr')
        probs = analyse(en_i, page('fr', loc), 'fr')
        if probs:
            print(f'  selftest FAIL: the identifier {name!r} is read as a '
                  'measurement in localized prose', file=sys.stderr)
            for x in probs:
                print('      ', x, file=sys.stderr)
            bad += 1
        if not analyse(en_i, page('fr', loc.replace(f'{name} 4.0',
                                                    f'{name} 4,0')), 'fr'):
            print(f'  selftest FAIL: {name!r} re-punctuated by a number pass '
                  'passes - a licence or a format name is not a number and '
                  'must survive one byte for byte', file=sys.stderr)
            bad += 1
    cases += 1
    if len(_IDENTS) != _IDENTS_EXPECTED:
        print(f'  selftest FAIL: _IDENTS is {len(_IDENTS)} names, '
              f'_IDENTS_EXPECTED says {_IDENTS_EXPECTED}. A name dropped from '
              'that tuple takes its own case above with it, and the arm then '
              'reads the licence footer every page carries as a defect.',
              file=sys.stderr)
        bad += 1

    # The three derivation traps, pinned directly rather than through a page,
    # because each one is a REGEX that reads as a clean tree the day it stops
    # matching. Every one of them cost a real defect in the one-off converter
    # this arm inherited its rules from.
    vt = version_strings('nzbfast 1.2.2 and NZBGet 26.3-testing beat '
                         'NZBGet 12.7&ndash;18.5 GB and 13.97 GB of disk')
    trap_cases = [
        # 1. a greedy version pattern pulled `13.9` out of the MEASUREMENT
        #    `13.97`, and would have shipped one unconverted number per page.
        ('13.9', False, 'a measurement had a version pulled out of it'),
        # 2. a product name in front of a figure does not make it a version:
        #    "NZBGet 12.7-18.5 GB" is disk I/O. A unit lookahead separates them.
        ('12.7', False, 'a disk figure behind a product name reads as a version'),
        # ...and the two that really are versions must still be found, or the
        #    arm protects nothing.
        ('1.2.2', True, 'a three-part version is not recognized'),
        ('26.3', True, 'a two-part version behind a product name is not '
                       'recognized'),
    ]
    for tok, want, why in trap_cases:
        cases += 1
        if (tok in vt) != want:
            print(f'  selftest FAIL: version derivation: {why} ({tok!r} '
                  f'{"missing from" if want else "in"} the set)', file=sys.stderr)
            bad += 1
    # 3. `\d+\.\d+` matches the `1.2` inside `1.2.2`, because what follows is a
    #    dot rather than a word character. The tokenizer must take the whole
    #    thing or the version arm never sees it.
    cases += 1
    if number_tokens('nzbfast 1.2.2 at 2.1x on 5.1.0RC2', EN_CONV) != \
            ['1.2.2', '2.1', '5.1.0']:
        print('  selftest FAIL: the tokenizer splits a version, or swallows a '
              f'unit: {number_tokens("nzbfast 1.2.2 at 2.1x on 5.1.0RC2", EN_CONV)}',
              file=sys.stderr)
        bad += 1
    # A space is a group separator only before EXACTLY three digits, or
    # `32 cores, 4 GB` glues into one number on the four space-thousands
    # locales.
    cases += 1
    if number_tokens('1 814 MB on 32 cores, 4 GB', NUMBER_CONV['fr']) != \
            ['1 814', '32', '4']:
        print('  selftest FAIL: the space-group tokenizer glues two numbers, '
              'or does not read a group at all: '
              f'{number_tokens("1 814 MB on 32 cores, 4 GB", NUMBER_CONV["fr"])}',
              file=sys.stderr)
        bad += 1

    # ...and a space group cannot follow a DECIMAL, or a decimal standing
    # beside a three-digit number glues into one ill-formed token and the arm
    # reports a defect on a correct translation. This is the real Finnish
    # sentence: English's "145.6 of 150" with the preposition dropped, as
    # Finnish drops it. Cells never showed this - a sentence puts two numbers
    # side by side and a cell does not.
    cases += 1
    _fi = number_tokens('(290,7 MB/s 300 MB/s, 145,6 150:sta)', NUMBER_CONV['fi'])
    if _fi != ['290,7', '300', '145,6', '150']:
        print('  selftest FAIL: a space group is being read after a decimal, '
              f'so two figures side by side glue into one: {_fi}',
              file=sys.stderr)
        bad += 1

    # The cell population itself, pinned by COUNT. What this arm protects
    # against is a matcher that has quietly stopped matching, and that reads as
    # a clean tree forever; an inert one has to show a zero here.
    cases += 1
    figs = [c for c in table_cells(EN_BODY) if is_figure_cell(c)]
    prose_cells = [c for c in table_cells(EN_BODY)
                   if not is_figure_cell(c) and any(ch.isdigit() for ch in c)]
    if len(figs) != 9 or len(prose_cells) != 2:
        print(f'  selftest FAIL: the fixture table has {len(figs)} figure '
              f'cell(s) and {len(prose_cells)} prose cell(s) with digits, not '
              '9 and 2 - either the matcher moved or the fixture did',
              file=sys.stderr)
        bad += 1
    cases += 1
    st = {}
    number_problems(en, page('fr', LOCALIZED_FR), 'fr', stats=st)
    if (st.get('cells'), st.get('values'), st.get('dates'),
            st.get('prose')) != (9, 13, 0, 6):
        print(f'  selftest FAIL: the number arm reached {st} on the fixture, '
              'not 9 cells / 13 values / 0 dates skipped / 6 prose figures. A '
              'scanner that has stopped matching reports a clean tree, so this '
              'count is the thing that says it is still running - and PROSE is '
              'counted separately because the two populations share no regex, '
              'so one of them can go inert while the other still reports.',
              file=sys.stderr)
        bad += 1
    # ...and the date cell really is DROPPED rather than compared, which is
    # only visible from the counts: the case above it goes green either way.
    cases += 1
    st = {}
    number_problems(en, page('fr', LOCALIZED_FR.replace('23 Aug 2026',
                                                        '23.8.2026')),
                    'fr', stats=st)
    if (st.get('cells'), st.get('values'), st.get('dates'),
            st.get('prose')) != (8, 11, 1, 4):
        print(f'  selftest FAIL: a reformatted date reached {st}, not 8 cells '
              '/ 11 values / 1 date skipped / 4 prose figures - the date is '
              'being compared rather than skipped, in the cell or in the '
              'sentence, or is not being counted', file=sys.stderr)
        bad += 1

    if bad:
        print(f'\nsite-check: {bad} selftest case(s) failed - this script is '
              'not doing its job, and its anonymity arm fails SILENTLY.',
              file=sys.stderr)
        return 1
    print(f'site-check: selftest ok ({cases} cases, {len(TAGS)} tags, '
          f'{len(BANNED)} ban entries, {len(LANGS)} locales, '
          f'{len(NUMBER_CONV)} number conventions, '
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
    stats = {}
    for base in BASES:
        if base not in found:
            continue          # already named by the roster arm above
        anon = base in ANON
        fail += check_english(f'website/{base}.html', base, anon)
        for l in LANGS:
            fail += check(f'website/{base}.html', f'website/{base}.{l}.html',
                          l, base, anon=anon, stats=stats)
    # What the number arm actually REACHED. A scanner that has quietly stopped
    # matching reads as a clean tree forever - nav-regen.py's picker arm
    # reported 64 pages current for weeks while matching none of them - so an
    # inert one has to show a zero here instead of a green, and a zero is a
    # refusal rather than a quiet pass.
    print(f'number parity: {stats.get("values", 0)} value(s) in '
          f'{stats.get("cells", 0)} figure cell(s) and '
          f'{stats.get("prose", 0)} figure(s) in prose across '
          f'{stats.get("pages", 0)} page(s)'
          + (f', {stats["dates"]} date cell(s) skipped'
             if stats.get('dates') else ''))
    # BOTH POPULATIONS ARE FLOORED, SEPARATELY. One count cannot stand in for
    # the other: the cell matcher and the prose matcher share no regex, so a
    # green total with a zero in it is a matcher that has stopped matching -
    # and that reads as a clean tree forever, which is the failure this whole
    # family of gates keeps growing to refuse.
    for key, what, why in (
            ('values', 'values in table cells',
             'every figure cell has left the site or the cell matcher has '
             'stopped matching'),
            ('prose', 'figures in prose',
             'every sentence on the site has stopped citing a number or the '
             'prose matcher has stopped matching')):
        if not stats.get(key):
            print(f'\nsite-check: the number-parity arm reached NO {what}. '
                  f'Either {why}; it is the second one. Do not read this as a '
                  'green.', file=sys.stderr)
            fail += 1
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
