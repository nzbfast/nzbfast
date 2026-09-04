#!/usr/bin/env python3
"""Structural parity for the translated manuals vs docs/MANUAL.html: a FULL
tag census, identical id/anchor sets, byte-identical <code>, lang + switcher.

WHY THE CENSUS IS THE WHOLE POINT. Until 22 Aug 2026 this script compared
five tag counts - h2, h3, pre, table, a - plus the <code> bag. An
English-only addition made of <p>, <li>, <b>, <div> or <tr> was therefore
INVISIBLE to it unless the new text happened to carry a <code>, and that is
not a theoretical hole: it has shipped untranslated copy three times.

  * 28 Jul 2026: two English-only changes were live in all 15 manuals and
    the report named one of them.
  * 3 Aug 2026: a 17-line block surfaced here as a single <code> diff, so
    the reader was told one inline ref had moved when a whole passage was
    missing.
  * 22 Aug 2026: this script named two <code> refs while FIVE blocks were
    actually untranslated - 3abf852d's `nzb360 users:` paragraph, two
    section 6 bullets stranded since 26 Jul (482c619a, 30bd0c90), a
    reverse-sort sentence, and a Group-by-title tail (75fa3c08) that all 15
    translations had condensed away.

None of those three is a case of the check not being run. It ran, and it
under-reported, every time. What actually found the 22 Aug five was a hand
census: count `p li tr td th div ol ul b em h1 h2 h3 pre table a code span`
in English and in each translation, then repeat the count per section to
localise the drift. That census is what this script now is.

TIERS. Fourteen structural tags plus `code` are HARD (they fail the run):

    p li ol ul tr td th div table pre h1 h2 h3 a code

A paragraph, a bullet, a table row, a heading, a link or a code ref that
exists in English and not in a translation is missing copy, full stop.
There is no translation of a <li> that is not a <li>: prose can be
reordered, merged across a sentence boundary, or written with a different
verb, but it cannot legitimately lose the element that carries it.

Three inline tags are a WARNING tier - they are printed, with the same
per-section detail, but they do not fail the run:

    b em span

These three mark emphasis INSIDE a sentence, and emphasis is the one thing
a translator moves legitimately. "the **wall** page's **Group by title**
tail" is two bold runs in English and can be one in a language that puts
both nouns in a single phrase, or three where a compound splits; an <em>
that carries an English idiom's stress may have nothing to sit on in
German. Failing on those trains the reader to wave the gate through, which
costs more than the class of defect they catch - an English-only sentence
made of NOTHING but a <b> is not a shape anything in this manual has ever
had, and would move `p` or `li` too. They stay visible because a large
delta in them (say `b -7` in one section) is a good SMELL of a condensed
block even when the structural counts happen to survive it, which is
exactly how the 22 Aug Group-by-title tail read.

PER SECTION, NOT JUST PER FILE. A whole-file census tells you a locale is
two <li> short; it does not tell you where, and the reader then diffs 1,500
lines in a language they may not read. So the census runs again per section
- the file split on `<h2 id="`, keyed by that id - and any locale with a
delta gets the breakdown printed under it:

    wall {'li': -2, 'b': -7}

The section arm is HARD on the structural tags in its own right, not merely
a diagnostic for the file total. A block that moved from one section to
another nets to zero at file level and is still wrong: the manual's
sections are numbered chapters and a paragraph that changed chapter in
translation is either misplaced or duplicated.

NO BASELINE. Verified 22 Aug 2026, after that day's five blocks were
translated: all 15 locales match English EXACTLY on all 18 counts, both
whole-file and per-section. The widened gate therefore starts clean and
carries no list of known-legit hits. Do not add one to silence a hit
without first reading the rendered page in that language and recording what
made the delta legitimate; the tiering above already covers the only class
that was expected to be noisy.

COMMENTS AND CSS DO NOT COUNT. Tag names inside an HTML comment or a
<style> body are blanked before counting, so a comment that mentions <p>
cannot invent a delta. That hazard used to be handled by asking everyone to
keep comments tag-name-free (TODO paragraph 190), which is the same kind of
promise as the five-tag list this replaces.

House gate conventions: `--selftest` runs the fixture cases below and is
the first thing to run if the census ever reads suspiciously quiet; no
build, no toolchain, about a tenth of a second. This script lives in
web/i18n/ beside check.py and site-check.py rather than in tools/ because
it is part of the translation workflow documented in web/i18n/README.md.

    python3 web/i18n/manual-check.py --selftest
    python3 web/i18n/manual-check.py
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

LANGS = ['fr', 'de', 'it', 'es', 'nl', 'pt', 'sv', 'da', 'nb', 'fi', 'tr', 'ro',
         'he', 'ar', 'fa']

# Hard: an element that carries copy. A missing one is missing copy.
HARD_TAGS = ['p', 'li', 'ol', 'ul', 'tr', 'td', 'th', 'div', 'table', 'pre',
             'h1', 'h2', 'h3', 'a', 'code']
# Warning tier: inline emphasis, which a translator may legitimately fold,
# split or drop. See the docstring.
SOFT_TAGS = ['b', 'em', 'span']
TAGS = HARD_TAGS + SOFT_TAGS

PREAMBLE = '(preamble)'


def strip_noise(s):
    """Blank the inside of HTML comments and of <style>/<script> bodies, so a
    tag name written in prose or in a CSS rule is not counted as an element.
    Replaces with spaces rather than deleting, so offsets and line numbers
    are unchanged."""
    def blank(m):
        return re.sub(r'[^\n]', ' ', m.group(0))
    s = re.sub(r'<!--.*?-->', blank, s, flags=re.S)
    return re.sub(r'<(style|script)\b[^>]*>.*?</\1>', blank, s, flags=re.S)


def ids(s):
    return sorted(re.findall(r'\bid="([^"]+)"', s))


def tagc(s, t):
    return len(re.findall(rf'<{t}\b', s))


# Multiset, not ordered: two adjacent inline <code> refs legitimately swap
# order when a sentence's word order changes in translation. Comparing the
# sorted bag still catches any added / removed / translated code block.
def codes(s):
    return sorted(re.findall(r'<code[^>]*>(.*?)</code>', s, re.S))


def counts(s):
    return {t: tagc(s, t) for t in TAGS}


def sections(s):
    """Split on `<h2 id="...">` into [(key, text)], in document order. The head,
    the nav and everything before the first h2 land under '(preamble)'."""
    out = []
    for part in re.split(r'(?=<h2 id=")', s):
        if not part:
            continue
        m = re.match(r'<h2 id="([^"]+)"', part)
        out.append((m.group(1) if m else PREAMBLE, part))
    return out


def delta(en, tr):
    """{tag: tr - en} for every tag that differs."""
    a, b = counts(en), counts(tr)
    return {t: b[t] - a[t] for t in TAGS if a[t] != b[t]}


def analyse(en_raw, tr_raw, lang):
    """Return (hard, warn, notes): lists of report lines. `hard` non-empty fails
    the run; `warn` is printed and tolerated; `notes` is the per-section
    breakdown, one line per section that differs at all."""
    en, tr = strip_noise(en_raw), strip_noise(tr_raw)
    hard, warn, notes = [], [], []

    if ids(en) != ids(tr):
        only_en = sorted(set(ids(en)) - set(ids(tr)))
        only_tr = sorted(set(ids(tr)) - set(ids(en)))
        hard.append(f'id mismatch only-en={only_en} only-tr={only_tr}')

    d = delta(en, tr)
    hd = {t: v for t, v in d.items() if t in HARD_TAGS}
    sd = {t: v for t, v in d.items() if t in SOFT_TAGS}
    if hd:
        hard.append(f'tag census (structural): {hd}')
    if sd:
        warn.append(f'tag census (inline emphasis): {sd}')

    en_secs, tr_secs = sections(en), sections(tr)
    en_by, tr_by = dict(en_secs), dict(tr_secs)
    only_en = [k for k, _ in en_secs if k not in tr_by]
    only_tr = [k for k, _ in tr_secs if k not in en_by]
    if only_en or only_tr:
        hard.append(f'section mismatch only-en={only_en} only-tr={only_tr}')

    for key, en_body in en_secs:
        if key not in tr_by:
            continue
        sdelta = delta(en_body, tr_by[key])
        if not sdelta:
            continue
        notes.append(f'{key} {sdelta}')
        shard = {t: v for t, v in sdelta.items() if t in HARD_TAGS}
        if shard and not hd:
            # Nets to zero across the file: a block changed section.
            hard.append(f'section {key} drifts {shard} with a matching '
                        f'file total - a block moved section')

    if codes(en) != codes(tr):
        hard.append(f'<code> content differs ({len(codes(en))} vs {len(codes(tr))})')
    if f'lang="{lang}"' not in tr:
        hard.append(f'missing lang="{lang}"')
    if 'langsw' not in tr:
        hard.append('switcher missing')
    return hard, warn, notes


def report(path, hard, warn, notes):
    # A per-section note with nothing at file level is inline emphasis that
    # moved between chapters: not a failure, but not silence either.
    status = 'PROBLEMS' if hard else ('WARN' if (warn or notes) else 'OK')
    print(f'{path}: {status}')
    for x in hard:
        print('   -', x)
    for x in warn:
        print('   ~', x, '(warning only)')
    if notes:
        print('     per-section drift:')
        for n in notes:
            print('       ', n)


# --- selftest ---------------------------------------------------------------

def doc(lang, body, switcher=True):
    """A minimal manual: head with a <style> the census must ignore, an optional
    language switcher, then the body."""
    sw = '<div class="langsw">x</div>\n' if switcher else ''
    return (f'<!doctype html>\n<html lang="{lang}">\n<head>'
            '<style>p{margin:0}</style></head><body>\n'
            f'{sw}{body}\n</body></html>\n')


EN_BODY = """
<h2 id="wall">6 &middot; The poster wall</h2>
<p>The wall shows <em>one</em> card per release.</p>
<ul>
<li>Click a card to open it.</li>
<li>Sort by newest first, or reverse.</li>
</ul>
<h2 id="remotes">12 &middot; Phone &amp; remote apps</h2>
<div class="note"><p><b>nzb360 users:</b> point it at <code>/api</code>.</p></div>
<table><tr><td>App</td><td>Mode</td></tr><tr><td>nzb360</td><td>SAB</td></tr></table>
"""

FAITHFUL = EN_BODY.replace('The wall shows <em>one</em> card per release.',
                           'Le mur montre <em>une</em> carte par version.')

# (name, want_hard, want_warn, translated body)
SELFTEST = [
    ('a faithful translation', False, False, FAITHFUL),
    # The 22 Aug 3abf852d shape: an English-only paragraph carrying no <code>,
    # which is exactly what the five-tag check could not see.
    ('an English-only <p> is dropped', True, True,
     FAITHFUL.replace('<p>Le mur montre <em>une</em> carte par version.</p>\n', '')),
    # The two section 6 bullets stranded since 26 Jul. Losing a bullet loses
    # whatever it contained, so the inline tier speaks up as well; the point of
    # the case is that `li` alone is enough to fail the run.
    ('two <li> bullets condensed away', True, False,
     FAITHFUL.replace('<li>Click a card to open it.</li>\n', '')
             .replace('<li>Sort by newest first, or reverse.</li>\n', '')),
    ('a table row dropped', True, False,
     FAITHFUL.replace('<tr><td>nzb360</td><td>SAB</td></tr>', '')),
    ('a whole <div> block dropped', True, True,
     FAITHFUL.replace(
         '<div class="note"><p><b>nzb360 users:</b> point it at '
         '<code>/api</code>.</p></div>\n', '')),
    # Inline-only drift: legitimate, printed, does not fail.
    ('a bold run folded away', False, True,
     FAITHFUL.replace('<b>nzb360 users:</b>', 'Pour nzb360 :')),
    ('an inline <em> dropped', False, True,
     FAITHFUL.replace('<em>une</em> carte', 'une carte')),
    ('inline warning plus a structural miss', True, True,
     FAITHFUL.replace('<li>Click a card to open it.</li>\n', '')
             .replace('<b>nzb360 users:</b>', 'Pour nzb360 :')),
    # Nets to zero at file level: the paragraph changed chapter. Only the
    # per-section arm can see this one.
    ('a paragraph moved to another section', True, False,
     FAITHFUL.replace('<p>Le mur montre <em>une</em> carte par version.</p>\n', '')
             .replace('<h2 id="remotes">12 &middot; Phone &amp; remote apps</h2>',
                      '<h2 id="remotes">12 &middot; Phone &amp; remote apps</h2>\n'
                      '<p>Le mur montre <em>une</em> carte par version.</p>')),
    ('a <code> ref translated', True, False,
     FAITHFUL.replace('<code>/api</code>', '<code>/api-fr</code>')),
    ('an id lost', True, False, FAITHFUL.replace(' id="wall"', '')),
    # A comment that names tags must not invent a delta.
    ('tag names inside an HTML comment', False, False,
     FAITHFUL + '\n<!-- a <p>, a <div> and two <li> live above -->'),
]


def selftest():
    en = doc('en', EN_BODY)
    cases = [(n, h, w, doc('fr', b)) for n, h, w, b in SELFTEST]
    # The two head arms, which are about the document rather than its body.
    cases.append(('the lang attribute missing', True, False, doc('en', FAITHFUL)))
    cases.append(('the switcher missing', True, False,
                  doc('fr', FAITHFUL, switcher=False)))
    bad = 0
    for name, want_hard, want_warn, tr in cases:
        hard, warn, _notes = analyse(en, tr, 'fr')
        got_hard, got_warn = bool(hard), bool(warn)
        if got_hard != want_hard or got_warn != want_warn:
            print(f'  selftest FAIL: {name}: hard={got_hard} (want {want_hard}) '
                  f'warn={got_warn} (want {want_warn})', file=sys.stderr)
            for x in hard + warn:
                print('      ', x, file=sys.stderr)
            bad += 1
    # An unknown flag must be a REFUSAL naming it, never a silent skip that
    # falls through to the ordinary clean gate verdict about a request
    # nobody honoured - the shape reproduced live on size-gate.py 31 Aug 2026.
    for args, want_bad in (
        (['--this-flag-does-not-exist'], True),
        ([], False),
        (['--selftest'], False),
    ):
        got_bad = unrecognised_argv(args) is not None
        if got_bad != want_bad:
            print(
                f'  selftest FAIL: unrecognised_argv({args!r}) flagged={got_bad},'
                f' wanted {want_bad}',
                file=sys.stderr,
            )
            bad += 1

    if bad:
        print(f'\nmanual-check: {bad} selftest case(s) failed - the census is '
              'not doing its job.', file=sys.stderr)
        return 1
    print(f'manual-check: selftest ok ({len(cases)} cases, {len(TAGS)} tags: '
          f'{len(HARD_TAGS)} hard, {len(SOFT_TAGS)} warning)')
    return 0


KNOWN_FLAGS = {'--selftest'}


def unrecognised_argv(argv):
    """First arg outside the known set, or None."""
    for a in argv:
        if a not in KNOWN_FLAGS:
            return a
    return None


def main():
    if '--selftest' in sys.argv:
        return selftest()

    bad_arg = unrecognised_argv(sys.argv[1:])
    if bad_arg is not None:
        print(
            f'manual-check: unrecognised argument {bad_arg!r} - known flags '
            'are --selftest, or no args for the gate. A stale checkout may '
            'be missing a flag this script now supports - merge '
            'origin/main.',
            file=sys.stderr,
        )
        return 1

    en_path = os.path.join(ROOT, 'docs', 'MANUAL.html')
    with open(en_path, encoding='utf-8') as f:
        en = f.read()
    fail = warned = 0
    for l in LANGS:
        rel = f'docs/i18n/MANUAL.{l}.html'
        with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
            tr = f.read()
        hard, warn, notes = analyse(en, tr, l)
        report(rel, hard, warn, notes)
        fail += bool(hard)
        warned += bool((warn or notes) and not hard)
    sys.stdout.flush()
    if fail:
        print(f'\nmanual-check: {fail} of {len(LANGS)} manual(s) differ '
              'structurally from docs/MANUAL.html. A tag that carries copy is '
              'missing from the translation, or sits in a different chapter '
              'from the English one. Translate the block where it belongs; do '
              'not delete the English one. The per-section breakdown above '
              'names the chapter to look in.', file=sys.stderr)
    elif warned:
        print(f'\nmanual-check: {warned} manual(s) differ only in inline '
              'emphasis (b/em/span), which a translator may legitimately fold '
              'or split. Read the section named above before assuming it is '
              'fine: a large inline delta is a good smell of a condensed '
              'block.')
    return 1 if fail else 0


if __name__ == '__main__':
    sys.exit(main())
