#!/usr/bin/env python3
"""Rewrite internal cross-page links on every localized website page so a
visitor stays in-language: href="index.html" -> href="index.<L>.html" for
all ten site families, everywhere EXCEPT the hreflang <link> block and the
langsw picker span (both of which must keep the bare English filenames and
their explicit per-language names). MANUAL.html and absolute URLs untouched.
Idempotent.

`--check` writes nothing and exits 1 if any page on disk differs from what
this script would produce. Same arm, and the same reason, as the generated
driver `tools/bench2j-gate.py` holds to its parent: committed output that
nothing verifies rots, and rots quietly - that one rotted twice before
anybody looked. Verified clean 23 Aug 2026 on all 150 pages, before AND
after BASES was widened from the four core marketing pages to all ten
families (see BASES below - the six that joined were already fully
in-language, so the widening moved no byte of any page and bought 90 pages
of protection). Fix a failure by RUNNING this script (no arguments), never
by hand-patching one href.

The trailing LEAK scan is a different question from `--check` and both are
worth having: `--check` asks whether the file matches this script's output,
the leak scan asks whether a bare cross-page href survived outside the
picker and the hreflang block. A file can pass the first and fail the
second if the rewrite itself is wrong.

THIS SCRIPT HAD NO `--selftest` UNTIL 23 Aug 2026, on the reasoning
(26296f256) that it runs against its own committed output - a fixed point
with no judgement to get wrong. That reasoning is sound about the OUTPUT and
incomplete about the PATTERN, which is the half a fixed point cannot see. A
regex that matches nothing rewrites nothing, so the file equals itself,
`--check` reports every page current, and the leak scan - which shares `PAT`
with the rewrite - finds nothing to report either. Measured that day on
origin/main: breaking `PAT`'s literal `href="` to `hrefZZZ="` still printed
"OK, every page matches the cross-link rewrite" AND "cross-link verify: OK",
and exited 0. Both arms dead, one silent green line. The fixed point of an
arm that reaches no pages is every page - nav-regen.py's picker arm passed
that way on all 64 of its pages for months, which is the sibling finding
this one was derived from.

WHY nav-regen's FIX DOES NOT TRANSFER, and why this file gets a selftest
instead of a `sub1`. nav-regen's arms replace a block that is ALWAYS present
on every page - one picker, one hreflang run, one switcher - so the correct
count is exactly 1 everywhere and `n != 1` is a sound guard. This arm
rewrites only hrefs that have DRIFTED back to English, so on a converged
tree it correctly matches nothing: measured 23 Aug 2026, all 150 localized
pages yield ZERO matches after the protection step. "Matched nothing" is the
HEALTHY state here and is indistinguishable, from the tree alone, from "the
pattern is dead", so a per-page or per-run `> 0` guard would fire on all 150
pages of a correct tree. Nothing about the real pages can settle the
question. `--selftest` settles it from the other end: it drives `relink` and
the leak scan over synthetic fixture pages carrying known English hrefs and
asserts they are rewritten and flagged, which proves the transform is alive
whether or not any real page still has drift left in it. Same convention as
nearly every gate in CLAUDE.md's list, and `web/i18n/site-check.py` is the
model for the frozen-roster shape.

    python3 web/i18n/site-crosslink.py --selftest
    python3 web/i18n/site-crosslink.py --check

ONE PROTECTION IS VESTIGIAL, and harmlessly so - re-confirmed by measurement
23 Aug 2026 rather than carried forward on the earlier argument. The `<span
class="langsw">` that `stash` protects has been a `<select class="langsw">`
on every page for some time (see nav-regen.py's docstring, where the same
drift left a whole arm inert): the census that day found ZERO langsw spans
and 160 langsw selects. It costs nothing here, and the reason is sharper
than "a select carries value=": every one of those 160 pickers does contain
the four characters `href`, in `onchange="location.href=this.value"`, and
PAT wants `href="` followed immediately by a base name, which `href=this`
can never be. The option targets are `value="index.html"`, also out of
reach. So the picker is unreachable by PAT twice over, and the SELFTEST
still drives the span protection at an anchor-shaped fixture - so if the
picker ever goes back to anchors the protection is known to work rather than
hoped to. Do not delete it on the strength of it being inert today.
"""
import re, glob, os, sys

CHECK = '--check' in sys.argv
SELFTEST = '--selftest' in sys.argv

# All TEN families, widened 23 Aug 2026 from the four core marketing pages.
# `indexer` and the five `explained*` pages ship 15 locales each and their
# cross-page links were hand-made; measured before the widening, all 90 of
# those pages were already fully in-language, so this is a zero-byte change to
# the site and pure protection - `--check` (CI's twentieth gate) now holds 150
# pages rather than 60, and the LEAK scan below reaches the six new families'
# hrefs as well. Do not narrow this back to the four: an un-listed family is
# one whose next hand-patched href nothing undoes and nothing reports, which
# is how those same six ended up with a hand-made hreflang block that pointed
# `en` and `x-default` at the localized page for twelve days.
BASES = ['index', 'features', 'download', 'benchmarks', 'indexer',
         'explained', 'explained-onepass', 'explained-damaged',
         'explained-method', 'explained-numbers']
LANGS = ['fr', 'de', 'it', 'es', 'nl', 'pt', 'sv', 'da', 'nb', 'fi', 'tr', 'ro',
         'he', 'ar', 'fa']
# Both rosters are PINNED, for the two different things a silent shortening
# would cost. The selftest gives every base a case of its own, driven off
# BASES - so a base dropped from that list deletes its own test and leaves a
# green run one family short, the exact shape site-check.py's BANNED_EXPECTED
# and LANGS_EXPECTED refuse. LANGS is not in `PAT` at all, but it is half the
# page population both arms walk, so a locale quietly leaving it takes ten
# pages out of the leak scan with nothing to say so. Raise either when the
# site really gains a family or a locale; LOWERING one is a claim that the
# site has withdrawn it, never a way to quieten a red run.
BASES_EXPECTED = 10
LANGS_EXPECTED = 15
# Longest first. `explained` and `explained-onepass` share a prefix, and
# while Python's alternation does backtrack into the later branch, spelling
# the order out means the regex does not depend on that to be right.
PAT = re.compile(r'href="(' + '|'.join(sorted(BASES, key=len, reverse=True))
                 + r')\.html(#[^"]*)?"')
# `relink` reads group 1 as the base and group 2 as the optional fragment, and
# `PAT.findall` hands the leak report a 2-tuple per hit on the same footing.
# Stated here rather than left to be discovered: dropping or adding a group is
# the one edit to this pattern that a fixture case cannot report cleanly - it
# takes `relink` out at `m.group(2)` with an IndexError before the selftest can
# say which shape broke.
assert PAT.groups == 2, 'PAT must keep exactly two groups: the base and the fragment'

# The two regions that legitimately hold bare + explicit per-language
# filenames: the hreflang alternates and the langsw picker. ONE roster, read
# by both arms - `relink` stashes these and puts them back, the leak scan
# blanks them - because they were two hand-kept copies of the same pair of
# patterns until 23 Aug 2026, and a protection that drifts between the arms
# means the rewrite and the verify disagree about what is out of bounds. It
# also gives the selftest one place to drive.
PROTECT = [
    (r'<link rel="alternate"[^>]*>', 0),
    (r'<span class="langsw".*?</span>', re.S),
]


def relink(s, lang):
    """The transform, as a pure function of the page text."""
    protected = {}
    def stash(m):
        key = f'\x00{len(protected)}\x00'
        protected[key] = m.group(0)
        return key
    for pat, flags in PROTECT:
        s = re.sub(pat, stash, s, flags=flags)
    # Rewrite the rest.
    s2 = PAT.sub(lambda m: f'href="{m.group(1)}.{lang}.html{m.group(2) or ""}"', s)
    for k, v in protected.items():
        s2 = s2.replace(k, v)
    return s2


def leaks(s):
    """Bare cross-page hrefs surviving OUTSIDE the protected regions - the
    verify arm, asking a different question from `--check`. Shares `PAT` and
    `PROTECT` with `relink`, which is why one dead pattern would take both
    arms down together and why the selftest drives this one too."""
    for pat, flags in PROTECT:
        s = re.sub(pat, '', s, flags=flags)
    return PAT.findall(s)


def rewrite(path, lang):
    """Bring one page up to date, or - under --check - report that it is not.
    Returns True if the file on disk differs from the transform's output."""
    orig = open(path, encoding='utf-8').read()
    fresh = relink(orig, lang)
    if fresh == orig:
        return False
    if not CHECK:
        open(path, 'w', encoding='utf-8').write(fresh)
    return True


# ---------------------------------------------------------------- selftest

# One fixture body per shape, frozen: (name, source, want_out, want_leaks).
# `want_out` is what `relink(source, 'fr')` must produce and `want_leaks` how
# many hits the verify arm must find in `source`. A case that expects a
# rewrite is what proves PAT is alive; a case that expects none is what
# proves the protections and the exclusions are. Do NOT trim this roster to
# make a run quieter - every entry is a shape that has to keep working for
# either arm's silence to mean anything.
FIXTURES = [
    ('bare cross-page href is rewritten',
     '<a href="features.html">Features</a>',
     '<a href="features.fr.html">Features</a>', 1),
    ('a fragment survives the rewrite',
     '<a href="index.html#speed">Speed</a>',
     '<a href="index.fr.html#speed">Speed</a>', 1),
    ('an already-localized href is left alone',
     '<a href="index.fr.html">Accueil</a>',
     '<a href="index.fr.html">Accueil</a>', 0),
    ('an absolute URL is left alone',
     '<a href="https://nzbfast.org/index.html">home</a>',
     '<a href="https://nzbfast.org/index.html">home</a>', 0),
    ('MANUAL.html is not a site family',
     '<a href="MANUAL.html">Manual</a>',
     '<a href="MANUAL.html">Manual</a>', 0),
    ('the hreflang block is protected',
     '<link rel="alternate" hreflang="en" href="index.html">',
     '<link rel="alternate" hreflang="en" href="index.html">', 0),
    ('the langsw picker is protected',
     '<span class="langsw"><a href="index.html">EN</a>\n'
     '<a href="features.html">FR</a></span>',
     '<span class="langsw"><a href="index.html">EN</a>\n'
     '<a href="features.html">FR</a></span>', 0),
    # The one that proves the protections do not swallow the whole page: a
    # stray body href sitting right beside a protected block still has to be
    # rewritten, and still has to be reported.
    ('a stray href beside a protected block is still caught',
     '<link rel="alternate" hreflang="en" href="index.html">\n'
     '<a href="download.html">Get it</a>',
     '<link rel="alternate" hreflang="en" href="index.html">\n'
     '<a href="download.fr.html">Get it</a>', 1),
]


def selftest():
    bad = 0
    cases = 0

    for name, src, want, want_leaks in FIXTURES:
        cases += 1
        got = relink(src, 'fr')
        if got != want:
            print(f'  selftest FAIL: {name}\n      got  {got!r}\n'
                  f'      want {want!r}', file=sys.stderr)
            bad += 1
        cases += 1
        n = len(leaks(src))
        if n != want_leaks:
            print(f'  selftest FAIL: {name}: verify arm found {n} leak(s), '
                  f'expected {want_leaks}', file=sys.stderr)
            bad += 1
        # Idempotence, at every shape rather than at one. The script's whole
        # contract with `--check` is that a second run is a no-op.
        cases += 1
        if relink(got, 'fr') != got:
            print(f'  selftest FAIL: {name}: relink is not idempotent',
                  file=sys.stderr)
            bad += 1

    # Every family, at a case of its own. The hand-written shapes above only
    # name two bases, which leaves the rest of the alternation - and the
    # longest-first ordering that keeps `explained-onepass` from being read
    # as `explained` - resting on the assumption that PAT is built from the
    # list. Driven off BASES, so a family ADDED without a translation gets
    # tested for free; BASES_EXPECTED below is what sees a family removed.
    for base in BASES:
        cases += 1
        src = f'<a href="{base}.html">x</a>'
        if relink(src, 'fr') != f'<a href="{base}.fr.html">x</a>':
            print(f'  selftest FAIL: {base}.html is not rewritten - check the '
                  'alternation and its longest-first ordering', file=sys.stderr)
            bad += 1
        cases += 1
        if len(leaks(src)) != 1:
            print(f'  selftest FAIL: a bare {base}.html href passes the verify '
                  'arm', file=sys.stderr)
            bad += 1

    cases += 1
    if len(BASES) != BASES_EXPECTED:
        print(f'  selftest FAIL: BASES is {len(BASES)} families, '
              f'BASES_EXPECTED says {BASES_EXPECTED}. The loop above only '
              'tests the families still on the list, so this line is the only '
              'thing that can see a deletion.', file=sys.stderr)
        bad += 1
    cases += 1
    if len(LANGS) != LANGS_EXPECTED:
        print(f'  selftest FAIL: LANGS is {len(LANGS)} locales, '
              f'LANGS_EXPECTED says {LANGS_EXPECTED}. Both arms walk BASES x '
              'LANGS, so a locale dropped from here silently takes ten pages '
              'out of the leak scan.', file=sys.stderr)
        bad += 1

    if bad:
        print(f'site-crosslink selftest: {bad} failure(s) in {cases} cases',
              file=sys.stderr)
        return 1
    print(f'site-crosslink selftest: OK ({cases} cases)')
    return 0


if SELFTEST:
    sys.exit(selftest())

# -------------------------------------------------------------------- main

stale = []
for base in BASES:
    for lang in LANGS:
        p = f'website/{base}.{lang}.html'
        if os.path.exists(p):
            if rewrite(p, lang):
                stale.append(p)
                print(('stale' if CHECK else 'relinked'), p)
if CHECK and stale:
    print(f'\nSTALE: {len(stale)} page(s) do not match what site-crosslink.py '
          'would produce. Regenerate with `python3 web/i18n/site-crosslink.py` '
          '(no arguments); do NOT hand-patch one href, the next run would '
          'silently undo it.', file=sys.stderr)
    sys.exit(1)
print(f'{len(stale)} files rewritten' if not CHECK
      else 'site-crosslink: OK, every page matches the cross-link rewrite')

# Verify: no bare cross-page href leaked outside picker/hreflang.
bad = 0
for base in BASES:
    for lang in LANGS:
        p = f'website/{base}.{lang}.html'
        if not os.path.exists(p):
            continue
        found = leaks(open(p, encoding='utf-8').read())
        if found:
            bad += 1
            print(f'  LEAK {p}: {found[:6]}')
print('cross-link verify:', 'OK' if not bad else f'{bad} files with leaks')
sys.exit(1 if bad else 0)
