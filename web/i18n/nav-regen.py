#!/usr/bin/env python3
"""Regenerate the language picker + hreflang alternates on all ten localized
website page families, and the switcher on every manual page, to the full
15-locale set. Idempotent: replaces the existing langsw select / hreflang block /
switcher div in place, base-aware (index picker -> index.<l>.html) and, for
the picker, locale-aware (`selected` lands on the page's own option).

`--check` writes nothing and exits 1 if any file on disk differs from what
this script would produce. Same arm, and the same reason, as the generated
driver `tools/bench2j-gate.py` holds to its parent: committed output that
nothing verifies rots, and rots quietly. That one rotted twice - once two
whole guards behind its parent, once the other way when a hand-added hook
made the documented remedy destructive - and nothing looked until somebody
ran a script by hand. Fix a `--check` failure by RUNNING this script (no arguments), never
by hand-patching a picker or an hreflang block in one file - the next
regeneration undoes a hand patch without saying so.

THE WEBSITE PICKER ARM WAS DEAD UNTIL 23 Aug 2026, and while it was, this
file was not a CI job. `web_picker` wrote a `<span class="langsw">` of
uppercase locale codes and the regex that placed it looked for one, but
every website page has carried a `<select class="langsw">` for some time -
native language names, a `value=` per option and `selected` on the page's
own locale, none of which that function knew how to produce. So it matched
nothing, on all 64 pages of the four core bases, for however long the markup
has been a select. Gating on it then would have reported "every picker is
current" while checking no picker at all, which is the rubber stamp this
repo keeps writing gates to avoid.

`web_picker(base, lang)` now emits the select, byte-identical to what those
pages carry, from the NATIVE map below - and `lang` is a parameter because
`selected` is per-page, which the span shape never needed to know. Verified
on landing: regenerating is a NO-OP over the whole tree, and a census of all
160 pickers - the six page families this script does not touch included -
found every one naming all 16 locales with the right option selected, so the
dead arm had not let a single picker drift while it was inert. That is luck
and not a reason: nothing had checked, which is the argument for the gate.
With all three arms live, `--check` is wired as one.

AND THE SIX HAND-MADE FAMILIES JOINED BASES the same day, once the picker
arm above was live. `indexer` and the five `explained*` families ship 15
locales each and no generator had ever touched them; widening was held back
only while `web_picker` was inert, because six more families under a dead
arm is coverage that reads as coverage and is not. All ten are in BASES now,
so `--check` - the twenty-first gate - holds 160 pages rather than 64.

WHAT THE CENSUS FOUND BEFORE THE WIDENING, over all 160 pages:

  - every picker names the same 16 targets (EN + 15) in the same order,
    with the same native labels and the page's own option `selected`;
  - every hreflang block carries the same 17 entries in the same order;
  - every body cross-page link on the 90 uncovered pages already points at
    a same-language sibling.

So nothing was short of the locale set. What the census DID turn up was a
live defect of the same family that counting alone cannot see: on all 75
localized `explained*` pages, `hreflang="en"` AND `hreflang="x-default"`
pointed at the localized page itself rather than at the English base - the
right seventeen entries with two of the hrefs wrong. Landed hand-made with
those pages on 11 Aug (9cc729700), published to gh-pages, twelve days with
every gate green. Fixed in place first, which is why regenerating with the
widened BASES rewrites NOTHING: the six families were already byte-identical
to this script's output before they joined it. Both arms were verified to
bite on a new family (an option and an alternate each deleted from
explained.fr.html - red under the ten, GREEN under the old four).

TWO THINGS THE WIDENING MADE WORTH ADDING, neither of which the census
could have found by reading pages. First, an inert arm now reports 160
pages current instead of 64, so every arm counts its own substitutions
through `sub1` and dies on the wrong count - see that function for why a
fixed-point check cannot notice this by itself. Second, BASES is held to
the tree by an assert rather than trusted: the six families above sat
uncovered on exactly the strength of nobody comparing this tuple to the
site, and a list is a gate that cannot see the eleventh family.

The same invariant is ALSO held by site-check.py, and deliberately so, since
the two fail differently: this script says "the tree does not match the
generator", which is fixed by rerunning it, and site-check says "this page
names fewer than 15 locales", which is fixed by putting the locale back. A
page nobody regenerates still gets censused.
"""
import re, glob, os, sys

CHECK = '--check' in sys.argv

LANGS = ['fr', 'de', 'it', 'es', 'nl', 'pt', 'sv', 'da', 'nb', 'fi', 'tr', 'ro',
         'he', 'ar', 'fa']
# Uppercase locale codes. The MANUAL switcher carries these; the website
# picker does not - see NATIVE below.
LABEL = {l: l.upper() for l in LANGS}
# The website picker names each language IN that language, which is what a
# reader who cannot read the page they landed on is looking for. Locale
# codes would be a regression, so this map is hand-written rather than
# derived from LABEL. `en` is in it because the picker's first option is the
# English base page.
NATIVE = {
    'en': 'English',    'fr': 'Français',   'de': 'Deutsch',      'it': 'Italiano',
    'es': 'Español',    'nl': 'Nederlands', 'pt': 'Português',   'sv': 'Svenska',
    'da': 'Dansk',      'nb': 'Norsk',      'fi': 'Suomi',        'tr': 'Türkçe',
    'ro': 'Română',     'he': 'עברית',      'ar': 'العربية',     'fa': 'فارسی',
}
assert set(NATIVE) == set(LANGS) | {'en'}, 'NATIVE must name every locale in LANGS, plus en'
# margin-inline-start (not -left) so the picker sits correctly in RTL pages.
PICKER_STYLE = ('font-size:11.5px;opacity:.8;margin-inline-start:10px;background:transparent;'
                'color:inherit;border:1px solid rgba(128,128,128,.4);border-radius:6px;'
                'padding:2px 4px;cursor:pointer;max-width:110px')
SW_STYLE = 'font-size:11.5px;margin-top:6px;color:var(--dim)'

def web_picker(base, lang):
    """The `<select class="langsw">` every website page carries. `lang` is
    the page's OWN locale ('en' on the English base), and it is a parameter
    rather than something derived from `base` because `selected` is the one
    thing that distinguishes a page's picker from its 15 siblings'."""
    opts = []
    for l in ['en'] + LANGS:
        href = f'{base}.html' if l == 'en' else f'{base}.{l}.html'
        sel = ' selected' if l == lang else ''
        opts.append(f'<option value="{href}"{sel}>{NATIVE[l]}</option>')
    return (f'<select class="langsw" aria-label="Language" style="{PICKER_STYLE}" '
            'onchange="location.href=this.value">' + ''.join(opts) + '</select>')

def web_hreflang(base):
    lines = [f'<link rel="alternate" hreflang="en" href="{base}.html">']
    lines += [f'<link rel="alternate" hreflang="{l}" href="{base}.{l}.html">' for l in LANGS]
    lines.append(f'<link rel="alternate" hreflang="x-default" href="{base}.html">')
    return '\n'.join(lines)

def manual_switcher():
    links = ['<a href="/manual">EN</a>'] + \
            [f'<a href="/manual/{l}">{LABEL[l]}</a>' for l in LANGS]
    return f'<div class="langsw" style="{SW_STYLE}">' + ' · '.join(links) + '</div>'

# All TEN families, widened 23 Aug 2026 the moment the picker arm above went
# live - `indexer` and the five `explained*` pages ship 15 locales each and
# their pickers and hreflang blocks had been hand-made since they landed.
# Widening was held back only while `web_picker` was inert, because six more
# families under a dead arm is coverage that reads as coverage and is not.
BASES = ('index', 'features', 'download', 'benchmarks', 'indexer',
         'explained', 'explained-onepass', 'explained-damaged',
         'explained-method', 'explained-numbers')


def localized_bases():
    """Every base on disk with at least one `<base>.<lang>.html` sibling."""
    found = set()
    for p in glob.glob('website/*.html'):
        parts = os.path.basename(p).split('.')
        if len(parts) == 3 and parts[1] in LANGS:
            found.add(parts[0])
    return found


# BASES is HELD to the tree rather than trusted, because the six families it
# just gained had sat uncovered for months on exactly the strength of nobody
# comparing this tuple to the site. A list is a gate that cannot see the
# eleventh family, so the eleventh fails the run by name instead of being
# quietly skipped. Same shape and same argument as the NATIVE/LANGS assert
# above. English-only pages (synology.html, unraid.html) have no localized
# sibling and no picker, so they are absent from both sides and nothing here
# has to special-case them.
_unlisted = localized_bases() - set(BASES)
assert not _unlisted, (
    f'localized page families missing from BASES: {sorted(_unlisted)}. Add '
    'them there - but translate the full locale set FIRST, because this '
    'script emits a picker naming every locale in LANGS, and a '
    'half-translated family would get options pointing at files that do not '
    'exist yet.')


def sub1(pat, repl, s, where, arm, **kw):
    """`re.sub` that REFUSES to match nothing.

    The dead picker arm above is not a failure a fixed-point check can see
    by itself, and that is worth being precise about: a regex that matches
    nothing rewrites nothing, so the file equals itself, `apply` reports it
    unchanged, and `--check` prints that every picker is current. The fixed
    point of an arm that reaches no pages is every page. Widening BASES made
    that worse rather than better - an inert arm now reports 160 pages clean
    instead of 64 - so every arm counts its own substitutions and dies on the
    wrong count, naming the file and the arm. Do NOT drop this to quiet a
    run: a wrong count means the markup moved out from under the PATTERN,
    and the pattern is what needs fixing.
    """
    out, n = re.subn(pat, repl, s, **kw)
    if n != 1:
        raise SystemExit(
            f'nav-regen: the {arm} arm matched {n} times in {where} (expected '
            'exactly 1). The markup has moved out from under this pattern - '
            'fix the PATTERN. Do NOT delete this check: an arm that reaches '
            'no pages reports every one of them as current.')
    return out


def regen_website(path, s, base, lang):
    # The picker is a SELECT. It was a `<span class="langsw">` of anchors
    # once, and this pattern went on looking for that span long after the
    # markup changed - the docstring has the whole finding. Do not narrow
    # `.*?</select>`: a page carries exactly one langsw select, and nothing
    # nests inside it.
    s = sub1(r'<select class="langsw".*?</select>',
             lambda m: web_picker(base, lang), s, path, 'picker', flags=re.S)
    # collapse the existing run of hreflang <link> tags into the fresh block
    return sub1(r'(<link rel="alternate"[^>]*>\s*)+',
                lambda m: web_hreflang(base) + '\n', s, path, 'hreflang', count=1)


def regen_manual(path, s):
    return sub1(r'<div class="langsw".*?</div>', lambda m: manual_switcher(), s,
                path, 'manual switcher', flags=re.S)


def apply(path, fresh):
    """Write `fresh` to `path` unless it already matches. Under --check,
    nothing is written and the path is returned as stale instead."""
    orig = open(path, encoding='utf-8').read()
    if fresh == orig:
        return False
    if not CHECK:
        open(path, 'w', encoding='utf-8').write(fresh)
    return True


stale = []
# ---- website ----
for p in sorted(glob.glob('website/*.html')):
    # `features.de.html` -> base 'features', lang 'de'; `features.html` -> 'en'.
    parts = os.path.basename(p).split('.')
    base, lang = parts[0], (parts[1] if len(parts) == 3 else 'en')
    if base not in BASES:
        continue
    if apply(p, regen_website(p, open(p, encoding='utf-8').read(), base, lang)):
        stale.append(p)
# ---- manual ----
for p in ['docs/MANUAL.html'] + sorted(glob.glob('docs/i18n/MANUAL.*.html')):
    if apply(p, regen_manual(p, open(p, encoding='utf-8').read())):
        stale.append(p)

if CHECK:
    if stale:
        print(f'STALE: {len(stale)} file(s) do not match what nav-regen.py '
              'would produce:', file=sys.stderr)
        for p in stale:
            print('   -', p, file=sys.stderr)
        print('\nRegenerate with `python3 web/i18n/nav-regen.py` (no '
              'arguments). Do NOT hand-patch a picker or an hreflang block '
              'in one file - the next regeneration would silently undo it.',
              file=sys.stderr)
        sys.exit(1)
    print('nav-regen: OK, every generated picker/hreflang/switcher is current')
else:
    print(f'{len(stale)} files regenerated '
          '(pickers/hreflang/switchers -> 15 locales + EN)')
