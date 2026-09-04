#!/usr/bin/env python3
"""Replace the card-layout manual section in English and the 15 translations.

Same shape as `pullsearch/port.py`, and here for the same reason: the
blocks live one file per locale next to this script, rendered FROM
`en.html` so only the prose differs - same tags in the same order, same
`href=`, same `<code>` content. That is checked before anything is
written, because `manual-check.py` compares exactly those things and a
structural slip in one locale is otherwise found at gate time.

This one REPLACES rather than inserts: `docs/MANUAL.html` and every
translated manual already carry a `dash-layout` section, written before
the card-discoverability round landed, so the section is swapped whole.
That makes the script idempotent by construction - it rewrites the same
region every run - and re-runnable when a locale's prose is corrected.

The region is everything from `<h3 id="dash-layout">` up to the `<h2>`
that opens the next chapter; both anchors are locale-independent and both
are asserted to match exactly once, so a drifted page fails loudly rather
than being silently skipped.

  ./port.py            rewrite the section in all 16 manuals
  ./port.py --check    verify block structure only, write nothing
  ./port.py fr de      limit to named locales
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
LANGS = ['fr', 'de', 'it', 'es', 'nl', 'pt', 'sv', 'da', 'nb', 'fi', 'tr', 'ro',
         'he', 'ar', 'fa']

START = '<h3 id="dash-layout">'
END = '<h2 id="adding"'


def blocks(path):
    """{name: html} from a BLOCK-marked file."""
    txt = open(path, encoding='utf-8').read()
    parts = re.split(r'<!--BLOCK (\w+)-->\n', txt)
    if parts[0].strip():
        raise SystemExit(f'{path}: text before the first block marker')
    return dict(zip(parts[1::2], parts[2::2]))


def tagstream(html):
    """Every tag in order, plus each <code>'s content: what parity means."""
    out = []
    for m in re.finditer(r'<(/?)(\w+)([^>]*)>', html):
        href = re.search(r'href="([^"]*)"', m.group(3))
        cls = re.search(r'class="([^"]*)"', m.group(3))
        idd = re.search(r'id="([^"]*)"', m.group(3))
        out.append((m.group(1), m.group(2), href and href.group(1),
                    cls and cls.group(1), idd and idd.group(1)))
    out += [('code:', c) for c in re.findall(r'<code[^>]*>(.*?)</code>', html, re.S)]
    return out


def manual(lang):
    return os.path.join(REPO, 'docs', 'MANUAL.html') if lang == 'en' \
        else os.path.join(REPO, 'docs', 'i18n', f'MANUAL.{lang}.html')


def rewrite(lang, en, check_only):
    tr = blocks(os.path.join(HERE, f'{lang}.html')) if lang != 'en' else en
    if set(tr) != set(en):
        raise SystemExit(f'{lang}: blocks {sorted(tr)} != {sorted(en)}')
    for name in en:
        a, b = tagstream(en[name]), tagstream(tr[name])
        if a != b:
            diff = [(x, y) for x, y in zip(a, b) if x != y][:3]
            raise SystemExit(f'{lang}/{name}: structure differs ({len(a)} vs {len(b)}) {diff}')
    if check_only:
        print(f'{lang}: block OK')
        return

    p = manual(lang)
    s = open(p, encoding='utf-8').read()
    for anchor in (START, END):
        n = s.count(anchor)
        if n != 1:
            raise SystemExit(f'{lang}: anchor {anchor!r}: {n} matches, expected 1')
    i, j = s.index(START), s.index(END)
    if j < i:
        raise SystemExit(f'{lang}: {END!r} precedes {START!r}')
    open(p, 'w', encoding='utf-8').write(s[:i] + tr['sec'].rstrip('\n') + '\n\n' + s[j:])
    print(f'{lang}: section rewritten')


KNOWN_FLAGS = {'--check'}


def unrecognised_argv(argv):
    """First flag-shaped arg outside the known set, or None. A bare locale
    code (e.g. `fr`) is a positional target and never flag-shaped."""
    for a in argv:
        if a.startswith('-') and a not in KNOWN_FLAGS:
            return a
    return None


def main():
    bad_arg = unrecognised_argv(sys.argv[1:])
    if bad_arg is not None:
        print(
            f"port.py: unrecognised argument {bad_arg!r} - known flags are "
            "--check, a locale code, or no args to port all locales. A "
            "stale checkout may be missing a flag this script now supports "
            "- merge origin/main.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    check_only = '--check' in sys.argv
    en = blocks(os.path.join(HERE, 'en.html'))
    langs = [a for a in sys.argv[1:] if not a.startswith('-')] or ['en'] + LANGS
    for lang in langs:
        rewrite(lang, en, check_only)


if __name__ == '__main__':
    main()
