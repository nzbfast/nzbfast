#!/usr/bin/env python3
"""Insert the pull-search manual blocks into the 15 translated manuals.

The blocks live one file per locale next to this script, rendered FROM
`en.html` so only the prose differs: same tags in the same order, same
`<code>` content, same `href=`. That is checked here before anything is
written, because `manual-check.py` compares exactly those things and a
structural slip in one locale is otherwise found at gate time.

Anchors are locale-independent on purpose (an `id=`, or a `<code>` whose
content is byte-identical everywhere), and every insertion asserts a
single match so a drifted page fails loudly instead of being skipped.

  ./port.py            insert (idempotent: refuses a file already done)
  ./port.py --check    verify block structure only, write nothing
"""
import json
import re
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
LANGS = ['fr', 'de', 'it', 'es', 'nl', 'pt', 'sv', 'da', 'nb', 'fi', 'tr', 'ro',
         'he', 'ar', 'fa']

# Two per-locale corrections that ride along; see fixes.json's header.
FIXES = json.load(open(os.path.join(HERE, 'fixes.json'), encoding='utf-8'))


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


def sub1(s, pat, repl, what):
    s2, n = re.subn(pat, repl, s, count=1)
    if n != 1:
        raise SystemExit(f'   anchor {what!r}: {n} matches, expected 1')
    return s2


def insert(lang, en, check_only):
    bp = os.path.join(HERE, f'{lang}.html')
    tr = blocks(bp)
    if set(tr) != set(en):
        raise SystemExit(f'{lang}: blocks {sorted(tr)} != {sorted(en)}')
    for name in en:
        a, b = tagstream(en[name]), tagstream(tr[name])
        if a != b:
            diff = [(x, y) for x, y in zip(a, b) if x != y][:3]
            raise SystemExit(f'{lang}/{name}: structure differs ({len(a)} vs {len(b)}) {diff}')
    if check_only:
        print(f'{lang}: blocks OK')
        return

    p = os.path.join(REPO, 'docs', 'i18n', f'MANUAL.{lang}.html')
    s = open(p, encoding='utf-8').read()
    if 'id="pullsearch"' in s:
        raise SystemExit(f'{lang}: already ported')

    # 1. the §5 methods-table row, after the Browse-index row: the row
    #    that links to Automation is the next one in every locale.
    i = s.index('id="adding"')
    j = s.index('<h3', i)
    region = s[i:j]
    region = sub1(region, r'<tr><td><b>[^<]*</b></td><td>[^<]*<a href="#automation">',
                  lambda m: tr['row'] + m.group(0), 'table row')
    s = s[:i] + region + s[j:]
    # 2. the section, before the nzblnk subsection
    s = sub1(s, re.escape('<h3 id="nzblnk">'), lambda m: tr['sec'] + m.group(0), 'section')
    # 3. the settings-reference entry, before Indexing - located by the
    #    last <h3 in front of the group name in that section's table.
    k = s.index('alt.binaries.teevee')
    h = s.rindex('<h3', 0, k)
    s = s[:h] + tr['set'] + s[h:]
    # 4. the watchlist paragraph, at the foot of that subsection
    s = sub1(s, re.escape('<h3 id="auto-rss">'), lambda m: tr['watch'] + m.group(0), 'watchlist')
    # 5. the stale sentence (exactly once), and the settings-card name
    #    (every mention, and there has to be at least one).
    fx = FIXES[lang]
    old, new = fx['sentence']
    s = sub1(s, re.escape(old), lambda m, n=new: n, 'note sentence')
    old, new = fx['card']
    n = s.count(old)
    if n < 1:
        raise SystemExit(f'   card name {old!r}: not found')
    s = s.replace(old, new)

    open(p, 'w', encoding='utf-8').write(s)
    print(f'{lang}: ported')


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
    langs = [a for a in sys.argv[1:] if not a.startswith('-')] or LANGS
    for lang in langs:
        insert(lang, en, check_only)


if __name__ == '__main__':
    main()
