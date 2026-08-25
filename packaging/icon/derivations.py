#!/usr/bin/env python3
"""Read the generators' DERIVATIONS tables and maintain the derived-icon manifests.

    python3 packaging/icon/derivations.py record <generator>
    python3 packaging/icon/derivations.py check  <generator>

Every committed raster under web/icons/ and the two in packaging/icon/ is
GENERATED from one of the three SVG masters beside this file, by
make-favicons.sh, make-icon.sh and make-ico.py. Each of those carries a
DERIVATIONS table naming, one row per output size, which master it comes
from and where the result is committed. This file is the half of that
arrangement a shell script should not be asked to do: after a generator
has written its outputs it calls `record`, and the sha256 each SOURCE had
at that instant is written into ICONS-DERIVED.manifest.

That record is what tools/icons-derived-gate.py holds on every branch
push. qlmanage and sips are both macOS-only, so the gate cannot rerun a
generator on the Linux runners; what it CAN do anywhere is notice that a
master has moved since the raster beside it was made. See that file's
header for the whole design and for what neither half can see.

WHY EACH GENERATOR OWNS ITS OWN ROWS rather than one pass recording
everything. Partial regeneration is the normal case - a change to
icon-small.svg is make-favicons.sh and make-ico.py, and nothing to do
with make-icon.sh - and a recorder that rewrote every row would then
stamp the untouched generator's outputs as current on the strength of a
run that never produced them. That is the one edit the gate cannot see,
made automatic. So `record` replaces the calling generator's rows and
leaves the rest of the file exactly as it found it.

TWO FAMILIES, TWO MANIFESTS, ONE FORMAT, added 24 Aug 2026. The rasters
above are the FIRST generation, straight off the SVG masters. There is a
SECOND: packaging/flatpak/make-icon.sh and packaging/qnap/make-icons.sh
downscale packaging/icon/icon-1024.png - itself an output of the first
generation - into the Flathub icon and the three QTS App Center icons.
Those four had no record of any kind until that day, so a master edited
and a downscale forgotten was invisible; tools/icon-downstream-gate.py is
what holds them now, and this recorder writes their records too.

They are a SEPARATE family with a SEPARATE manifest rather than more rows
in ICONS-DERIVED.manifest, and both halves of that are deliberate. The
records here are keyed by GENERATOR, and `packaging/flatpak/make-icon.sh`
and `packaging/icon/make-icon.sh` share a basename - so one manifest
holding both families would have to key on the full path, which means
rewriting every record tools/icons-derived-gate.py reads and its 42-case
selftest with them, to buy uniformity, with no defect behind it. The two
gates also check genuinely different subjects downstream of the shared
digest: one holds web/site.webmanifest, two pages' `<link rel="icon">`
tags and what the daemon serves; the other holds a hicolor install path
and a qbuild copy list. What IS shared is shared for real and lives here
once - the table format, the digest, the refusals - so a SIXTH generator
anywhere gets the same format and the same errors rather than a third
dialect.

THE TRANSFORM COLUMN is the one format change, and it is optional, so
the first generation's three tables are untouched by it. A row is
`<source> <output> <pixel size> [<transform>]` and the transform defaults
to `scale`, a plain downscale, which is what every row in this directory
is. The second family needs one more: packaging/qnap/make-icons.sh writes
a greyed-out stopped-state icon, because `sips -M` against a grey
ColorSync profile writes NO OUTPUT AT ALL for an image with an alpha
channel and fails silently - that script's own header records that its
first cut shipped a "grey" icon byte-identical to the colour one. A
transform token this file has never heard of is a refusal, not a row it
skips: the whole roster comes from these tables.

NO --selftest HERE, and that is a decision rather than an omission: this
recorder cannot fail quietly. Every way it can go wrong - a row it did
not write, a row it wrote twice, a table it could not read - lands in a
manifest, and each gate holds its manifest to the same tables in both
directions and refuses an empty or partial roster outright. The parsing
is deliberately duplicated in the gates rather than imported, because
this file ships to the public repo (packaging/ does, wholesale) and they
do not, so a shipped generator must never call into tools/.
"""
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

# The transforms a row may name, and what each one means to the gate that
# reads it. `scale` is a plain `sips -z N N` downscale and is the default,
# so a three-field row keeps working unchanged. `grey` is that followed by
# a luma pass, and it is the reason this column exists at all - see the
# docstring. A token neither of these is a refusal: the gates switch arms
# on it, so one they do not recognise is one whose output nothing checks.
TRANSFORMS = ("scale", "grey")
DEFAULT_TRANSFORM = "scale"

_ICON_HEADER = """\
# ICONS-DERIVED.manifest - GENERATED by the three generators in
# packaging/icon/. Do not hand-edit.
#
# One record per (output, source) pair:
#
#     derived <generator> <output> <source> <sha256 of the source when generated>
#
# Held by tools/icons-derived-gate.py, which refuses the tree when a
# master has moved since the raster committed beside it was made. That is
# how an edited SVG whose icons were forgotten becomes a red line instead
# of a stale mark in the tab strip, the taskbar and the install dialog.
#
# Editing a digest here without rerunning the generator that owns it is
# the one edit that gate cannot see, and it defeats it completely. Rerun
# the generator on a mac and commit what it wrote.

"""

_DOWNSTREAM_HEADER = """\
# ICONS-DOWNSTREAM.manifest - GENERATED by the two SECOND-generation
# generators, packaging/flatpak/make-icon.sh and
# packaging/qnap/make-icons.sh. Do not hand-edit.
#
# One record per (output, source) pair:
#
#     derived <generator> <output> <source> <sha256 of the source when generated>
#
# The source is packaging/icon/icon-1024.png, itself an output of the
# first generation next door - so an edit to icon.svg reports that master
# stale first, and these four the moment it is regenerated.
#
# Held by tools/icon-downstream-gate.py, which refuses the tree when the
# master has moved since the downscale committed beside it was made. That
# is how a forgotten downscale becomes a red line instead of a stale icon
# on the Flathub page and in the QTS App Center.
#
# Editing a digest here without rerunning the generator that owns it is
# the one edit that gate cannot see, and it defeats it completely. Rerun
# the generator on a mac and commit what it wrote.

"""

# The two families. A family is a manifest and the generators that write
# into it, and a generator belongs to exactly one. `key` is how a record
# names its generator: the first family's three all live in one directory
# so a basename is unambiguous and is what its records have always held;
# the second family spans two directories and two of the five scripts
# share the basename `make-icon.sh`, so its records name the full path.
# `width` is only the column the records are padded to.
FAMILIES = {
    "icon": {
        "manifest": os.path.join(HERE, "ICONS-DERIVED.manifest"),
        "generators": ("make-favicons.sh", "make-icon.sh", "make-ico.py"),
        "dir": HERE,
        "header": _ICON_HEADER,
        "width": 17,
    },
    "downstream": {
        "manifest": os.path.join(HERE, "ICONS-DOWNSTREAM.manifest"),
        "generators": (
            "packaging/flatpak/make-icon.sh",
            "packaging/qnap/make-icons.sh",
        ),
        "dir": ROOT,
        "header": _DOWNSTREAM_HEADER,
        "width": 29,
    },
}

# Kept for the callers that still name the first family's manifest and
# roster directly. The family table above is what this file works from.
MANIFEST = FAMILIES["icon"]["manifest"]
GENERATORS = FAMILIES["icon"]["generators"]

# Both spellings of the same table, so the shell and python generators
# can carry one format between them:
#     DERIVATIONS="            and     DERIVATIONS = """
TABLE_RE = re.compile(r'^DERIVATIONS\s*=\s*("""|")\n(.*?)^\1', re.M | re.S)

HEADER = _ICON_HEADER


class TableError(Exception):
    """A generator's table could not be read as the rule. Always a refusal."""


def family_of(generator):
    """The family `generator` belongs to, or a TableError naming it.

    A generator in no family is a refusal rather than a family invented
    for it: a record written under a name no gate reads is one nothing
    ever holds, which is the shape this whole arrangement exists to
    refuse.
    """
    for name, fam in FAMILIES.items():
        if generator in fam["generators"]:
            return name, fam
    known = ", ".join(g for f in FAMILIES.values() for g in f["generators"])
    raise TableError(
        f"{generator!r} is not one of the icon generators ({known}). Add it to "
        "FAMILIES here and to the gate that owns its family, or call this with "
        "the name one of them is listed under."
    )


def parse_table(text, where):
    """DERIVATIONS rows as (source, output, size, transform), repo-relative.

    A table that will not parse is an exception and never an empty list.
    The whole roster comes from these tables, so one that silently read
    as empty would record nothing and report success having done so.

    The fourth field is optional and defaults to `scale`; see TRANSFORMS.
    """
    m = TABLE_RE.search(text)
    if not m:
        raise TableError(
            f"{where}: no `DERIVATIONS=` table. Both this recorder and the gate "
            "that owns this generator take the roster from it, so one they "
            "cannot read is one that covers nothing. Restore it rather than "
            "loosening the pattern."
        )
    rows = []
    for n, raw in enumerate(m.group(2).splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) not in (3, 4):
            raise TableError(
                f"{where}: DERIVATIONS row {n} has {len(fields)} field(s), want "
                "`<source> <output> <size> [<transform>]`"
            )
        src, out, size = fields[:3]
        transform = fields[3] if len(fields) == 4 else DEFAULT_TRANSFORM
        if transform not in TRANSFORMS:
            raise TableError(
                f"{where}: DERIVATIONS row {n}: transform {transform!r} is not one of "
                f"{', '.join(TRANSFORMS)}. The gates switch arms on this token, so one "
                "they do not know is an output nothing checks - teach them the "
                "transform rather than dropping the column."
            )
        if not size.isdigit() or int(size) <= 0:
            raise TableError(
                f"{where}: DERIVATIONS row {n}: size {size!r} is not a positive integer"
            )
        for p in (src, out):
            if p.startswith("/") or ".." in p.split("/"):
                raise TableError(
                    f"{where}: DERIVATIONS row {n}: {p!r} must be a path relative to "
                    "the repository root"
                )
        rows.append((src, out, int(size), transform))
    if not rows:
        raise TableError(
            f"{where}: the DERIVATIONS table is empty - an empty roster is not a clean one"
        )
    return rows


def sha256_of(rel):
    path = os.path.join(ROOT, rel)
    if not os.path.isfile(path):
        raise TableError(f"{rel} is not there - it cannot be recorded as a source")
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rows_for(generator):
    """The (output, source, sha256) triples `generator` would record now."""
    _name, fam = family_of(generator)
    path = os.path.join(fam["dir"], generator)
    rel = os.path.relpath(path, ROOT)
    if not os.path.isfile(path):
        raise TableError(f"{rel} is not there")
    with open(path, encoding="utf-8") as f:
        table = parse_table(f.read(), rel)
    # A source is hashed ONCE however many sizes it feeds: the .ico has
    # seven rows and two sources, and seven records for it would say
    # nothing the two do not.
    pairs = sorted({(out, src) for src, out, _size, _tf in table})
    return [(out, src, sha256_of(src)) for out, src in pairs]


def read_manifest(fam):
    """Existing records as {generator: [(output, source, sha), ...]}."""
    if not os.path.isfile(fam["manifest"]):
        return {}
    name = os.path.basename(fam["manifest"])
    out = {}
    with open(fam["manifest"], encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            if fields[0] != "derived" or len(fields) != 5:
                raise TableError(
                    f"{name}:{n}: want "
                    f"`derived <generator> <output> <source> <sha256>`, found {line!r}"
                )
            out.setdefault(fields[1], []).append((fields[2], fields[3], fields[4]))
    return out


def write_manifest(fam, by_gen):
    name = os.path.basename(fam["manifest"])
    width = fam["width"]
    body = []
    for gen in fam["generators"]:
        for out, src, sha in sorted(by_gen.get(gen, [])):
            body.append(f"derived  {gen:<{width}} {out:<34} {src:<30} {sha}\n")
    unknown = sorted(set(by_gen) - set(fam["generators"]))
    if unknown:
        raise TableError(
            f"{name} holds records for {', '.join(unknown)}, which is not one of this "
            "family's generators. Add it to FAMILIES here and to the gate, or delete "
            "the records."
        )
    with open(fam["manifest"], "w", encoding="utf-8") as f:
        f.write(fam["header"] + "".join(body))


def main(argv):
    if len(argv) != 2 or argv[0] not in ("record", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    verb, generator = argv
    try:
        _name, fam = family_of(generator)
    except TableError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2
    name = os.path.basename(fam["manifest"])
    try:
        mine = rows_for(generator)
        existing = read_manifest(fam)
        if verb == "record":
            existing[generator] = mine
            write_manifest(fam, existing)
            print(f"recorded {len(mine)} source digest(s) for {generator}")
            return 0
        if sorted(existing.get(generator, [])) != sorted(mine):
            print(
                f"✗ {name} is not what {generator} would record now.",
                file=sys.stderr,
            )
            print(
                "    Rerun that generator with no arguments and commit what it wrote.",
                file=sys.stderr,
            )
            return 1
    except TableError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1
    print(f"✓ {name} matches what {generator} records")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
