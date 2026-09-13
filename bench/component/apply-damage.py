#!/usr/bin/env python3
"""Apply a recorded PAR2 damage map to a copy of a pristine corpus.

    apply-damage.py <pristine-dir> <damaged-dir> <map-file> [--block-size N]

Two map dialects, told apart by the first line.

BLOCK MAPS (the original, `map-*.txt`): line 1 is the block size, every
further line is "<volume> <block index>". One byte mid-block is flipped
(XOR 0xFF) per entry, which is exactly what `harness/assemble.ps1` does
on Windows. Both rigs must apply the SAME map rather than re-rolling
damage from a seed, or the machines stop being comparable - a corpus
whose damaged blocks land in different volumes changes how much each
tool has to read, and that difference is worth more than the margins
being measured.

ARTICLE MAPS (`amap-*.txt`, added 6 Sep 2026 for the scenario legs):
line 1 is "ARTICLE <bytes>" - the yEnc article payload size, 768000 on
the shapes the rig builds - and every further line is one of

    <file> <index>              one article gone
    <file> <first>-<last>       a contiguous run of articles gone
    DELETE <file>               the whole member never arrived

The span is ZERO-FILLED, not byte-flipped, because that is what the
wire actually does: an article that never arrives leaves the decoder a
hole it fills with nothing, and the member keeps its declared length.
A flipped byte is a different fixture - it is a corrupted article that
DID arrive - and the two damage the same block count while giving the
verifier different work.

Why article units at all: a reader has "two articles missing", not
"three blocks". With 1 MiB slices one 750 KiB article damages one or
two blocks depending on where it lands, so the block count is a
CONSEQUENCE of the article map and not an input to it. Pass
`--block-size N` and this script prints the block count the map
implies at that slice size, which is the number the results page
carries in its footnote. It is a report, never a check: the tools
decide for themselves what they read.
"""
import os
import shutil
import subprocess
import sys

ART_PREFIX = "ARTICLE"


def clone_tree(src, dst):
    """Copy the corpus, cheaply where the filesystem allows it.

    An APFS `cp -c` is a clone, so a damaged copy of a 10 GiB fixture
    costs the blocks it damages rather than 10 GiB, and the scenario
    rig holds eight of them. It falls back to a real copy everywhere
    else, which is what this script did before.
    """
    if os.path.exists(dst):
        shutil.rmtree(dst)
    if sys.platform == "darwin":
        if subprocess.call(["cp", "-c", "-R", src, dst]) == 0:
            return
        if os.path.exists(dst):
            shutil.rmtree(dst)
    shutil.copytree(src, dst)


def apply_blocks(dst, lines):
    block_size = int(lines[0])
    handles = {}
    try:
        for line in lines[1:]:
            name, block = line.split()
            if name not in handles:
                handles[name] = open(os.path.join(dst, name), "r+b")
            fh = handles[name]
            offset = int(block) * block_size + block_size // 2
            fh.seek(offset)
            byte = fh.read(1)
            if not byte:
                sys.exit(f"{name}: block {block} is past end of file")
            fh.seek(offset)
            fh.write(bytes([byte[0] ^ 0xFF]))
    finally:
        for fh in handles.values():
            fh.close()
    print(f"{dst}: damaged {len(lines) - 1} blocks in {len(handles)} volumes")


def apply_articles(dst, lines, block_size):
    art = int(lines[0].split()[1])
    spans = []          # (file, start byte, end byte)
    deleted = []
    articles = 0
    for line in lines[1:]:
        head, rest = line.split(None, 1)
        if head == "DELETE":
            deleted.append(rest.strip())
            continue
        first, _, last = rest.strip().partition("-")
        first = int(first)
        last = int(last) if last else first
        if last < first:
            sys.exit(f"{head}: article range {rest} runs backwards")
        spans.append((head, first * art, (last + 1) * art))
        articles += last - first + 1

    handles = {}
    try:
        for name, start, end in spans:
            if name not in handles:
                path = os.path.join(dst, name)
                if not os.path.exists(path):
                    sys.exit(f"{name}: no such member in {dst}")
                handles[name] = open(path, "r+b")
            fh = handles[name]
            size = os.path.getsize(os.path.join(dst, name))
            if start >= size:
                sys.exit(f"{name}: article span {start} is past end of file")
            fh.seek(start)
            # Never extend the member: an article past the end of the last
            # one is short, and a fixture whose length disagrees with its
            # FileDesc takes a completely different door through verify.
            fh.write(b"\0" * (min(end, size) - start))
    finally:
        for fh in handles.values():
            fh.close()
    for name in deleted:
        path = os.path.join(dst, name)
        if not os.path.exists(path):
            sys.exit(f"{name}: no such member in {dst}")
        os.remove(path)

    note = ""
    if block_size:
        # A span damages every slice it touches: floor(start) .. ceil(end).
        # Counted per member as a set, so two articles inside one slice are
        # one damaged block and not two.
        touched = set()
        for name, start, end in spans:
            for b in range(start // block_size, -(-end // block_size)):
                touched.add((name, b))
        note = f", {len(touched)} damaged block(s) at {block_size} B slices"
    print(
        f"{dst}: {articles} article(s) zeroed in {len(handles)} member(s), "
        f"{len(deleted)} member(s) deleted{note}"
    )


def main():
    args = [a for a in sys.argv[1:]]
    block_size = 0
    if "--block-size" in args:
        i = args.index("--block-size")
        block_size = int(args[i + 1])
        del args[i : i + 2]
    if len(args) != 3:
        sys.exit(__doc__)
    src, dst, mapfile = args

    clone_tree(src, dst)

    with open(mapfile) as fh:
        lines = [
            line.strip()
            for line in fh
            if line.strip() and not line.lstrip().startswith("#")
        ]
    if lines[0].startswith(ART_PREFIX):
        apply_articles(dst, lines, block_size)
    else:
        apply_blocks(dst, lines)


if __name__ == "__main__":
    main()
