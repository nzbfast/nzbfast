#!/usr/bin/env python3
"""classify.py - grade one client run of one nested-corpus leg.

    classify.py <manifest.json> <outdir> <client-exit-code> [--skip-dirs a,b]

Prints one line:  class=<c> matched=<k>/<n> [missing=a,b] [leftover=x,y]

Classes (the "automatic vs manual intervention" framing):
  auto-complete        every manifest payload exists under <outdir> with a
                       matching sha256 (found anywhere in the tree)
  manual-intervention  the client finished without an error but the final
                       payloads are not all there - an operator would have
                       to keep unpacking or repairing by hand
  fail                 nonzero exit / timeout, and no complete payload set

--skip-dirs NAMES excludes directory names anywhere under <outdir> from the
walk. It exists because a client may STAGE a payload inside its own delivery
directory: Weaver writes `complete/.weaver-staging/<job>/` and moves the file
out when the job finishes, so a full-size payload sitting there is work in
progress and NOT a delivered result. Counting it graded three Weaver legs
auto-complete whose job never finished and whose log recorded no completion,
alongside an `inner.rar.partial` in the same directory. Every other client
already keeps its intermediate area OUTSIDE the tree we grade (nzbget
inter/, SAB incomplete/, rustnzb incomplete/), so this is what makes Weaver
graded on the same footing rather than on a more generous one.
"""

import hashlib
import json
import os
import sys


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    argv = sys.argv[1:]
    skip = set()
    if "--skip-dirs" in argv:
        i = argv.index("--skip-dirs")
        skip = {d for d in argv[i + 1].split(",") if d}
        del argv[i:i + 2]
    # --names-strict: deobfuscation grading. The nested round asks "did
    # the payload bytes come out"; a deobf round asks "did they come out
    # UNDER THE RIGHT NAME" - bytes-right-name-wrong is precisely the
    # defect those legs exist to measure, so content found elsewhere is
    # counted separately as misnamed= and caps the class at
    # manual-intervention (an operator must rename by hand). A payload
    # with a "path" field must sit at that outdir-relative path (tree
    # legs); otherwise its exact basename anywhere counts. Default
    # behavior without the flag is unchanged for the old rounds.
    strict = False
    if "--names-strict" in argv:
        strict = True
        argv.remove("--names-strict")
    if len(argv) != 3:
        sys.exit(__doc__)
    manifest = json.load(open(argv[0]))
    outdir, rc = argv[1], int(argv[2])

    # Index every file under outdir by basename and by size (clients
    # differ on layout, and some rename the extracted payload to the job
    # name - SAB renames a lone unpacked file to the NZB name). A payload
    # is "present" when its exact bytes exist anywhere in the tree, so we
    # match on content (size + sha256), not on the corpus-side basename.
    by_name, by_size = {}, {}
    for root, dirs, files in os.walk(outdir):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in files:
            path = os.path.join(root, name)
            by_name.setdefault(name, []).append(path)
            try:
                by_size.setdefault(os.path.getsize(path), []).append(path)
            except OSError:
                pass

    def content_ok(cand, p):
        try:
            return os.path.getsize(cand) == p["bytes"] and sha256(cand) == p["sha256"]
        except OSError:
            return False

    missing, matched, misnamed = [], 0, []
    for p in manifest["payloads"]:
        ok = False
        if strict and p.get("path"):
            # Tree leg: the payload must sit AT its expected relative
            # path. The job root differs per client (outdir/<job>/...),
            # so any file whose outdir-relative path ends with the
            # expected path counts - a component-aligned suffix, never a
            # substring, so "S_01.VOB" cannot satisfy "VTS_01.VOB".
            want = p["path"].replace("\\", "/").strip("/").split("/")
            for cands in by_name.get(want[-1], []):
                rel = os.path.relpath(cands, outdir).replace(os.sep, "/").split("/")
                if rel[-len(want):] == want and content_ok(cands, p):
                    ok = True
                    break
        else:
            # Fast path: a file with the same basename and matching content.
            for cand in by_name.get(p["name"], []):
                if content_ok(cand, p):
                    ok = True
                    break
        # Name-independent path: any file of the right size and sha256
        # (credits clients that renamed the extracted payload). Under
        # --names-strict this does NOT credit a match - it diagnoses one:
        # the bytes exist under some other name/place, which is the
        # deobfuscation defect itself.
        if not ok:
            for cand in by_size.get(p["bytes"], []):
                if sha256(cand) == p["sha256"]:
                    if strict:
                        misnamed.append(p["name"])
                    else:
                        ok = True
                    break
        if ok:
            matched += 1
        elif p["name"] not in misnamed:
            missing.append(p["name"])

    # Leftover archives = a visible signal that denesting stopped early.
    leftover = sorted(
        n for n in by_name
        if n.rsplit(".", 1)[-1].lower() in ("rar", "7z", "par2")
    )

    n = len(manifest["payloads"])
    if matched == n and n > 0:
        cls = "auto-complete"
    elif rc == 0:
        cls = "manual-intervention"
    else:
        cls = "fail"
    line = f"class={cls} matched={matched}/{n}"
    if missing:
        line += " missing=" + ",".join(missing[:5])
    if misnamed:
        line += " misnamed=" + ",".join(misnamed[:5])
    if leftover:
        line += " leftover=" + ",".join(leftover[:5])
    print(line)


if __name__ == "__main__":
    main()
