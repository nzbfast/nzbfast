#!/usr/bin/env python3
"""Write an SPDX 2.3 SBOM for one release asset.

    packaging/make-sbom.py --asset <file> --target <triple> [--target <triple> ...] \
        -p <pkg> [-p <pkg> ...] \
        [--out <file>.spdx.json]
    packaging/make-sbom.py --selftest

One document per asset, named `<asset>.spdx.json` beside it by default.
It answers "which crates, at which versions, under which licences, went
into THIS file", so it is computed for the asset's own target triple and
its own packages (a universal macOS binary names both of its triples,
and gets the union of the two graphs) - the Windows zip carries nzbtray as well as nzbfast,
and a musl build resolves a different graph from an apple one.

WHERE THE GRAPH COMES FROM. `cargo tree -e normal,build --target <t>
-p <pkg>...` with the default features: the same resolver the release
build runs, so the set is the one that was compiled - not `cargo
metadata`, whose resolve is workspace-wide and would list crates that
only another member's features pull in. Dev-dependencies are excluded
by the edge filter. Build-dependencies and proc-macros are included:
they ran at build time and produced code that is in the binary.

WHAT IS NOT IN IT. C and C++ sources compiled by `-sys` crates (aws-lc,
sqlite, mimalloc, rapidyenc) appear as the crate that vendors them, not
as separate packages; the SBOM is a crate graph, and says so in its
comment field rather than pretending to be more.

NO PATHS. `cargo tree` prints a path dependency's absolute directory,
which on a builder is that builder's home. Workspace and vendored crates
are recorded by their path RELATIVE to the repository root, and a path
dependency outside the root is a refusal: an SBOM is a published file.

DETERMINISM. `created` comes from SOURCE_DATE_EPOCH when it is set (the
provenance workflow pins it to the tag's commit time), and every list is
sorted, so a rebuild of the same tag writes the same bytes.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_URL = "https://github.com/nzbfast/nzbfast"

# `name vX.Y.Z`, then any of `(proc-macro)`, `(<source>)` and the dedupe
# mark `(*)` in parentheses, then `|` and the licence.
LINE = re.compile(
    r"^(?P<depth>\d+)(?P<name>[A-Za-z0-9_.+-]+) v(?P<version>\S+)"
    r"(?P<groups>(?: \([^)]*\))*)\|(?P<license>.*)$"
)
GROUP = re.compile(r" \(([^)]*)\)")


class Refusal(Exception):
    pass


def cargo_tree(targets, packages, root):
    cmd = ["cargo", "tree", "--locked"]
    for t in targets:
        cmd += ["--target", t]
    cmd += ["-e", "normal,build", "--prefix", "depth", "--format", "{p}|{l}"]
    for p in packages:
        cmd += ["-p", p]
    out = subprocess.run(cmd, cwd=root, check=True, capture_output=True, text=True)
    return out.stdout


def lock_checksums(root):
    """{(name, version): sha256} for registry packages, from Cargo.lock."""
    sums = {}
    name = version = None
    in_pkg = False  # the file opens with a top-level `version = 4`
    with open(os.path.join(root, "Cargo.lock"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("["):
                in_pkg = line == "[[package]]"
                name = version = None
            elif not in_pkg:
                continue
            elif line.startswith("name = "):
                name = line.split('"')[1]
            elif line.startswith("version = "):
                version = line.split('"')[1]
            elif line.startswith("checksum = ") and name and version:
                sums[(name, version)] = line.split('"')[1]
    return sums


def spdx_license(raw):
    """Cargo's licence field as an SPDX expression, or NOASSERTION.

    Old crates still write `MIT/Apache-2.0`, which SPDX does not parse;
    the slash meant OR. An empty field (a crate shipping `license-file`
    only) is no assertion, never a guess.
    """
    raw = raw.strip()
    if not raw:
        return "NOASSERTION"
    if "/" in raw:
        raw = " OR ".join(part.strip() for part in raw.split("/"))
    if not re.fullmatch(r"[A-Za-z0-9.+\-() ]+", raw):
        return "NOASSERTION"
    return raw


def parse_tree(text, root):
    """Packages and edges from `cargo tree --prefix depth` output.

    Returns ({key: pkg}, {(parent_key, child_key)}, [root keys]). A key is
    (name, version); one crate at two versions is two packages.
    """
    pkgs, edges, roots, stack = {}, set(), [], []
    # normcase: on a Windows runner cargo and __file__ can disagree about
    # drive-letter case, and the comparison below must not read that as
    # "outside the repository".
    root_real = os.path.normcase(os.path.realpath(root))
    for raw in text.splitlines():
        if not raw.strip():
            continue
        m = LINE.match(raw)
        if not m:
            raise Refusal("cannot read cargo tree line: %r" % raw)
        depth = int(m.group("depth"))
        key = (m.group("name"), m.group("version"))
        groups = [g for g in GROUP.findall(m.group("groups")) if g not in ("*", "proc-macro")]
        if len(groups) > 1:
            raise Refusal("more than one source on cargo tree line: %r" % raw)
        source = groups[0] if groups else ""
        rel = None
        if source and not source.startswith(("registry ", "http", "git+")):
            if source.startswith("\\\\?\\"):  # a Windows verbatim path
                source = source[4:]
            path = os.path.normcase(os.path.realpath(source))
            if path != root_real and not path.startswith(root_real + os.sep):
                raise Refusal(
                    "%s %s is a path dependency outside the repository (%s); "
                    "refusing to write its location into a published file"
                    % (key[0], key[1], source))
            rel = os.path.relpath(path, root_real).replace(os.sep, "/")
        if source.startswith(("http", "git+")):
            raise Refusal(
                "%s %s comes from git (%s); this generator records crates.io "
                "and workspace paths only - teach it the git case before "
                "shipping one" % (key[0], key[1], source))
        if key not in pkgs:
            pkgs[key] = {"license": spdx_license(m.group("license")), "path": rel}
        elif rel and not pkgs[key]["path"]:
            pkgs[key]["path"] = rel
        del stack[depth:]
        if depth == 0:
            if key not in roots:
                roots.append(key)
        else:
            if not stack:
                raise Refusal("cargo tree line at depth %d with no parent: %r" % (depth, raw))
            edges.add((stack[-1], key))
        stack.append(key)
    if not roots:
        raise Refusal("cargo tree printed no root package")
    return pkgs, edges, roots


def spdx_id(key):
    return "SPDXRef-Package-%s-%s" % (
        re.sub(r"[^A-Za-z0-9.-]", "-", key[0]),
        re.sub(r"[^A-Za-z0-9.-]", "-", key[1]))


def build_doc(asset_name, asset_sha, targets, pkgs, edges, roots, sums, epoch):
    target = " + ".join(targets)
    created = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    artifact = {
        "SPDXID": "SPDXRef-Artifact",
        "name": asset_name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "checksums": [{"algorithm": "SHA256", "checksumValue": asset_sha}],
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "comment": "Release asset for target %s." % target,
    }
    packages = [artifact]
    for key in sorted(pkgs):
        info = pkgs[key]
        p = {
            "SPDXID": spdx_id(key),
            "name": key[0],
            "versionInfo": key[1],
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": info["license"],
            "copyrightText": "NOASSERTION",
        }
        if info["path"] is not None:
            p["downloadLocation"] = "NOASSERTION"
            p["sourceInfo"] = "built from %s in %s" % (info["path"], REPO_URL)
        else:
            p["downloadLocation"] = "https://crates.io/api/v1/crates/%s/%s/download" % key
            p["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:cargo/%s@%s" % key,
            }]
            if key in sums:
                p["checksums"] = [{"algorithm": "SHA256", "checksumValue": sums[key]}]
        packages.append(p)
    rels = [{"spdxElementId": "SPDXRef-DOCUMENT",
             "relationshipType": "DESCRIBES",
             "relatedSpdxElement": "SPDXRef-Artifact"}]
    for r in sorted(roots):
        rels.append({"spdxElementId": "SPDXRef-Artifact",
                     "relationshipType": "CONTAINS",
                     "relatedSpdxElement": spdx_id(r)})
    for parent, child in sorted(edges):
        rels.append({"spdxElementId": spdx_id(parent),
                     "relationshipType": "DEPENDS_ON",
                     "relatedSpdxElement": spdx_id(child)})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": asset_name,
        "documentNamespace": "%s/sbom/%s-%s" % (REPO_URL, asset_name, asset_sha),
        "creationInfo": {
            "created": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Organization: nzbfast", "Tool: packaging/make-sbom.py"],
        },
        "comment": (
            "Crate graph of the packages compiled into this asset for %s "
            "(cargo tree -e normal,build, default features). C and C++ "
            "sources built by -sys crates are covered by the crate that "
            "vendors them." % target),
        "packages": packages,
        "relationships": rels,
    }


def check_doc(doc):
    """Structural checks a consumer will rely on. Returns a list of faults."""
    faults = []
    ids = [p["SPDXID"] for p in doc["packages"]]
    if len(ids) != len(set(ids)):
        faults.append("duplicate SPDXID")
    known = set(ids) | {"SPDXRef-DOCUMENT"}
    for r in doc["relationships"]:
        for side in ("spdxElementId", "relatedSpdxElement"):
            if r[side] not in known:
                faults.append("relationship names unknown element %s" % r[side])
    for i in ids:
        if not re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", i):
            faults.append("bad SPDXID %s" % i)
    text = json.dumps(doc)
    for marker in ("/Users/", "/home/", "C:\\\\", "D:\\\\", "/private/", "/tmp/"):
        if marker in text:
            faults.append("an absolute path (%s) reached the document" % marker)
    if not any(r["relationshipType"] == "CONTAINS" for r in doc["relationships"]):
        faults.append("the artifact contains no package")
    return faults


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def generate(asset, targets, packages, out, root=ROOT, tree_text=None, workspace=None):
    # `workspace` is the cargo workspace the packages live in: `cargo tree`
    # runs there and its Cargo.lock supplies the checksums. It defaults to
    # the repository root; the parfast desktop app's crates are a DETACHED
    # workspace (apps/parfast), which the root manifest never names. Path
    # dependencies are still judged against `root`, the repository, so a
    # crate the app reaches by ../../crates is recorded, and one outside
    # the repository is still refused.
    ws = workspace or root
    if not os.path.isfile(asset):
        raise Refusal("no asset at %s - an SBOM describes a file that exists" % asset)
    if tree_text is None:
        tree_text = cargo_tree(targets, packages, ws)
    pkgs, edges, roots = parse_tree(tree_text, root)
    want = set(packages)
    got = {k[0] for k in roots}
    if want - got:
        raise Refusal("cargo tree did not root at %s (got %s)" % (sorted(want - got), sorted(got)))
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or 0)
    doc = build_doc(os.path.basename(asset), sha256_file(asset), targets,
                    pkgs, edges, roots, lock_checksums(ws), epoch)
    faults = check_doc(doc)
    if faults:
        raise Refusal("generated SBOM fails its own checks: " + "; ".join(faults))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    return doc


def selftest():
    """Runs against a canned tree: no cargo, no network, no build."""
    with tempfile.TemporaryDirectory() as d:
        root = os.path.realpath(d)
        os.makedirs(os.path.join(root, "crates", "app", "wsm"))
        os.makedirs(os.path.join(root, "vendor", "eng"))
        with open(os.path.join(root, "Cargo.lock"), "w") as f:
            f.write('version = 4\n\n[[package]]\nname = "dep"\nversion = "1.0.0"\n'
                    'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                    'checksum = "%s"\n' % ("ab" * 32))
        asset = os.path.join(root, "app.tar.gz")
        with open(asset, "wb") as f:
            f.write(b"payload")
        tree = "\n".join([
            "0app v1.2.3 (%s/crates/app)|GPL-3.0-or-later" % root,
            "1dep v1.0.0|MIT/Apache-2.0",
            "1eng v0.1.0 (%s/vendor/eng)|" % root,
            "2dep v1.0.0|MIT/Apache-2.0 (*)",
            "1mac v0.2.0 (proc-macro)|MIT",
            "1wsm v0.3.0 (proc-macro) (%s/crates/app/wsm)|MIT" % root,
        ]) + "\n"
        out = os.path.join(root, "app.tar.gz.spdx.json")
        doc = generate(asset, ["x86_64-unknown-linux-musl"], ["app"], out, root, tree)
        by = {p["name"]: p for p in doc["packages"]}
        checks = [
            (by["dep"]["licenseDeclared"] == "MIT OR Apache-2.0", "slash licence normalised"),
            (by["eng"]["licenseDeclared"] == "NOASSERTION", "empty licence is NOASSERTION"),
            (by["eng"]["sourceInfo"].startswith("built from vendor/eng "), "path recorded relative"),
            (by["dep"]["checksums"][0]["checksumValue"] == "ab" * 32, "lock checksum carried"),
            (by["app.tar.gz"]["checksums"][0]["checksumValue"]
             == hashlib.sha256(b"payload").hexdigest(), "artifact digest is the file's"),
            (sum(1 for p in doc["packages"] if p["name"] == "dep") == 1, "dedupe holds"),
            (root not in open(out).read(), "no absolute path in the output"),
            (by["wsm"]["sourceInfo"].startswith("built from crates/app/wsm "),
             "a path proc-macro keeps its path"),
            ("externalRefs" in by["mac"] and "sourceInfo" not in by["mac"],
             "a registry proc-macro is a registry crate"),
            ({(r["spdxElementId"], r["relatedSpdxElement"]) for r in doc["relationships"]
              if r["relationshipType"] == "DEPENDS_ON"}
             == {(spdx_id(("app", "1.2.3")), spdx_id(("dep", "1.0.0"))),
                 (spdx_id(("app", "1.2.3")), spdx_id(("eng", "0.1.0"))),
                 (spdx_id(("app", "1.2.3")), spdx_id(("mac", "0.2.0"))),
                 (spdx_id(("app", "1.2.3")), spdx_id(("wsm", "0.3.0"))),
                 (spdx_id(("eng", "0.1.0")), spdx_id(("dep", "1.0.0")))}, "edges follow depth"),
        ]
        # The refusal arms: a path outside the root, and a line the parser
        # cannot read. Each must refuse, never write a document.
        for bad, why in [
            ("0app v1.2.3 (/elsewhere/app)|MIT\n", "outside-root path refused"),
            ("0app v1.2.3 (%s/crates/app)|MIT\nnonsense\n" % root, "unreadable line refused"),
        ]:
            try:
                generate(asset, ["t"], ["app"], out + ".bad", root, bad)
                checks.append((False, why))
            except Refusal:
                checks.append((not os.path.exists(out + ".bad"), why))
    failed = [why for ok, why in checks if not ok]
    for ok, why in checks:
        print("%s %s" % ("ok  " if ok else "FAIL", why))
    if failed:
        print("make-sbom selftest: %d of %d arm(s) failed" % (len(failed), len(checks)))
        return 1
    print("make-sbom selftest: %d arms ok" % len(checks))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--asset")
    ap.add_argument("--target", action="append", default=[])
    ap.add_argument("-p", "--package", action="append", default=[])
    ap.add_argument("--out")
    ap.add_argument("--workspace", help="cargo workspace dir, relative to the repository (default: the root)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not (a.asset and a.target and a.package):
        ap.error("--asset, --target and at least one -p are required")
    out = a.out or a.asset + ".spdx.json"
    try:
        ws = os.path.join(ROOT, a.workspace) if a.workspace else None
        doc = generate(a.asset, a.target, a.package, out, workspace=ws)
    except Refusal as e:
        print("make-sbom: REFUSING - %s" % e, file=sys.stderr)
        return 2
    print("%s: %d packages, %d dependency edges" % (
        out, len(doc["packages"]) - 1,
        sum(1 for r in doc["relationships"] if r["relationshipType"] == "DEPENDS_ON")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
