#!/usr/bin/env python3
"""Stage a Sigstore attestation bundle beside each asset it covers.

    packaging/stage-attestation.py <bundle.jsonl> <asset> [<asset> ...]
    packaging/stage-attestation.py --selftest

Writes `<asset>.intoto.jsonl` for every asset named, each a byte-for-byte
copy of the bundle `actions/attest-build-provenance` produced, after
proving that the signed statement inside it names THAT asset's sha256 as
a subject. A bundle for the wrong subject is worse than no bundle: it
verifies, against something else.

Copied verbatim, never re-serialised: the signature covers the base64
statement inside the bundle, but re-serialising signed material to
prettify it is a habit worth not having. `<asset>.intoto.jsonl` is
load-bearing twice: it pairs the bundle with the file it describes, and
it is the exact case-sensitive suffix OpenSSF Scorecard's Signed-Releases
check looks for.

One bundle may cover several assets (one attest call over a job's whole
output, which is how the Windows and Linux installer jobs in
provenance-release.yml attest), so each asset gets its own copy and each
copy is checked against its own file.

This was an inline step in provenance-release.yml until the installer
jobs needed the same check three times; one copy now, so the three
cannot drift apart.
"""

import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile


def subjects(bundle_path):
    text = open(bundle_path, encoding="utf-8").read()
    # The action writes each bundle as compact JSON plus a newline,
    # appending, so this is genuinely JSON Lines. Accept a whole-file
    # bundle too rather than let a formatting change on their side fail
    # a release.
    try:
        bundles = [json.loads(text)]
    except json.JSONDecodeError:
        bundles = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    if not bundles:
        raise SystemExit("%s: empty attestation bundle" % bundle_path)
    found = []
    for b in bundles:
        stmt = json.loads(base64.b64decode(b["dsseEnvelope"]["payload"]))
        for subj in stmt.get("subject", []):
            found.append((subj.get("name"), subj.get("digest", {}).get("sha256")))
    return len(bundles), found


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stage(bundle_path, assets):
    n, found = subjects(bundle_path)
    digests = {d for _, d in found}
    for asset in assets:
        want = sha256(asset)
        if want not in digests:
            raise SystemExit("%s attests %s, not %s (%s)" % (bundle_path, found, want, asset))
    for asset in assets:
        shutil.copyfile(bundle_path, asset + ".intoto.jsonl")
        print("%s.intoto.jsonl: %d bundle(s), subject sha256 %s confirmed"
              % (asset, n, sha256(asset)))


def selftest():
    def bundle(*payloads):
        lines = []
        for digests in payloads:
            stmt = {"subject": [{"name": "x", "digest": {"sha256": d}} for d in digests]}
            env = {"payload": base64.b64encode(json.dumps(stmt).encode()).decode()}
            lines.append(json.dumps({"dsseEnvelope": env}))
        return "\n".join(lines) + "\n"

    ok = True
    with tempfile.TemporaryDirectory() as d:
        a, b = os.path.join(d, "a.zip"), os.path.join(d, "b.exe")
        open(a, "wb").write(b"aaa")
        open(b, "wb").write(b"bbb")
        da, db = sha256(a), sha256(b)
        good = os.path.join(d, "good.jsonl")
        open(good, "w").write(bundle([da, db]))
        stage(good, [a, b])
        same = open(a + ".intoto.jsonl", "rb").read() == open(good, "rb").read()
        print("%s copies are byte-identical to the bundle" % ("ok  " if same else "FAIL"))
        ok &= same
        # Two appended bundles, the second covering the asset: still a pass.
        two = os.path.join(d, "two.jsonl")
        open(two, "w").write(bundle([db], [da]))
        stage(two, [a])
        print("ok   a subject in the second appended bundle is found")
        # A bundle that does not name the asset must refuse and stage NOTHING.
        wrong = os.path.join(d, "wrong.jsonl")
        open(wrong, "w").write(bundle([da]))
        os.remove(a + ".intoto.jsonl")
        try:
            stage(wrong, [a, b])
            print("FAIL a bundle missing one subject was accepted")
            ok = False
        except SystemExit:
            clean = not os.path.exists(a + ".intoto.jsonl")
            print("%s a missing subject refuses before staging any copy"
                  % ("ok  " if clean else "FAIL"))
            ok &= clean
    print("stage-attestation selftest: %s" % ("ok" if ok else "FAILED"))
    return 0 if ok else 1


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) < 3:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    stage(argv[1], argv[2:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
