#!/usr/bin/env python3
"""generate.py - build the no-RAR deobfuscation capability corpus.

    ./generate.py [--out DIR] [--leg NAME]

One leg per capability-matrix row (research/NORAR-DEOBF-MATRIX-2026-08-29.md):
bare files on the wire under random-looking names, real names only in
the PAR2 FileDesc packets, no archive anywhere. Everything is generated
(payload bytes from os.urandom, PAR2 sets built locally by par2cmdline,
three shapes patched by par2patch.py into what MultiPar/parpar emit
natively), so the corpus and its NZBs are publishable by construction.

Output is the nested-corpus leg-dir layout, so the same legs feed
nzbserve, run-legs.sh and classify.py unchanged:

    <out>/norar/<leg>/post/         files posted AND served
    <out>/norar/<leg>/manifest.json nested-corpus schema
    <out>/norar/<leg>/deobf.json    exact expected END STATE (names are
                                    the measurement here, so grading by
                                    payload content alone is not enough)
    <out>/norar/<leg>/<leg>.nzb     written by nzbserve build

Structure and names are deterministic; payload bytes are drawn fresh
each generation and pinned by sha256 in the manifests, the same
convention as bench/nested-corpus. Requires par2 (par2cmdline) and the
repo toolchain (cargo, to build nzbserve once).

Posting note: each leg's post/ dir is what `nzbfast post` uploads, one
leg = one NZB. The real NZB is minted at post time; the .nzb here is the
loopback rig's and exists for local verification (roundtrip.py) and for
competitor rounds over nzbserve.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
PAR2PATCH = os.path.join(HERE, "par2patch.py")
NZBSERVE = os.environ.get(
    "NZBSERVE",
    os.path.join(HERE, "..", "nested-corpus", "nzbserve", "target", "release", "nzbserve"),
)

KIB = 1024
MIB = 1024 * 1024


def msg(s):
    print(f"[capability-corpus] {s}")


def die(s):
    print(f"[capability-corpus] ERROR: {s}", file=sys.stderr)
    sys.exit(1)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def urandom(n):
    return os.urandom(n)


def ts_payload(n):
    """MPEG-TS shaped bytes: 0x47 sync every 188 bytes, so a container
    sniffer has something real to recognise on the extensionless leg."""
    b = bytearray(urandom(n))
    for i in range(0, n, 188):
        b[i] = 0x47
    return bytes(b)


def twin_pair(n, head):
    """Two same-length payloads sharing an identical (zero-filled) first
    `head` bytes - the padded-VOB / disk-image shape that collides the
    (length, md5-16k) live-matcher key."""
    a = bytearray(n)
    b = bytearray(n)
    a[head:] = urandom(n - head)
    b[head:] = urandom(n - head)
    return bytes(a), bytes(b)


class Leg:
    def __init__(self, out_root, name, shape, notes):
        self.name = name
        self.shape = shape
        self.notes = notes
        self.dir = os.path.join(out_root, "norar", name)
        shutil.rmtree(self.dir, ignore_errors=True)
        self.post = os.path.join(self.dir, "post")
        self.work = os.path.join(self.dir, "work")
        os.makedirs(self.post)
        os.makedirs(self.work)
        # (real relative path, bytes) staged for par2 create
        self.staged = []
        # deobf.json accumulators
        self.expected = []
        self.forbidden = []
        self.race_disjunction = False
        # A documented nzbfast capability gap: {"log_contains": ...,
        # "note": ...}. The leg is still postable - the row measures.
        self.known_gap = None
        # (posted name, size_lie, total_lie) for the lying-yEnc-header
        # sidecar nzbserve reads (`yenclies.txt`). Empty for every leg
        # but n37, and an empty list writes no file at all - the rig
        # only reads the sidecar when it exists.
        self.yenc_lies = []
        self.payloads = []  # manifest payload pins
        # CLOSED-WORLD FURNITURE. roundtrip.py grades a schema-2 leg
        # closed: anything in the output tree that no expectation
        # claimed and no pattern here names is a failure. `finish()`
        # seeds this with the posted files that are neither an expected
        # output nor a forbidden leftover - which is exactly the
        # recovery furniture (the PAR2 blobs, an SFV sidecar) a client
        # legitimately leaves on disk. Anything a leg's own name source
        # RENAMES has to be added by hand, because the generator is the
        # only thing that knows the real name before the client does.
        self.allowed_extra = []
        self.closed_world = True
        self.closed_world_reason = None
        # Optional per-row oracles, all read by roundtrip.py:
        self.budget = {}           # {metric: upper bound} - spend
        self.honest_failure = None # an acceptable nonzero end state
        self.arrival_plans = {}    # {name: stall plan} for --arrival

    def allow_extra(self, pattern, why=None):
        """Name output the closed-world arm must not refuse. Use it for
        furniture whose landed name the generator knows and the posted
        listing does not - a recovery set the leg's own chain renames,
        for instance. A row that keeps junk on PURPOSE says so with
        `open_world(reason)` instead; this is for one named thing."""
        self.allowed_extra.append(pattern)
        if why:
            self.notes += f" Allowed extra {pattern}: {why}"
        return self

    def open_world(self, reason):
        """Opt this row out of closed-world grading. It takes a REASON
        because an opt-out with none is indistinguishable from a grader
        that never looked - which is the defect the arm exists for."""
        self.closed_world = False
        self.closed_world_reason = reason
        return self

    def spend(self, **bounds):
        """Upper bounds on what the client may spend to reach the end
        state: repair blocks, bytes on disk, output amplification, wall
        time. Final bytes alone cannot see a phantom repair."""
        self.budget.update(bounds)
        return self

    def honest_fail(self, log_contains, retained=(), rc_must_be_nonzero=False):
        """The end state for a row that CANNOT succeed: a nonzero exit
        that says why and keeps the bytes it promised to keep. It never
        makes rc=0 acceptable with wrong or missing output."""
        self.honest_failure = {
            "log_contains": log_contains,
            "retained": list(retained),
            "rc_must_be_nonzero": bool(rc_must_be_nonzero),
        }
        return self

    def arrival(self, name, plan):
        """A named stall plan for `roundtrip.py --arrival <name>`; see
        that file's ArrivalPlan for the shape."""
        self.arrival_plans[name] = plan
        return self

    def stage(self, rel, data):
        """Write a real-named file into work/ for par2 create."""
        p = os.path.join(self.work, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        self.staged.append(rel)

    def post_file(self, name, data):
        """A file as it goes on the wire (already-obfuscated name)."""
        with open(os.path.join(self.post, name), "wb") as f:
            f.write(data)

    def lie(self, name, size_lie, total_lie=9):
        """Post `name` with LYING yEnc headers: every `=ybegin size=`
        overstates the true length by `size_lie` and every `total=`
        overstates the part count by `total_lie`, while the `=ypart`
        ranges stay TRUE (a real poster's tooling gets the ranges right
        or nothing decodes at all). Matrix row 20 / finding F5: the
        receiving client preallocates the slot at the DECLARED size, so
        a client that never truncates back to the FileDesc length
        publishes the payload plus a zero-padded tail - at rc=0, with
        verify green. The lie rides `yenclies.txt` beside the leg dir,
        the same sidecar convention as nzbpass.txt.

        NOTE for the eventual upload lane: this is a LOOPBACK-RIG
        affordance. `nzbfast post` writes honest headers, so a real
        upload of this leg's post/ dir would carry none of the lie -
        posting n37 for publication needs a lying knob on the poster
        first, or a hand-built post. The rig NZB here is the graded
        artefact until then."""
        self.yenc_lies.append((name, int(size_lie), int(total_lie)))

    def expect(self, path, data):
        """The end state: `path` (relative to the client's out dir, None
        = anywhere inside it) must hold exactly `data`."""
        self.expected.append(
            {"path": path, "sha256": sha256(data), "bytes": len(data)}
        )
        # Manifest payload entries carry "path" for classify.py
        # --names-strict (the deobf grading arm); entries without one
        # are graded by content anywhere, exactly like deobf.json's
        # path-null expectations.
        p = {
            "name": (os.path.basename(path) if path else "(anywhere)"),
            "bytes": len(data),
            "sha256": sha256(data),
        }
        if path:
            p["path"] = path
        self.payloads.append(p)

    def marker(self, subdir=None, sfv=False, pad_to=0):
        """The TEST PASSED file, protected by the same mechanism the leg
        tests: staged like any covered payload (so its real name lives
        only in the leg's name source), posted under a hash name, and
        expected under its real name - seeing it on disk IS the pass
        signal for a human running the test. Presence is necessary, not
        sufficient: byte checksums, forbidden leftovers and containment
        still live in the manifests. `subdir` buries it in the leg's
        tree; `sfv=True` skips staging (the caller writes the sidecar
        entry itself) and returns (real_name, bytes, obf_name).
        `pad_to` grows the body to at least that many bytes with a
        stated reason - n37 needs its marker over the 16 KiB md5-16k
        head window, because a covered file SHORTER than that is a
        second, unrelated hazard under a size lie (matrix finding F10)
        and a marker must test its own leg's mechanism, not two."""
        name = f"TEST PASSED - {self.name}.txt"
        rel = f"{subdir}/{name}" if subdir else name
        body = (
            "TEST PASSED\r\n\r\n"
            f"Capability test {self.name}.\r\n"
            "Seeing this file under this name means your client passed "
            "the core of this test.\r\n"
            "Full grading (byte checksums, forbidden leftovers, "
            "containment) lives in the published manifest.\r\n"
        ).encode()
        if pad_to and len(body) < pad_to:
            tail = (
                "\r\nPadding follows so this marker clears the 16 KiB "
                "md5-16k head window the recovery-set matcher keys on. "
                "It is not decoration: see this leg's notes.\r\n"
            ).encode()
            body = body + tail + b"." * (pad_to - len(body) - len(tail))
        obf = "m" + hashlib.md5(f"marker-{self.name}".encode()).hexdigest()[:10]
        self.post_file(obf, body)
        self.expect(rel, body)
        self.forbidden.append(obf)
        if not sfv:
            self.stage(rel, body)
        return rel, body, obf

    def par2(self, redundancy, patch=None, obf_prefix=None, block=None, index_only=False):
        """par2 create over everything staged; move the blobs to post/ -
        under their real .par2 names, or under `<obf_prefix><NN>` hash
        names (the sniffed-par2 shape) when a prefix is given.
        `patch(path)` runs on each blob before it moves. `block` pins the
        slice size (par2cmdline's tiny default makes degenerate sets on
        MiB-scale files; real posts carry KiB-scale blocks)."""
        # Options must precede the par2 base name - par2cmdline stops
        # option parsing at the first non-option argument, so a -s after
        # the name is silently ignored (measured: a block=65536 leg came
        # out at the 528-byte default).
        cmd = ["par2", "create", f"-r{redundancy}", "-q"]
        if block:
            cmd.append(f"-s{block}")
        cmd += [self.name] + self.staged
        r = subprocess.run(cmd, cwd=self.work, capture_output=True, text=True)
        if r.returncode != 0:
            die(f"par2 create failed for {self.name}: {r.stdout} {r.stderr}")
        blobs = sorted(f for f in os.listdir(self.work) if f.endswith(".par2"))
        if not blobs:
            die(f"par2 create produced nothing for {self.name}")
        if index_only:
            # The manifest-only shape (case 16): ship just the index
            # file - names + verification for kilobytes, zero recovery.
            for f in blobs:
                if "vol" in f:
                    os.remove(os.path.join(self.work, f))
            blobs = [f for f in blobs if "vol" not in f]
            if len(blobs) != 1:
                die(f"expected exactly one index par2, got {blobs}")
        for i, f in enumerate(blobs):
            p = os.path.join(self.work, f)
            if patch:
                patch(p)
            wire = f"{obf_prefix}{i:02d}" if obf_prefix else f
            shutil.move(p, os.path.join(self.post, wire))

    def finish(self, tier="norar"):
        listing = sorted(
            (
                {"name": n, "bytes": os.path.getsize(os.path.join(self.post, n))}
                for n in os.listdir(self.post)
                if not n.startswith(".")
            ),
            key=lambda e: e["name"],
        )
        manifest = {
            "leg": self.name,
            "tier": tier,
            "shape": self.shape,
            "depth": 0,
            "quick": False,
            "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "tools": {"par2": par2_version()},
            "payloads": self.payloads,
            "post_files": listing,
            "ghost_files": [],
            "passwords": None,
            "expected": {"nzbfast": "auto-complete"},
            "notes": self.notes,
        }
        with open(os.path.join(self.dir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        # The closed-world allow list: posted files that are neither an
        # expected output nor a forbidden leftover. Those are the
        # recovery blobs and sidecars, which a client keeps.
        expected_paths = {e["path"] for e in self.expected if e["path"]}
        expected_names = {os.path.basename(p) for p in expected_paths}
        seeded = [
            e["name"]
            for e in listing
            if e["name"] not in expected_names and e["name"] not in self.forbidden
        ]
        deobf = {
            "leg": self.name,
            # Schema 2 turns roundtrip.py's closed-world arm on. A
            # manifest with no schema key is a schema-1 manifest and is
            # graded exactly as the first 50 posted legs were.
            "schema": 2,
            "expected": self.expected,
            "forbidden": self.forbidden,
            "race_disjunction": self.race_disjunction,
            "known_gap": self.known_gap,
            "output_policy": {
                "closed_world": self.closed_world,
                "allowed_extra": sorted(set(seeded) | set(self.allowed_extra)),
                "reason": self.closed_world_reason,
            },
            "budget": self.budget,
            "honest_failure": self.honest_failure,
            "arrival_plans": self.arrival_plans,
            "notes": self.notes,
        }
        with open(os.path.join(self.dir, "deobf.json"), "w") as f:
            json.dump(deobf, f, indent=2)
            f.write("\n")
        if self.yenc_lies:
            # Must land before `nzbserve build` below - the sidecar is
            # what makes the articles (and so the NZB's segment sizes)
            # carry the lie.
            with open(os.path.join(self.dir, "yenclies.txt"), "w") as f:
                f.write(
                    "# <posted name> <size_lie> <total_lie> - see "
                    "nzbserve's read_yenc_lies\n"
                )
                for name, size_lie, total_lie in self.yenc_lies:
                    f.write(f"{name} {size_lie} {total_lie}\n")
        shutil.rmtree(self.work)
        r = subprocess.run([NZBSERVE, "build", self.dir], capture_output=True, text=True)
        if r.returncode != 0:
            die(f"nzbserve build failed for {self.name}: {r.stdout} {r.stderr}")
        msg(f"{self.name}: {len(listing)} posted file(s), {len(self.expected)} expected output(s)")


def par2_version():
    try:
        out = subprocess.run(["par2", "--version"], capture_output=True, text=True)
        return (out.stdout or out.stderr).splitlines()[0].strip()
    except Exception:
        return "unknown"


def patch_rename(src, dst):
    def go(path):
        r = subprocess.run(
            [sys.executable, PAR2PATCH, "rename", path, src, dst],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            die(f"par2patch rename failed on {path}: {r.stdout} {r.stderr}")

    return go


def patch_splice_empty(name):
    def go(path):
        r = subprocess.run(
            [sys.executable, PAR2PATCH, "splice-empty", path, name],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            die(f"par2patch splice-empty failed on {path}: {r.stdout} {r.stderr}")

    return go


# ---- the legs ---------------------------------------------------------


def gen_n01(out):
    leg = Leg(
        out,
        "n01-announced-par2",
        "obfuscated payload + announced PAR2 (real names only in FileDesc)",
        "Baseline: hash subject and hash yEnc name on the payload; the "
        "PAR2 set rides under its own real names. Expected: the payload "
        "lands byte-exact under its FileDesc name with no operator step.",
    )
    data = urandom(2 * MIB)
    leg.stage("Corpus.Baseline.2026.mkv", data)
    leg.post_file("Vq2mKd83RtY", data)
    leg.expect("Corpus.Baseline.2026.mkv", data)
    leg.forbidden.append("Vq2mKd83RtY")
    leg.marker()
    leg.par2(20, block=65536)
    # ARRIVAL ORDER (roundtrip.py --arrival late-par2). The baseline
    # shape is the cheapest place to prove the stall proxy end to end,
    # and the order it forces is a real question rather than a drill:
    # with the recovery set held back, a client that finalizes a name
    # before the strongest evidence has arrived lands the hash name and
    # never corrects it.
    leg.arrival("late-par2", {"stall": [{"match": "*par2*", "after_others": 3,
                                         "delay_ms": 300}]})
    leg.finish()


def gen_n02(out):
    leg = Leg(
        out,
        "n02-sniffed-par2",
        "everything on the wire is a hash - PAR2 posted under hash names too",
        "Hard mode: no subject or filename anywhere says par2. The "
        "recovery set must be recognised by CONTENT, then the payload "
        "renamed from its FileDesc. Expected: identical end state to the "
        "announced leg.",
    )
    data = urandom(2 * MIB)
    leg.stage("Corpus.Sniffed.2026.mkv", data)
    leg.post_file("Jm5nPw72QsX", data)
    leg.expect("Corpus.Sniffed.2026.mkv", data)
    leg.forbidden.append("Jm5nPw72QsX")
    leg.marker()
    leg.par2(20, obf_prefix="Wd4mRq7yZ", block=65536)
    leg.finish()


def gen_n03(out):
    leg = Leg(
        out,
        "n03-extensionless",
        "extensionless obfuscated payload, no PAR2 name anywhere",
        "The r/usenet field case: no name source at all, payload is a "
        "real MPEG-TS stream. Correct outcome: bytes land intact and the "
        "client resolves a REAL container extension (never appends junk "
        "like .bin; keeping the hash name intact is acceptable, junk "
        "suffixes or deletion are not).",
    )
    data = ts_payload(1 * MIB)
    leg.post_file("Vn6tRc39PmB", data)
    leg.expect(None, data)
    # No TEST PASSED marker, deliberately: this leg's whole point is
    # that NO name source exists, and naming a marker would add one.
    # The pass signal is the manifest checksum alone.
    leg.finish()


def gen_n04(out):
    leg = Leg(
        out,
        "n04-zerobyte",
        "0-byte member named only in a FileDesc (VIDEO_TS placeholder), not posted",
        "par2cmdline cannot even describe this shape (it skips 0-byte "
        "files at create); the set is patched to what MultiPar emits. "
        "Correct outcome: the client creates the empty file under its "
        "real name - the MD5 of an empty file is the descriptor's own, "
        "so creating it is the proof - and reports nothing missing.",
    )
    data = urandom(1 * MIB)
    leg.stage("Feature.Main.mkv", data)
    leg.post_file("Gh3sLp94WtY", data)
    leg.expect("Feature.Main.mkv", data)
    leg.expect("VTS_02_0.BUP", b"")
    leg.forbidden.append("Gh3sLp94WtY")
    leg.marker()
    leg.par2(20, patch=patch_splice_empty("VTS_02_0.BUP"), block=65536)
    leg.finish()


def gen_n05(out):
    leg = Leg(
        out,
        "n05-zerobyte-posted",
        "0-byte placeholder POSTED as one empty yEnc article + sniffed PAR2",
        "The other half of the placeholder case: the empty file IS on "
        "the wire, under a hash name, and the PAR2 set is fully "
        "obfuscated too. Correct outcome: the placeholder ends under its "
        "FileDesc name (paired with the arrived empty article, not "
        "minted twice), the payload deobfuscates, no hash names remain.",
    )
    data = urandom(1 * MIB)
    leg.stage("Real.Movie.2026.mkv", data)
    leg.post_file("g2LnXw8pKf5", data)
    leg.post_file("n0ByTeQq7wX", b"")
    leg.expect("Real.Movie.2026.mkv", data)
    leg.expect("VTS_02_0.VOB", b"")
    leg.forbidden += ["g2LnXw8pKf5", "n0ByTeQq7wX"]
    leg.marker()
    leg.par2(
        20,
        patch=patch_splice_empty("VTS_02_0.VOB"),
        obf_prefix="Vd4mRq7yWz",
        block=65536,
    )
    leg.finish()


def gen_n06(out):
    leg = Leg(
        out,
        "n06-tree",
        "directory tree in FileDesc names (VIDEO_TS/...)",
        "A DVD-shaped tree: FileDesc names carry safe relative paths. "
        "Correct outcome: the TREE lands intact (VIDEO_TS/VTS_01_1.VOB "
        "plays in place); flattening to VIDEO_TS_VTS_01_1.VOB loses the "
        "structure a player needs.",
    )
    vob = urandom(int(1.5 * MIB))
    bup = urandom(64 * KIB)
    leg.stage("VIDEO_TS/VTS_01_1.VOB", vob)
    leg.stage("VIDEO_TS/VTS_01_0.BUP", bup)
    leg.post_file("Xk4pQn8rLw1", vob)
    leg.post_file("Zm2vTc5yHd9", bup)
    leg.expect("VIDEO_TS/VTS_01_1.VOB", vob)
    leg.expect("VIDEO_TS/VTS_01_0.BUP", bup)
    leg.forbidden += ["Xk4pQn8rLw1", "Zm2vTc5yHd9"]
    leg.marker(subdir="VIDEO_TS")
    leg.par2(20)
    leg.finish()


def gen_n07(out):
    leg = Leg(
        out,
        "n07-dup-basenames",
        "duplicate basenames in different directories (a/readme.txt, b/readme.txt)",
        "Correct outcome: both land byte-exact and distinct - preserved "
        "trees keep them apart naturally; a flattening client must "
        "disambiguate, never rename one over the other.",
    )
    one = urandom(300 * KIB)
    two = urandom(300 * KIB)
    leg.stage("a/readme.txt", one)
    leg.stage("b/readme.txt", two)
    leg.post_file("Qw7fJm2nRv4", one)
    leg.post_file("Ht5kBc9xPz6", two)
    leg.expect("a/readme.txt", one)
    leg.expect("b/readme.txt", two)
    leg.forbidden += ["Qw7fJm2nRv4", "Ht5kBc9xPz6"]
    leg.marker()
    leg.par2(20)
    leg.finish()


def gen_n08(out):
    leg = Leg(
        out,
        "n08-lookalike",
        "sub/movie.mkv beside sub_movie.mkv - tree name vs its flat lookalike",
        "Correct outcome: both files land byte-exact and distinct. With "
        "preserved trees they never collide; a flattening client maps "
        "both onto one name and must disambiguate rather than lose one.",
    )
    inner = urandom(600 * KIB)
    flat = urandom(700 * KIB)
    leg.stage("sub/movie.mkv", inner)
    leg.stage("sub_movie.mkv", flat)
    leg.post_file("Pt4gHj52BwQ", inner)
    leg.post_file("Ln7yVz16McK", flat)
    leg.expect("sub/movie.mkv", inner)
    leg.expect("sub_movie.mkv", flat)
    leg.forbidden += ["Pt4gHj52BwQ", "Ln7yVz16McK"]
    leg.marker()
    leg.par2(20)
    leg.finish()


def gen_n09(out):
    leg = Leg(
        out,
        "n09-traversal",
        "traversal attempt in a FileDesc name (../evil.bin) - the SECURITY row",
        "The FileDesc name is poster-typed bytes. Correct outcome: "
        "CONTAINMENT - the payload lands inside the job directory under "
        "a sanitized name and nothing ever appears outside it. A client "
        "that writes beside or above its output directory fails this "
        "row however good its deobfuscation is.",
    )
    data = urandom(500 * KIB)
    leg.stage("zzzzevil.bin", data)
    leg.post_file("Bv2wQm85XdF", data)
    leg.expect(None, data)
    leg.marker()
    leg.par2(20, patch=patch_rename("zzzzevil.bin", "../evil.bin"))
    leg.finish()


def gen_n10(out):
    leg = Leg(
        out,
        "n10-dup-filedesc",
        "two FileDesc entries carrying the SAME name for different files",
        "Correct outcome: content ties each slot to its own descriptor "
        "and BOTH files survive, disambiguated - neither may be renamed "
        "over the other.",
    )
    one = urandom(400 * KIB)
    two = urandom(550 * KIB)
    leg.stage("dupXa.bin", one)
    leg.stage("dupXb.bin", two)
    leg.post_file("Rz5jTn93GcW", one)
    leg.post_file("Hd8pYw41SkV", two)
    leg.expect(None, one)
    leg.expect(None, two)
    leg.forbidden += ["Rz5jTn93GcW", "Hd8pYw41SkV"]

    def both(path):
        patch_rename("dupXa.bin", "dupfil.bin")(path)
        patch_rename("dupXb.bin", "dupfil.bin")(path)

    leg.marker()
    leg.par2(20, patch=both)
    leg.finish()


def gen_n11(out):
    leg = Leg(
        out,
        "n11-subset",
        "PAR2 covers only a SUBSET of the post",
        "One covered file, one stray with no name anywhere. Correct "
        "outcome: the covered file deobfuscates, the stray keeps its "
        "posted name byte-exact, and its presence does not fail the job.",
    )
    covered = urandom(800 * KIB)
    stray = urandom(650 * KIB)
    leg.stage("Named.By.Par2.bin", covered)
    leg.post_file("Cw3fJq67ZtL", covered)
    leg.post_file("Ux9kBs25NhD", stray)
    leg.expect("Named.By.Par2.bin", covered)
    leg.expect("Ux9kBs25NhD", stray)
    leg.forbidden.append("Cw3fJq67ZtL")
    leg.marker()
    leg.par2(20)
    leg.finish()


def gen_n12(out):
    leg = Leg(
        out,
        "n12-exact16k",
        "a file of exactly 16384 bytes - the md5-16k boundary",
        "Head equals whole file, md5-16k equals whole-file MD5. Correct "
        "outcome: lands under its FileDesc name like any other size.",
    )
    data = urandom(16384)
    leg.stage("Exact.Head.bin", data)
    leg.post_file("Xk2vRq81LmZ", data)
    leg.expect("Exact.Head.bin", data)
    leg.forbidden.append("Xk2vRq81LmZ")
    leg.marker()
    leg.par2(20)
    leg.finish()


def gen_n13(out):
    leg = Leg(
        out,
        "n13-short",
        "a file under 16 KiB (short head)",
        "The head is the whole file, shorter than the hash window. "
        "Correct outcome: lands under its FileDesc name.",
    )
    data = urandom(9000)
    leg.stage("Short.Sample.bin", data)
    leg.post_file("Nw6qFj18TdR", data)
    leg.expect("Short.Sample.bin", data)
    leg.forbidden.append("Nw6qFj18TdR")
    leg.marker()
    leg.par2(20)
    leg.finish()


def gen_n14(out):
    leg = Leg(
        out,
        "n14-damaged-head",
        "damaged first 16 KiB - the content-hash tier cannot match",
        "64 bytes poisoned inside the payload's first 16 KiB AFTER the "
        "PAR2 set was built, so the md5-16k tier has nothing to claim "
        "and repair must both fix and name the file. Correct outcome: "
        "repaired byte-exact under its FileDesc name.",
    )
    data = urandom(1 * MIB)
    leg.stage("Damaged.Head.mkv", data)
    leg.expect("Damaged.Head.mkv", data)
    leg.forbidden.append("Fk9mDt48RvC")
    leg.marker()
    leg.par2(20, block=65536)
    wire = bytearray(data)
    wire[1000:1064] = urandom(64)
    leg.post_file("Fk9mDt48RvC", bytes(wire))
    # Finding F9 (get-path repair never adoption-scanned an unclaimed
    # damaged-head candidate) was FIXED 30 Aug 2026: the recovery-block
    # shortfall now falls through to the repair engines when unclaimed
    # candidates exist, the sliding scan harvests the good blocks, and
    # the spent damaged twin is swept. This leg is held to the strict
    # expectation.
    leg.finish()


def gen_n15(out):
    leg = Leg(
        out,
        "n15-twins-r100",
        "identical first 16 KiB, same length, two files - 100% recovery",
        "Zero-filled heads (disk images, padded VOBs) collide the "
        "(length, md5-16k) key. Correct outcome: both twins byte-exact "
        "under their own FileDesc names. At r=100 even a crossed claim "
        "is recoverable - the cost of crossing is a full repair of an "
        "intact post, which is itself worth measuring.",
    )
    a, b = twin_pair(200_000, 20_000)
    leg.stage("Twin.Alpha.vob", a)
    leg.stage("Twin.Beta.vob", b)
    leg.post_file("Jm5nPw72QsA", a)
    leg.post_file("Ty8cKd31VbN", b)
    leg.expect("Twin.Alpha.vob", a)
    leg.expect("Twin.Beta.vob", b)
    leg.forbidden += ["Jm5nPw72QsA", "Ty8cKd31VbN"]
    leg.marker()
    leg.par2(100)
    leg.finish()


def gen_n16(out):
    leg = Leg(
        out,
        "n16-twins-r10",
        "identical first 16 KiB, same length - realistic 10% recovery",
        "The sharpest row of the family: with only 10% recovery a "
        "client that guesses the pairing from the 16 KiB head and "
        "guesses wrong turns a 100% intact post into a failed job. "
        "Correct outcome: both twins byte-exact under their own names, "
        "every run.",
    )
    a, b = twin_pair(200_000, 20_000)
    leg.stage("Low.Alpha.vob", a)
    leg.stage("Low.Beta.vob", b)
    leg.post_file("Jm5nPw72QsB", a)
    leg.post_file("Ty8cKd31VbM", b)
    leg.expect("Low.Alpha.vob", a)
    leg.expect("Low.Beta.vob", b)
    leg.forbidden += ["Jm5nPw72QsB", "Ty8cKd31VbM"]
    # F1 (identical-head claim race) was fixed on 30 Aug 2026
    # (c3e433e24: the md5-16k tier declines ambiguity and settle
    # resolves twins by whole-file MD5), so nzbfast is held to the
    # strict expectation on this leg like any other.
    leg.marker()
    leg.par2(10)
    leg.finish()




# ---- wave-2 legs (matrix cases 16-25; only the postable shapes) ------


def gen_n17(out):
    leg = Leg(
        out,
        "n17-manifest-only-par2",
        "PAR2 index file only - names + verification, ZERO recovery volumes",
        "The lightest full obfuscation: the poster ships kilobytes of "
        "FileDesc + checksums and no redundancy at all. Correct "
        "outcome: rename and verify both work with zero recovery "
        "blocks; a damaged article on such a post must fail cleanly, "
        "never wedge.",
    )
    data = urandom(2 * MIB)
    leg.stage("Corpus.Manifest.Only.mkv", data)
    leg.post_file("Kp6dWn31JzT", data)
    leg.expect("Corpus.Manifest.Only.mkv", data)
    leg.forbidden.append("Kp6dWn31JzT")
    leg.marker()
    leg.par2(5, block=65536, index_only=True)
    leg.finish()


def gen_n18(out):
    leg = Leg(
        out,
        "n18-raw-splits",
        "raw split parts, FileDesc names the PARTS (.001/.002, no container)",
        "Lighter than any archive: plain byte halves. Correct outcome: "
        "parts renamed from their FileDescs and JOINED - the whole "
        "file lands byte-exact.",
    )
    data = urandom(1 * MIB)
    half = len(data) // 2
    leg.stage("Rawsplit.mkv.001", data[:half])
    leg.stage("Rawsplit.mkv.002", data[half:])
    leg.post_file("Yt3gRb57QcM", data[:half])
    leg.post_file("Wf8jHx24VnK", data[half:])
    leg.expect("Rawsplit.mkv", data)
    leg.forbidden += ["Yt3gRb57QcM", "Wf8jHx24VnK"]
    leg.marker()
    leg.par2(20, block=65536)
    leg.finish()


def gen_n19(out):
    leg = Leg(
        out,
        "n19-split-join",
        "raw split halves posted, FileDesc names only the JOIN",
        "The MultiPar join shape: the PAR2 set describes the joined "
        "file, the wire carries two obfuscated halves. Every joined "
        "block exists at block-aligned offsets, so a client with a "
        "block-harvesting scan assembles this with zero recovery "
        "spend. Correct outcome: the joined file lands byte-exact.",
    )
    data = urandom(1 * MIB)
    half = len(data) // 2
    leg.stage("Joined.Feature.mkv", data)
    leg.post_file("Zr5mKt82XwP", data[:half])
    leg.post_file("Qn9cVd46LbS", data[half:])
    leg.expect("Joined.Feature.mkv", data)
    # Finding F7 (the join shape failed: the second half was never
    # harvested) was FIXED 30 Aug 2026 by the same fall-through as F9 -
    # the sliding scan assembles the join from both halves with zero
    # recovery spend. Held to the strict expectation.
    leg.marker()
    leg.par2(20, block=65536)
    leg.finish()


def gen_n20(out):
    leg = Leg(
        out,
        "n20-decoy-junk",
        "uncovered junk beside a covered payload, incl. a same-length decoy",
        "The reverse of the subset case: extra files the PAR2 set never "
        "mentions, one of them the SAME length as the covered payload "
        "(aimed at clients that match content by size). Correct "
        "outcome: the covered file deobfuscates, the decoy never "
        "claims its name, junk lands byte-exact under posted names, "
        "the job completes.",
    )
    covered = urandom(900 * KIB)
    decoy = urandom(900 * KIB)  # same length, different bytes
    junk = urandom(300 * KIB)
    leg.stage("Covered.Payload.mkv", covered)
    leg.post_file("Gd2xNs71RfW", covered)
    leg.post_file("Mb7tQk39ZhC", decoy)
    leg.post_file("Vs4wJp85KdY", junk)
    leg.expect("Covered.Payload.mkv", covered)
    leg.expect("Mb7tQk39ZhC", decoy)
    leg.expect("Vs4wJp85KdY", junk)
    leg.forbidden.append("Gd2xNs71RfW")
    leg.marker()
    leg.par2(20, block=65536)
    leg.finish()


def gen_n21(out):
    import zlib

    leg = Leg(
        out,
        "n21-sfv-sidecar",
        "SFV/CRC32 sidecar as the ONLY name source (no PAR2 anywhere)",
        "Lighter than PAR2 for small sets: an .sfv maps real names to "
        "CRC32s, payload names are random. Correct outcome: names "
        "resolved from the SFV (a full-file CRC32 is free at decode "
        "time). Clients without SFV naming keep the posted hashes - "
        "bytes intact is the floor, names resolved is the row.",
    )
    one = urandom(400 * KIB)
    two = urandom(500 * KIB)
    mrel, mbody, _ = leg.marker(sfv=True)
    sfv = (
        "; corpus SFV sidecar (generated)\n"
        f"Real.Track.One.flac {zlib.crc32(one) & 0xFFFFFFFF:08X}\n"
        f"Real.Track.Two.flac {zlib.crc32(two) & 0xFFFFFFFF:08X}\n"
        f"{mrel} {zlib.crc32(mbody) & 0xFFFFFFFF:08X}\n"
    ).encode()
    leg.post_file("Tc6yBw18NmQ", one)
    leg.post_file("Hj3kFv92XsD", two)
    leg.post_file("corpus-set.sfv", sfv)
    leg.expect("Real.Track.One.flac", one)
    leg.expect("Real.Track.Two.flac", two)
    leg.forbidden += ["Tc6yBw18NmQ", "Hj3kFv92XsD"]
    # Finding F6 was FIXED 30 Aug 2026 (`sfv-naming`): a settle-time
    # tier reads the sidecars, checksums the settled unclaimed files,
    # and renames on a unique full-file CRC32 match - ambiguity
    # declined on both sides. Held to the strict expectation.
    leg.finish()


def gen_n22(out):
    leg = Leg(
        out,
        "n22-two-par2-sets",
        "two independent PAR2 sets in one post, each covering half the files",
        "Correct outcome: each set claims only its own files; all four "
        "payloads land byte-exact under their own FileDesc names.",
    )
    a1 = urandom(300 * KIB)
    a2 = urandom(350 * KIB)
    b1 = urandom(400 * KIB)
    b2 = urandom(450 * KIB)
    leg.stage("SetA.First.bin", a1)
    leg.stage("SetA.Second.bin", a2)
    leg.post_file("Pw5nGc27TkR", a1)
    leg.post_file("Xd8fLm63BvJ", a2)
    for n, d in [("SetA.First.bin", a1), ("SetA.Second.bin", a2)]:
        leg.expect(n, d)
    ma = "TEST PASSED - n22 (set A).txt"
    mb_body = b"TEST PASSED\r\n\r\nCapability test n22-two-par2-sets, set A of two.\r\n"
    leg.stage(ma, mb_body)
    leg.post_file("m22aQx7Vd31w", mb_body)
    leg.expect(ma, mb_body)
    leg.forbidden.append("m22aQx7Vd31w")
    cmd = ["par2", "create", "-r20", "-s65536", "-q", "setA", "SetA.First.bin", "SetA.Second.bin", ma]
    r = subprocess.run(cmd, cwd=leg.work, capture_output=True, text=True)
    if r.returncode != 0:
        die(f"par2 create setA failed: {r.stdout} {r.stderr}")
    for f in sorted(os.listdir(leg.work)):
        if f.endswith(".par2"):
            shutil.move(os.path.join(leg.work, f), os.path.join(leg.post, f))
    for f in list(leg.staged):
        os.remove(os.path.join(leg.work, f))
    leg.staged = []
    leg.stage("SetB.First.bin", b1)
    leg.stage("SetB.Second.bin", b2)
    leg.post_file("Ke2sYq94WzH", b1)
    leg.post_file("Rv7bTj51McN", b2)
    for n, d in [("SetB.First.bin", b1), ("SetB.Second.bin", b2)]:
        leg.expect(n, d)
    leg.forbidden += ["Pw5nGc27TkR", "Xd8fLm63BvJ", "Ke2sYq94WzH", "Rv7bTj51McN"]
    mbn = "TEST PASSED - n22 (set B).txt"
    mbb = b"TEST PASSED\r\n\r\nCapability test n22-two-par2-sets, set B of two.\r\n"
    leg.stage(mbn, mbb)
    leg.post_file("m22bZk4Wf82j", mbb)
    leg.expect(mbn, mbb)
    leg.forbidden.append("m22bZk4Wf82j")
    cmd = ["par2", "create", "-r20", "-s65536", "-q", "setB", "SetB.First.bin", "SetB.Second.bin", mbn]
    r = subprocess.run(cmd, cwd=leg.work, capture_output=True, text=True)
    if r.returncode != 0:
        die(f"par2 create setB failed: {r.stdout} {r.stderr}")
    for f in sorted(os.listdir(leg.work)):
        if f.endswith(".par2"):
            shutil.move(os.path.join(leg.work, f), os.path.join(leg.post, f))
    leg.finish()


def gen_n23(out):
    leg = Leg(
        out,
        "n23-windows-hostile",
        "Windows-hostile FileDesc names: reserved device names, trailing dot/space",
        "CON.mkv, NUL, and a name ending in a dot-space. Correct "
        "outcome: the same post lands the same way on every host - "
        "sanitized, byte-exact, and nothing ever opens a device.",
    )
    a = urandom(200 * KIB)
    b = urandom(250 * KIB)
    c = urandom(300 * KIB)
    leg.stage("zzzzwinA.mkv", a)
    leg.stage("zzzzwinB.bin", b)
    leg.stage("zzzztrail.txt", c)
    leg.post_file("Fb4qZn86SjL", a)
    leg.post_file("Nc9wDh35GtX", b)
    leg.post_file("Lm1vRs72YpB", c)
    # Landed names measured 30 Aug 2026 (matrix row 24): _CON.mkv,
    # _NUL, trail.txt - identical on every host by design.
    leg.expect("_CON.mkv", a)
    leg.expect("_NUL", b)
    leg.expect("trail.txt", c)
    leg.forbidden += ["Fb4qZn86SjL", "Nc9wDh35GtX", "Lm1vRs72YpB"]

    def hostile(path):
        patch_rename("zzzzwinA.mkv", "CON.mkv")(path)
        patch_rename("zzzzwinB.bin", "NUL")(path)
        patch_rename("zzzztrail.txt", "trail.txt. ")(path)

    leg.marker()
    leg.par2(20, block=65536, patch=hostile)
    leg.finish()




# ---- wave-3 legs (30 Aug 2026): adversarial rows + lightweight recipes


def gen_n24(out):
    leg = Leg(
        out,
        "n24-dedupe-descriptors",
        "two FileDescs, identical content, ONE posted copy (dedupe post)",
        "ADVERSARIAL. A poster ships one copy of bytes two files share "
        "(MultiPar dedupe shape) - kilobytes of descriptor buying a "
        "whole duplicate file. Correct outcome: BOTH names land "
        "byte-exact; the client derives the second file from the first.",
    )
    data = urandom(600 * KIB)
    leg.stage("Copy.One.bin", data)
    leg.stage("Copy.Two.bin", data)
    leg.post_file("Uy4wNb82RcJ", data)
    leg.expect("Copy.One.bin", data)
    leg.expect("Copy.Two.bin", data)
    leg.forbidden.append("Uy4wNb82RcJ")
    leg.marker()
    leg.par2(10, block=65536)
    leg.finish()


def gen_n25(out):
    leg = Leg(
        out,
        "n25-near-twin-decoy",
        "damaged covered payload beside an UNCOVERED decoy sharing its length and head",
        "ADVERSARIAL, aimed at content-matching internals: the decoy "
        "matches the payload's (length, head-hash) key, the payload's "
        "posted copy is damaged past the head, and only whole-file "
        "evidence plus block-level repair can sort it out. Correct "
        "outcome: the payload repairs byte-exact under its real name "
        "AND the decoy survives byte-exact - a client that deletes or "
        "renames the decoy loses bytes the post carried.",
    )
    payload_bytes = bytearray(urandom(1 * MIB))
    decoy = bytearray(urandom(1 * MIB))
    decoy[: 128 * KIB] = payload_bytes[: 128 * KIB]
    leg.stage("Genuine.Payload.mkv", bytes(payload_bytes))
    leg.expect("Genuine.Payload.mkv", bytes(payload_bytes))
    leg.marker()
    leg.par2(20, block=65536)
    wire = bytearray(payload_bytes)
    wire[800_000:800_064] = urandom(64)
    leg.post_file("Aq7dLs94WfM", bytes(wire))
    leg.post_file("Zn3kTv61XbP", bytes(decoy))
    leg.expect("Zn3kTv61XbP", bytes(decoy))
    leg.forbidden.append("Aq7dLs94WfM")
    leg.finish()


def gen_n26(out):
    leg = Leg(
        out,
        "n26-triplet-one-damaged",
        "three same-length zero-head files, one posted copy damaged, 15% recovery",
        "ADVERSARIAL. The identical-head family at three-way scale "
        "with damage on top: head hashes cannot tell the three apart, "
        "two resolve by whole-file evidence, and the third needs "
        "block-level harvest plus recovery. Correct outcome: all three "
        "land byte-exact under their own names.",
    )
    files = []
    for i, name in enumerate(["Trip.Alpha.vob", "Trip.Beta.vob", "Trip.Gamma.vob"]):
        b = bytearray(300_000)
        b[64 * KIB :] = urandom(300_000 - 64 * KIB)
        files.append((name, bytes(b)))
        leg.stage(name, bytes(b))
        leg.expect(name, bytes(b))
    leg.marker()
    leg.par2(15, block=65536)
    posted = ["Cx2mVb85TjR", "Kd6pWn13YsF", "Rv9qHc47LmZ"]
    for (name, data), obf in zip(files[:2], posted[:2]):
        leg.post_file(obf, data)
    wire = bytearray(files[2][1])
    wire[150_000:150_064] = urandom(64)
    leg.post_file(posted[2], bytes(wire))
    leg.forbidden += posted
    leg.finish()


def gen_n27(out):
    leg = Leg(
        out,
        "n27-par2-of-par2",
        "the recovery set is itself obfuscated and named by a SECOND set",
        "ADVERSARIAL chain: payload and its PAR2 both ride under hash "
        "names; a small outer PAR2 (announced) names the inner PAR2 "
        "files. A name-driven client must chase the chain; a "
        "content-sniffing client can shortcut it. Correct outcome: the "
        "payload lands under its real name either way.",
    )
    data = urandom(1 * MIB)
    leg.stage("Chained.Payload.mkv", data)
    leg.expect("Chained.Payload.mkv", data)
    leg.post_file("Bw5rJk28NcV", data)
    leg.forbidden.append("Bw5rJk28NcV")
    # The marker is covered by the INNER set: it only lands when the
    # whole chain ran.
    mrel, _, _ = leg.marker()
    # Inner set over the payload, posted under hash names.
    cmd = ["par2", "create", "-r10", "-s65536", "-q", "inner", "Chained.Payload.mkv", mrel]
    r = subprocess.run(cmd, cwd=leg.work, capture_output=True, text=True)
    if r.returncode != 0:
        die(f"inner par2 failed: {r.stdout} {r.stderr}")
    inner = sorted(f for f in os.listdir(leg.work) if f.endswith(".par2"))
    for i, f in enumerate(inner):
        shutil.copy(os.path.join(leg.work, f), os.path.join(leg.post, f"Gm4tXz7{i:02d}Qd"))
    # Outer set over the inner par2 FILES (their real names), announced.
    cmd = ["par2", "create", "-r10", "-q", "outer"] + inner
    r = subprocess.run(cmd, cwd=leg.work, capture_output=True, text=True)
    if r.returncode != 0:
        die(f"outer par2 failed: {r.stdout} {r.stderr}")
    for f in sorted(os.listdir(leg.work)):
        if f.startswith("outer") and f.endswith(".par2"):
            shutil.move(os.path.join(leg.work, f), os.path.join(leg.post, f))
    # The inner set rides under hash names and the OUTER set renames it,
    # so its landed names are in no posted listing - the one place in
    # this corpus where the closed-world seed cannot see legitimate
    # furniture, and the reason `allow_extra` exists.
    leg.allow_extra("inner*.par2", "the inner recovery set, deobfuscated by the outer one")
    leg.finish()


def gen_n28(out):
    leg = Leg(
        out,
        "n28-foreign-set-decoy",
        "a junk PAR2 set covering a file that is not in the post at all",
        "ADVERSARIAL. Beside the real set rides a second, complete "
        "recovery set whose only member was never posted (a foreign or "
        "poisoned set). Correct outcome: the real payload lands under "
        "its name; the foreign set neither fails the job nor invents "
        "files; the phantom is reported honestly at most.",
    )
    data = urandom(800 * KIB)
    leg.stage("Actual.Payload.mkv", data)
    leg.expect("Actual.Payload.mkv", data)
    leg.post_file("Fj6bQw35KpD", data)
    leg.forbidden.append("Fj6bQw35KpD")
    leg.marker()
    leg.par2(15, block=65536)
    phantom = urandom(400 * KIB)
    ph = os.path.join(leg.work, "Phantom.File.bin")
    os.makedirs(leg.work, exist_ok=True)
    with open(ph, "wb") as f:
        f.write(phantom)
    cmd = ["par2", "create", "-r15", "-q", "phantomset", "Phantom.File.bin"]
    r = subprocess.run(cmd, cwd=leg.work, capture_output=True, text=True)
    if r.returncode != 0:
        die(f"phantom par2 failed: {r.stdout} {r.stderr}")
    for f in sorted(os.listdir(leg.work)):
        if f.startswith("phantomset") and f.endswith(".par2"):
            shutil.move(os.path.join(leg.work, f), os.path.join(leg.post, f))
    leg.finish()


def gen_n29(out):
    leg = Leg(
        out,
        "n29-zero-head-dvd-drill",
        "the full DVD drill: zero-head same-length VOB pair, tree, placeholder, sniffed PAR2, 10% recovery",
        "ADVERSARIAL capstone - every hard property at once, the shape "
        "a real padded-VOB DVD post has. Correct outcome: the "
        "VIDEO_TS tree lands intact with both VOBs byte-exact under "
        "their own names and the 0-byte BUP created, nothing left "
        "under hash names.",
    )
    a = bytearray(700_000)
    b = bytearray(700_000)
    a[128 * KIB :] = urandom(700_000 - 128 * KIB)
    b[128 * KIB :] = urandom(700_000 - 128 * KIB)
    leg.stage("VIDEO_TS/VTS_01_1.VOB", bytes(a))
    leg.stage("VIDEO_TS/VTS_01_2.VOB", bytes(b))
    leg.post_file("Ht8cRn52WqX", bytes(a))
    leg.post_file("Pb3fKm79ZdT", bytes(b))
    leg.expect("VIDEO_TS/VTS_01_1.VOB", bytes(a))
    leg.expect("VIDEO_TS/VTS_01_2.VOB", bytes(b))
    leg.expect("VIDEO_TS/VTS_01_0.BUP", b"")
    leg.forbidden += ["Ht8cRn52WqX", "Pb3fKm79ZdT"]
    leg.marker(subdir="VIDEO_TS")
    leg.par2(
        10,
        block=65536,
        patch=patch_splice_empty("VIDEO_TS/VTS_01_0.BUP"),
        obf_prefix="Sv6yGw24Jf",
    )
    leg.finish()


def gen_n30(out):
    leg = Leg(
        out,
        "n30-damaged-index",
        "the PAR2 index file is damaged; the volumes are intact",
        "ADVERSARIAL. The one par2 file most clients read first is "
        "poisoned mid-packet; every critical packet also rides in the "
        "volumes. Correct outcome: naming and verification proceed "
        "from the volume copies; the job completes clean.",
    )
    data = urandom(900 * KIB)
    leg.stage("Resilient.Payload.mkv", data)
    leg.expect("Resilient.Payload.mkv", data)
    leg.post_file("Lc9wDh35GtY", data)
    leg.forbidden.append("Lc9wDh35GtY")

    def poison_index(path):
        if "vol" in os.path.basename(path):
            return
        # Corrupt EVERY packet in the index - one spot proved too weak
        # once the index grew a second FileDesc (the set then activated
        # half-degraded and the with-set path had no reason to consult
        # the volumes). Each packet's body gets 8 bytes flipped, so no
        # critical-packet copy in this file survives its own MD5.
        blob = bytearray(open(path, "rb").read())
        off = 0
        while True:
            at = blob.find(b"PAR2\0PKT", off)
            if at < 0:
                break
            spot = at + 72
            if spot + 8 <= len(blob):
                for i in range(spot, spot + 8):
                    blob[i] ^= 0xA5
            off = at + 8
        open(path, "wb").write(blob)

    leg.marker()
    leg.par2(15, block=65536, patch=poison_index)
    leg.finish()


def gen_n31(out):
    leg = Leg(
        out,
        "n31-index-only-tree",
        "RECIPE: manifest-only PAR2 + directory tree + placeholder",
        "The complete post-bare-land-perfect recipe at minimum "
        "overhead: random names on the wire, one tiny PAR2 index "
        "buying names, verification, the tree and the placeholder - "
        "no recovery spend, no container bytes, no unpack pass. "
        "Correct outcome: the tree lands intact, verified, placeholder "
        "included.",
    )
    vob = urandom(int(1.2 * MIB))
    ifo = urandom(48 * KIB)
    leg.stage("VIDEO_TS/VTS_02_1.VOB", vob)
    leg.stage("VIDEO_TS/VTS_02_0.IFO", ifo)
    leg.post_file("Qk2sYv86MnB", vob)
    leg.post_file("Dw7jTc41RfH", ifo)
    leg.expect("VIDEO_TS/VTS_02_1.VOB", vob)
    leg.expect("VIDEO_TS/VTS_02_0.IFO", ifo)
    leg.expect("VIDEO_TS/VTS_02_0.BUP", b"")
    leg.forbidden += ["Qk2sYv86MnB", "Dw7jTc41RfH"]
    leg.marker(subdir="VIDEO_TS")
    leg.par2(
        5,
        block=65536,
        patch=patch_splice_empty("VIDEO_TS/VTS_02_0.BUP"),
        index_only=True,
    )
    leg.finish()


def gen_n32(out):
    leg = Leg(
        out,
        "n32-sniffed-index-only",
        "RECIPE: manifest-only PAR2 posted under a hash name too",
        "Total obfuscation at kilobyte cost: nothing on the wire says "
        "par2, nothing says a real name, and the single index file "
        "still buys full naming and verification for a client that "
        "recognises it by content. Correct outcome: identical end "
        "state to the announced index-only leg.",
    )
    data = urandom(2 * MIB)
    leg.stage("Corpus.Sniffed.Index.mkv", data)
    leg.expect("Corpus.Sniffed.Index.mkv", data)
    leg.post_file("Xt5nZb27VcW", data)
    leg.forbidden.append("Xt5nZb27VcW")
    leg.marker()
    leg.par2(5, block=65536, index_only=True, obf_prefix="Yg8hKq63Ds")
    leg.finish()


def gen_n33(out):
    leg = Leg(
        out,
        "n33-join-quarters",
        "RECIPE: raw quarters + a small PAR2 naming only the join",
        "The no-container split recipe: a file cut into four aligned "
        "raw parts under hash names, one PAR2 set describing only the "
        "joined file. No archive bytes, no unpack pass; a "
        "block-harvesting client assembles it with zero recovery "
        "spend. Correct outcome: the joined file lands byte-exact.",
    )
    data = urandom(2 * MIB)
    q = len(data) // 4
    leg.stage("Joined.Quarters.mkv", data)
    leg.expect("Joined.Quarters.mkv", data)
    for i, obf in enumerate(["Ba4cWk92NvJ", "Om6fSd18XzQ", "Ue1gLp75HbY", "Iw3jRt56KmC"]):
        leg.post_file(obf, data[i * q : (i + 1) * q])
        leg.forbidden.append(obf)
    leg.marker()
    leg.par2(10, block=65536)
    leg.finish()


def gen_n34(out):
    leg = Leg(
        out,
        "n34-sfv-tree",
        "RECIPE: SFV sidecar naming files INTO a directory tree",
        "The lightest name source carrying structure: sidecar entries "
        "spell relative paths, payloads ride under hash names. Correct "
        "outcome: files land byte-exact at their tree paths.",
    )
    import zlib

    one = urandom(500 * KIB)
    two = urandom(400 * KIB)
    mrel, mbody, _ = leg.marker(subdir="Album.Disc1", sfv=True)
    sfv = (
        "; capability corpus tree sidecar\n"
        f"Album.Disc1/track01.flac {zlib.crc32(one) & 0xFFFFFFFF:08X}\n"
        f"Album.Disc1/track02.flac {zlib.crc32(two) & 0xFFFFFFFF:08X}\n"
        f"{mrel} {zlib.crc32(mbody) & 0xFFFFFFFF:08X}\n"
    ).encode()
    leg.post_file("Nq7vBc39TdK", one)
    leg.post_file("Jf2xGm84WsR", two)
    leg.post_file("album-set.sfv", sfv)
    leg.expect("Album.Disc1/track01.flac", one)
    leg.expect("Album.Disc1/track02.flac", two)
    leg.forbidden += ["Nq7vBc39TdK", "Jf2xGm84WsR"]
    leg.finish()


def gen_n35(out):
    leg = Leg(
        out,
        "n35-unicode-names",
        "non-ASCII FileDesc names: accents, CJK, mixed scripts",
        "Cross-platform naming: PAR2 names are bytes, filesystems "
        "disagree about normalization and encodings. Correct outcome: "
        "every file lands byte-exact under a faithful rendering of its "
        "declared name on every host.",
    )
    a = urandom(300 * KIB)
    b = urandom(350 * KIB)
    c = urandom(250 * KIB)
    for name, data, obf in [
        ("\u00dcn\u00efc\u00f8de Film (2026).mkv", a, "Ah5kNw72PcM"),
        ("\u7535\u5f71.\u540d\u5b57.mkv", b, "Es8dVt31QjZ"),
        ("Fran\u00e7ais \u0438\u043c\u044f.bin", c, "Ur4mYb96LfX"),
    ]:
        leg.stage(name, data)
        leg.post_file(obf, data)
        leg.expect(name, data)
        leg.forbidden.append(obf)
    leg.marker()
    leg.par2(15, block=65536)
    leg.finish()


def gen_n36(out):
    leg = Leg(
        out,
        "n36-many-small",
        "120 small files, one recovery set, everything obfuscated",
        "The per-file overhead drill: naming, verification and "
        "publishing at file-count scale rather than byte scale. "
        "Correct outcome: all 120 land byte-exact under their real "
        "names with nothing left as a hash.",
    )
    for i in range(120):
        data = urandom(8 * KIB)
        name = f"Small.Set.{i:03d}.dat"
        obf = hashlib.md5(f"n36-{i}".encode()).hexdigest()[:11]
        leg.stage(name, data)
        leg.post_file(obf, data)
        leg.expect(name, data)
        leg.forbidden.append(obf)
    leg.marker()
    leg.par2(10)
    leg.finish()


def gen_n37(out):
    leg = Leg(
        out,
        "n37-lying-size",
        "LYING yEnc headers: =ybegin size= and total= both overstate",
        "Matrix row 20 (finding F5). Every article of the payload "
        "declares a size 77,777 bytes larger than the file really is "
        "and a part count nine larger than the post really carries, "
        "while the =ypart ranges stay true - the shape a poster's "
        "tooling produces when its header writer and its splitter "
        "disagree (get the ranges wrong instead and nothing decodes at "
        "all). The receiving client preallocates the slot at the "
        "DECLARED size, so a client that never holds the published "
        "length back to the FileDesc length ships the payload plus "
        "77,777 zero bytes of tail - at rc=0, with verify green, "
        "because PAR2 verifies the covered blocks and says nothing "
        "about what follows them. Correct outcome: the file lands "
        "byte-exact at its FileDesc length under its FileDesc name. "
        "The marker rides the same lying headers, so seeing it at its "
        "true size is the human pass signal.",
    )
    data = urandom(900 * KIB)
    leg.stage("Overstated.Feature.mkv", data)
    leg.post_file("Nx4vHd67ZpT", data)
    leg.lie("Nx4vHd67ZpT", 77_777)
    leg.expect("Overstated.Feature.mkv", data)
    leg.forbidden.append("Nx4vHd67ZpT")
    # The marker is guarded by the mechanism under test (README's rule):
    # posted through the same lie, so a client that publishes at the
    # DECLARED length lands it 77,777 bytes longer than it is, and the
    # sha256 in deobf.json refuses that.
    #
    # It is padded past 16 KiB on purpose, and the reason is a SECOND
    # hazard this leg deliberately does not carry (matrix finding F10,
    # measured 30 Aug 2026 while building this leg): the recovery-set
    # matcher's md5-16k tier asks for min(DECLARED size, 16384) head
    # bytes and only considers descriptors whose own
    # min(length, 16384) equals it, so a lie over a file whose TRUE
    # length is under 16 KiB makes the two disagree and the file never
    # joins the set at all - no claimed descriptor, so the F5
    # truncation never runs and the census guard fails the job at
    # rc=1. The boundary is exact: a lied covered file of 16384 bytes
    # passes, 16383 fails. Folding that into this leg would have made
    # row 20 ungradeable (the whole leg would have to carry a
    # `known_gap`, which passes it wholesale and hides the payload
    # result that IS the row). Give it its own leg when it is fixed.
    _mrel, _mbody, mobf = leg.marker(pad_to=20 * KIB)
    leg.lie(mobf, 77_777)
    leg.par2(20, block=65536)
    leg.finish()


LEGS = [
    gen_n01, gen_n02, gen_n03, gen_n04, gen_n05, gen_n06, gen_n07, gen_n08,
    gen_n09, gen_n10, gen_n11, gen_n12, gen_n13, gen_n14, gen_n15, gen_n16,
    gen_n17, gen_n18, gen_n19, gen_n20, gen_n21, gen_n22, gen_n23, gen_n24,
    gen_n25, gen_n26, gen_n27, gen_n28, gen_n29, gen_n30, gen_n31, gen_n32,
    gen_n33, gen_n34, gen_n35, gen_n36, gen_n37,
]


def main():
    out = os.path.join(HERE, "corpus")
    only = None
    args = sys.argv[1:]
    while args:
        a = args.pop(0)
        if a == "--out" and args:
            out = os.path.abspath(args.pop(0))
        elif a == "--leg" and args:
            only = args.pop(0)
        else:
            sys.exit(__doc__)
    if shutil.which("par2") is None:
        die("par2 not found (brew install par2)")
    if not os.path.exists(NZBSERVE):
        msg("building nzbserve (one-time)")
        r = subprocess.run(
            ["cargo", "build", "--release", "--quiet", "--manifest-path",
             os.path.join(HERE, "..", "nested-corpus", "nzbserve", "Cargo.toml")],
        )
        if r.returncode != 0 or not os.path.exists(NZBSERVE):
            die("nzbserve build failed")
    ran = 0
    for gen in LEGS:
        legid = gen.__name__[4:]  # gen_n01 -> n01
        if only and not only.startswith(legid):
            continue
        gen(out)
        ran += 1
    if ran == 0:
        die(f"--leg {only!r} matched no generator (n01..n37)")
    msg(f"done: {ran} leg(s) under {os.path.join(out, 'norar')}")


if __name__ == "__main__":
    main()
