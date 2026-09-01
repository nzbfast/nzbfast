# lib.sh - shared helpers for the nested-corpus generator. Sourced by
# generate.sh / validate.sh; POSIX sh, macOS + Linux.

msg() { printf '[nested-corpus] %s\n' "$*"; }
die() { printf '[nested-corpus] ERROR: %s\n' "$*" >&2; exit 1; }

# Portable file size in bytes.
fsize() {
    stat -f%z "$1" 2>/dev/null || stat -c%s "$1"
}

sha256() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        sha256sum "$1" | cut -d' ' -f1
    fi
}

# rand_file <path> <bytes> - payload bytes straight from /dev/urandom.
# Generated content only: no third-party material enters the corpus.
rand_file() {
    head -c "$2" /dev/urandom > "$1"
    [ "$(fsize "$1")" = "$2" ] || die "short read generating $1"
}

# passed_file <dir> <leg-name> - the TEST PASSED marker, written where
# the DEEPEST layer is built so it only lands when the whole chain ran
# (an inner archive left unopened in the output directory cannot fake
# it). Presence is the human pass signal; the manifest checksums stay
# the grading truth. Leaves the filename in $_pf for the archive line.
passed_file() {
    _pf="TEST PASSED - $2.txt"
    printf 'TEST PASSED\r\n\r\nCapability test %s.\r\nSeeing this file means your client completed the full chain of this test.\r\nFull grading lives in the published manifest.\r\n' \
        "$2" > "$1/$_pf"
}

# poison <file> - overwrite 64 bytes at the 3/5 point with fresh random
# bytes (post-generation damage; always after any PAR2/RR covering it).
poison() {
    _sz=$(fsize "$1")
    [ "$_sz" -gt 1024 ] || die "poison target too small: $1"
    _off=$((_sz * 3 / 5))
    dd if=/dev/urandom of="$1" bs=1 seek="$_off" count=64 conv=notrunc 2>/dev/null
    msg "poisoned 64 bytes at offset $_off of $(basename "$1")"
}

# ---- tool wrappers (versions checked once by generate.sh) -------------

# rar_a <archive> <flags...> -- <files...>   (cwd must hold the files)
rar_a() {
    _arc=$1; shift
    _flags=""
    while [ "$1" != "--" ]; do _flags="$_flags $1"; shift; done
    shift
    # -idq quiet, -ma5 RAR5, -y assume yes, -ep no paths stored
    # shellcheck disable=SC2086
    rar a -idq -y -ma5 -ep $_flags "$_arc" "$@" || die "rar a $_arc failed"
}

# ---- leg lifecycle ----------------------------------------------------

# leg_init <tier> <leg> - (re)creates $L with post/ ghost/ work/.
leg_init() {
    TIER=$1
    LEG=$2
    L="$OUT/$TIER/$LEG"
    rm -rf "$L"
    mkdir -p "$L/post" "$L/ghost" "$L/work"
    : > "$L/work/payloads.tsv"
    msg "=== $TIER/$LEG ==="
}

# add_payload <file> [depth] - record a final-output file (name, size,
# sha256) in the manifest payload list. Call BEFORE the file is wrapped
# or damaged.
add_payload() {
    printf '%s\t%s\t%s\t%s\n' \
        "$(basename "$1")" "$(fsize "$1")" "$(sha256 "$1")" "${2:-}" \
        >> "$L/work/payloads.tsv"
}

# finish_leg <shape> <depth> <expected-json> <notes> [passwords-json]
# Writes manifest.json, builds the NZB, drops work/.
finish_leg() {
    _shape=$1 _depth=$2 _expected=$3 _notes=$4 _pw=${5:-null}
    LEGDIR="$L" SHAPE="$_shape" DEPTH="$_depth" TIER="$TIER" LEG="$LEG" \
    EXPECTED="$_expected" NOTES="$_notes" PASSWORDS="$_pw" QUICK="$QUICK" \
    RAR_VER="$RAR_VER" SEVENZ_VER="$SEVENZ_VER" PAR2_VER="$PAR2_VER" \
    python3 - <<'PY' || die "manifest emit failed for $LEG"
import json, os, sys, datetime

L = os.environ["LEGDIR"]
payloads = []
for line in open(os.path.join(L, "work", "payloads.tsv")):
    name, size, sha, depth = line.rstrip("\n").split("\t")
    p = {"name": name, "bytes": int(size), "sha256": sha}
    if depth:
        p["at_depth"] = int(depth)
    payloads.append(p)

def listing(sub):
    d = os.path.join(L, sub)
    if not os.path.isdir(d):
        return []
    return sorted(
        [{"name": n, "bytes": os.path.getsize(os.path.join(d, n))}
         for n in os.listdir(d)
         if not n.startswith(".") and os.path.isfile(os.path.join(d, n))],
        key=lambda e: e["name"])

pw = os.environ["PASSWORDS"]
manifest = {
    "leg": os.environ["LEG"],
    "tier": os.environ["TIER"],
    "shape": os.environ["SHAPE"],
    "depth": int(os.environ["DEPTH"]),
    "quick": os.environ["QUICK"] == "1",
    "generated_utc": datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
    "tools": {
        "rar": os.environ["RAR_VER"],
        "7zip": os.environ["SEVENZ_VER"],
        "par2": os.environ["PAR2_VER"],
    },
    "payloads": payloads,
    "post_files": listing("post"),
    "ghost_files": listing("ghost"),
    "passwords": json.loads(pw) if pw != "null" else None,
    "expected": json.loads(os.environ["EXPECTED"]),
    "notes": os.environ["NOTES"],
}
with open(os.path.join(L, "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
print(f"[nested-corpus] manifest: {len(payloads)} payload(s), "
      f"{len(manifest['post_files'])} posted, "
      f"{len(manifest['ghost_files'])} ghosted")
PY
    "$NZBSERVE" build "$L" || die "nzb build failed for $LEG"
    rm -rf "$L/work"
}
