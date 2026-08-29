#!/bin/sh
# generate.sh - build the public extreme-nesting benchmark corpus.
#
#   ./generate.sh [--quick] [--tier realistic|extreme|apocalypse|all]
#                 [--leg NAME] [--out DIR]
#
# Structure is deterministic (same legs, shapes, sizes, damage offsets);
# payload BYTES are drawn fresh from /dev/urandom each generation and
# pinned by sha256 in each leg's manifest.json. All content is generated
# here - nothing third-party, nothing copyrighted.
#
# Required tools (versions this corpus was authored against):
#   rar   7.23   (rarlab CLI; store mode, RAR5, recovery records, -p)
#   7zz   26.02  (7-Zip; or 7z/7za from p7zip - auto-detected)
#   par2  1.2.0  (par2cmdline)
#   cargo        (builds nzbserve, the NZB builder + loopback NNTP rig)
#
# Output: <out>/<tier>/<leg>/{post/,ghost/,manifest.json,<leg>.nzb}
#   post/  the files a client downloads (served as real yEnc articles)
#   ghost/ files listed in the NZB whose articles the rig answers 430
#          (only the par-only leg uses this)

set -eu
cd "$(dirname "$0")"
. ./lib.sh

QUICK=0
TIERS=all
ONLY_LEG=""
OUT="$PWD/corpus"
while [ $# -gt 0 ]; do
    case "$1" in
        --quick) QUICK=1 ;;
        --tier) TIERS=$2; shift ;;
        --leg) ONLY_LEG=$2; shift ;;
        # normalised to absolute below: the leg builders cd into work/ and
        # then reference $L/post/..., so a relative --out resolves against the
        # wrong directory and rar fails with "cannot create".
        --out) OUT=$2; shift ;;
        *) die "unknown arg: $1 (usage: generate.sh [--quick] [--tier T] [--leg NAME] [--out DIR])" ;;
    esac
    shift
done

# ---- tools ------------------------------------------------------------
command -v rar >/dev/null || die "rar CLI not found (brew install rar / rarlab.com)"
command -v par2 >/dev/null || die "par2 not found (brew install par2)"
SEVENZ=""
for c in 7zz 7z 7za; do
    command -v "$c" >/dev/null && { SEVENZ=$c; break; }
done
[ -n "$SEVENZ" ] || die "no 7-Zip CLI found (7zz/7z/7za)"
RAR_VER=$(rar -iver | tr -d '\r\n')
SEVENZ_VER=$("$SEVENZ" i 2>/dev/null | grep -m1 -E "7-Zip" | tr -s ' ' | cut -d: -f1 | sed 's/ *$//')
PAR2_VER=$(par2 --version 2>/dev/null | head -1)
msg "tools: rar $RAR_VER | $SEVENZ_VER | $PAR2_VER"

# ---- nzbserve (NZB builder) ------------------------------------------
NZBSERVE=${NZBSERVE:-"$PWD/nzbserve/target/release/nzbserve"}
if [ ! -x "$NZBSERVE" ]; then
    command -v cargo >/dev/null || die "cargo not found and NZBSERVE not set"
    msg "building nzbserve (one-time)"
    cargo build --release --quiet --manifest-path "$PWD/nzbserve/Cargo.toml" \
        || die "nzbserve build failed"
fi
[ -x "$NZBSERVE" ] || die "nzbserve missing at $NZBSERVE"

case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac

# ---- sizes ------------------------------------------------------------
if [ "$QUICK" = 1 ]; then
    SZ_REAL=25165824      # 24 MiB
    SZ_X1=12582912        # 12 MiB
    SZ_X2=6291456         # 6 MiB
    SZ_X3=12582912
    SZ_APOC=16777216      # 16 MiB
    SZ_SIB=262144         # 256 KiB
    VOL=4m
else
    SZ_REAL=1610612736    # 1.5 GiB
    SZ_X1=536870912       # 512 MiB
    SZ_X2=268435456       # 256 MiB
    SZ_X3=536870912
    SZ_APOC=402653184     # 384 MiB
    SZ_SIB=2097152        # 2 MiB
    VOL=100m
fi

# ---- shared leg steps -------------------------------------------------

# outer_post <stem> <files...> - store-mode RAR5 volumes of <files> into
# $L/post + a 10% PAR2 set over the volumes. The standard "what actually
# gets posted" wrapper for every leg.
outer_post() {
    _stem=$1; shift
    ( cd "$L/work" && rar_a "$L/post/$_stem.rar" -m0 -v$VOL -- "$@" )
    ( cd "$L/post" && par2 create -r10 -q -q "$_stem.par2" "$_stem".*rar \
        >/dev/null ) || die "par2 create failed ($LEG)"
}

# ---- realistic tier ---------------------------------------------------

gen_r1() {
    leg_init realistic r1-depth1-store
    rand_file "$L/work/movie.bin" $SZ_REAL
    rand_file "$L/work/sample.bin" $SZ_SIB
    add_payload "$L/work/movie.bin" 1
    add_payload "$L/work/sample.bin" 1
    outer_post r1 movie.bin sample.bin
    finish_leg "rar(store,vols)+par2 > payload" 1 \
        '{"nzbfast":"auto-complete","nzbget":"auto-complete","sabnzbd":"auto-complete","rustnzb":"auto-complete"}' \
        "Baseline: single store-mode layer, the shape every client automates."
}

gen_r2() {
    leg_init realistic r2-depth2-store-store
    rand_file "$L/work/movie.bin" $SZ_REAL
    add_payload "$L/work/movie.bin" 2
    ( cd "$L/work" && rar_a inner.rar -m0 -- movie.bin && rm movie.bin )
    outer_post r2 inner.rar
    finish_leg "rar(store,vols)+par2 > rar(store) > payload" 2 \
        '{"nzbfast":"auto-complete","nzbget":"manual-intervention","sabnzbd":"auto-complete","rustnzb":"manual-intervention"}' \
        "Classic obfuscation shape: store RAR inside store RAR. Expected classes are hypotheses until a client is actually run; run-legs.sh records measured classes."
}

gen_r2c() {
    leg_init realistic r2c-depth2-store-compressed
    rand_file "$L/work/movie.bin" $SZ_REAL
    add_payload "$L/work/movie.bin" 2
    ( cd "$L/work" && rar_a inner.rar -m3 -- movie.bin && rm movie.bin )
    outer_post r2c inner.rar
    finish_leg "rar(store,vols)+par2 > rar(m3) > payload" 2 \
        '{"nzbfast":"auto-complete","nzbget":"manual-intervention","sabnzbd":"auto-complete","rustnzb":"manual-intervention"}' \
        "Depth-2 with a COMPRESSED inner layer - the shape the chasing-decompressor work targets."
}

gen_r3() {
    leg_init realistic r3-rar-wrap-7z
    rand_file "$L/work/movie.bin" $SZ_REAL
    add_payload "$L/work/movie.bin" 2
    ( cd "$L/work" && "$SEVENZ" a -bso0 -bsp0 -mx1 payload.7z movie.bin \
        && rm movie.bin ) || die "7z a failed"
    outer_post r3 payload.7z
    finish_leg "rar(store,vols)+par2 > 7z(lzma2) > payload" 2 \
        '{"nzbfast":"auto-complete","nzbget":"manual-intervention","sabnzbd":"auto-complete","rustnzb":"manual-intervention"}' \
        "RAR wrapping 7z: end-loaded inner metadata (7z keeps its content map at the tail)."
}

# ---- extreme tier -----------------------------------------------------

# ladder <leg> <depth> <payload-bytes>: level D holds payload+sibling_D,
# level k holds level_(k+1).rar + sibling_k, level 1 is the posted outer.
gen_ladder() {
    leg_init extreme "$1"
    _depth=$2
    rand_file "$L/work/payload.bin" "$3"
    add_payload "$L/work/payload.bin" "$_depth"
    _k=$_depth
    while [ "$_k" -ge 1 ]; do
        rand_file "$L/work/sibling_$_k.bin" $SZ_SIB
        add_payload "$L/work/sibling_$_k.bin" "$_k"
        _k=$((_k - 1))
    done
    _k=$_depth
    _inner=payload.bin
    while [ "$_k" -ge 2 ]; do
        ( cd "$L/work" && rar_a "level_$_k.rar" -m0 -- "$_inner" "sibling_$_k.bin" \
            && rm "$_inner" "sibling_$_k.bin" )
        _inner="level_$_k.rar"
        _k=$((_k - 1))
    done
    outer_post "$1" "$_inner" sibling_1.bin
}

gen_x1() {
    gen_ladder x1-depth5-ladder 5 $SZ_X1
    finish_leg "rar(store,vols)+par2 > rar(store) x4 > payload (sibling file at every level)" 5 \
        '{"nzbfast":"auto-complete","nzbget":"manual-intervention","sabnzbd":"manual-intervention","rustnzb":"manual-intervention"}' \
        "Depth-5 all-store ladder, sibling file at every level. Exactly at nzbfast NEST_MAX_DEPTH=5."
}

gen_x2() {
    gen_ladder x2-depth10-ladder 10 $SZ_X2
    finish_leg "rar(store,vols)+par2 > rar(store) x9 > payload (sibling file at every level)" 10 \
        '{"nzbfast":"manual-intervention","nzbget":"manual-intervention","sabnzbd":"manual-intervention","rustnzb":"manual-intervention"}' \
        "Depth-10 ladder. nzbfast defaults the nested depth cap to 5 (the in-stream child chain and the disk post-pass share one nested_max_depth setting), so at the default this leg exercises graceful materialization at the cap - the deepest reached layer is left as a healthy archive, rc=0, never a failed job. Raise nested_max_depth (or NZBFAST_NESTED_MAX_DEPTH=10) to auto-complete the whole ladder."
}

gen_x3() {
    leg_init extreme x3-mixed-7z-rar-store
    rand_file "$L/work/payload.bin" $SZ_X3
    add_payload "$L/work/payload.bin" 3
    ( cd "$L/work" && rar_a inner.rar -m0 -- payload.bin && rm payload.bin )
    ( cd "$L/work" && "$SEVENZ" a -bso0 -bsp0 -mx1 mid.7z inner.rar \
        && rm inner.rar ) || die "7z a failed"
    outer_post x3 mid.7z
    finish_leg "rar(store,vols)+par2 > 7z(lzma2) > rar(store) > payload" 3 \
        '{"nzbfast":"auto-complete","nzbget":"manual-intervention","sabnzbd":"manual-intervention","rustnzb":"manual-intervention"}' \
        "Mixed-format chain: alternating 7z and RAR layers over a store core."
}

# ---- apocalypse tier --------------------------------------------------

gen_r4() {
    leg_init realistic r4-inner-damaged
    rand_file "$L/work/movie.bin" $SZ_REAL
    add_payload "$L/work/movie.bin" 2
    # THE FIELD SHAPE THIS LEG EXISTS FOR: the post arrives intact and the
    # ARCHIVE INSIDE IT does not. One recovery pass is needed, and it is
    # needed on content that only exists AFTER the outer archive has been
    # opened - which is a different operation from repairing the posted set,
    # and the one most clients stop at.
    #
    # Level 2 (inner): a plain store RAR of the payload. Its PAR2 is computed
    # BEFORE the damage and travels with it, so the recovery set is complete
    # and the repair is genuinely available to any client that looks for it.
    ( cd "$L/work" && rar_a inner.rar -m0 -- movie.bin && rm movie.bin )
    ( cd "$L/work" && par2 create -r10 -q -q inner.par2 inner.rar >/dev/null )
    poison "$L/work/inner.rar"
    # Level 1 (outer, posted): HEALTHY volumes and a HEALTHY posted PAR2.
    # Nothing is wrong with the transfer, which is the whole point - a client
    # cannot reach the payload by being good at the posted set alone, and a
    # leg that damaged the outer too would let a client that repairs only
    # what was posted look like it had solved this one.
    ( cd "$L/work" && rar_a "$L/post/r4.rar" -m0 -v$VOL -- inner.rar inner*.par2 )
    ( cd "$L/post" && par2 create -r10 -q -q r4.par2 r4.*rar >/dev/null )
    finish_leg "rar(store,vols)+par2 healthy > rar(store,damaged)+par2-alongside > payload" 2 \
        '{}' \
        "Intact post, damaged inner archive, inner PAR2 packed alongside it. 64 bytes poisoned in inner.rar AFTER its PAR2 was computed, so the recovery set is complete and the repair is available to anyone who looks. Recovery chain: extract the outer, par2 repair inner.rar, extract the rebuilt archive. Realistic tier on purpose - this is a bad source or a partial re-post, not a torture shape, and unlike a1 it needs exactly ONE repair and no rar recovery record."
}

gen_a1() {
    leg_init apocalypse a1-damage-every-level
    rand_file "$L/work/payload.bin" $SZ_APOC
    add_payload "$L/work/payload.bin" 3
    # Level 3 (innermost): store RAR with a 10% recovery record, then
    # 64 poisoned bytes. rar's own RR can repair it (rar r).
    ( cd "$L/work" && rar_a level3.rar -m0 -rr10p -- payload.bin && rm payload.bin )
    poison "$L/work/level3.rar"
    # Level 2: wraps the (damaged-inside) level3, gets its own PAR2, then
    # 64 poisoned bytes AFTER the PAR2 was computed. The level-2 PAR2
    # travels alongside level2.rar inside the outer archive.
    ( cd "$L/work" && rar_a level2.rar -m0 -- level3.rar && rm level3.rar )
    ( cd "$L/work" && par2 create -r10 -q -q level2.par2 level2.rar >/dev/null )
    poison "$L/work/level2.rar"
    # Level 1 (outer, posted): volumes + outer PAR2, then poison one
    # middle volume AFTER the PAR2 was computed.
    ( cd "$L/work" && rar_a "$L/post/a1.rar" -m0 -v$VOL -- level2.rar level2*.par2 )
    ( cd "$L/post" && par2 create -r10 -q -q a1.par2 a1.*rar >/dev/null )
    _vict=$(ls "$L/post" | grep -E '\.part0*2\.rar$' || true)
    [ -n "$_vict" ] || _vict=$(ls "$L/post" | grep -E '\.rar$' | head -1)
    poison "$L/post/$_vict"
    finish_leg "rar(store,vols,damaged)+par2 > rar(store,damaged)+par2-alongside > rar(store,damaged,rr10) > payload" 3 \
        '{"nzbfast":"manual-intervention","nzbget":"manual-intervention","sabnzbd":"manual-intervention","rustnzb":"manual-intervention"}' \
        "64 bytes poisoned at every level, each level carrying its own recovery (outer PAR2 posted, level-2 PAR2 packed alongside it inside the outer, recovery record inside level 3). Outer repair is automatic for PAR2-aware clients; levels 2 and 3 need the operator to run par2 and rar r by hand today. Full recovery chain: outer PAR2 repair, extract, par2 repair level2.rar, extract, rar r level3.rar, extract rebuilt archive."
}

gen_a2() {
    leg_init apocalypse a2-par-only
    rand_file "$L/work/payload.bin" $SZ_APOC
    add_payload "$L/work/payload.bin" 1
    ( cd "$L/work" && rar_a "$L/post/a2.rar" -m0 -v$VOL -- payload.bin )
    # 100% recovery data: enough blocks to rebuild the ENTIRE volume set.
    ( cd "$L/post" && par2 create -r100 -q -q a2.par2 a2.*rar >/dev/null )
    # The volumes are listed in the NZB but every article answers 430:
    # the rig's ghost/ dir. par2 alone must reconstruct them.
    mv "$L/post/"a2.*rar "$L/ghost/"
    finish_leg "par2(100%) only; rar(store,vols) ghosted > payload" 1 \
        '{"nzbfast":"auto-complete","nzbget":"manual-intervention","sabnzbd":"manual-intervention","rustnzb":"fail"}' \
        "Every archive article is missing (430); the posted PAR2 set carries 100% recovery data, enough to rebuild the whole volume set from nothing. Tests whole-file reconstruction, the hardest PAR2 path."
}

gen_a3() {
    leg_init apocalypse a3-password-chain
    PW1=corpus-a3-l1 PW2=corpus-a3-l2 PW3=corpus-a3-l3
    rand_file "$L/work/payload.bin" $SZ_APOC
    add_payload "$L/work/payload.bin" 3
    ( cd "$L/work" && rar_a level3.rar -m0 "-p$PW3" -- payload.bin && rm payload.bin )
    printf '%s\n' "$PW3" > "$L/work/password_l3.txt"
    add_payload "$L/work/password_l3.txt" 2
    ( cd "$L/work" && rar_a level2.rar -m0 "-p$PW2" -- level3.rar password_l3.txt \
        && rm level3.rar password_l3.txt )
    printf '%s\n' "$PW2" > "$L/work/password_l2.txt"
    add_payload "$L/work/password_l2.txt" 1
    ( cd "$L/work" && rar_a "$L/post/a3.rar" -m0 -v$VOL "-p$PW1" -- level2.rar password_l2.txt )
    # The outer password is posted in the clear next to the volumes.
    printf '%s\n' "$PW1" > "$L/post/password_l1.txt"
    ( cd "$L/post" && par2 create -r10 -q -q a3.par2 a3.*rar >/dev/null )
    finish_leg "rar(store,vols,pw)+par2 > rar(store,pw) > rar(store,pw) > payload (password_k.txt at each level)" 3 \
        '{"nzbfast":"manual-intervention","nzbget":"manual-intervention","sabnzbd":"manual-intervention","rustnzb":"fail"}' \
        "Password chain: each level is AES-encrypted and ships the NEXT level's password as a sibling text file. The outer password rides in the clear (password_l1.txt) and in the manifest. No client automates reading a password out of an extracted file; every layer past the first is a manual step." \
        '{"level1":"'"$PW1"'","level2":"'"$PW2"'","level3":"'"$PW3"'"}'
}

# ---- dispatch ---------------------------------------------------------

want() {
    [ -z "$ONLY_LEG" ] || [ "$ONLY_LEG" = "$1" ]
}
tier_on() {
    [ "$TIERS" = all ] || [ "$TIERS" = "$1" ]
}

mkdir -p "$OUT"
START=$(date +%s)
if tier_on realistic; then
    if want r1-depth1-store; then gen_r1; fi
    if want r2-depth2-store-store; then gen_r2; fi
    if want r2c-depth2-store-compressed; then gen_r2c; fi
    if want r3-rar-wrap-7z; then gen_r3; fi
    if want r4-inner-damaged; then gen_r4; fi
fi
if tier_on extreme; then
    if want x1-depth5-ladder; then gen_x1; fi
    if want x2-depth10-ladder; then gen_x2; fi
    if want x3-mixed-7z-rar-store; then gen_x3; fi
fi
if tier_on apocalypse; then
    if want a1-damage-every-level; then gen_a1; fi
    if want a2-par-only; then gen_a2; fi
    if want a3-password-chain; then gen_a3; fi
fi
msg "done in $(( $(date +%s) - START ))s -> $OUT"
