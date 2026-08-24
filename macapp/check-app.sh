#!/bin/bash
# Check an assembled NzbFast.app - the bundle macapp/make-app.sh writes.
#
#   ./check-app.sh [path/to/NzbFast.app]   default: build/NzbFast.app
#   ./check-app.sh --selftest [path]       prove every arm below can fail
#
# WHY THIS EXISTS. `swift build` (the macapp-build job) covers the
# WRAPPER. It does not cover the BUNDLE: make-app.sh also parses the
# version out of crates/nzbfast/Cargo.toml and the beta serial out of
# packaging/beta-serial.txt, renders a ten-entry iconset through sips
# and iconutil, writes Info.plist from a heredoc, and ad-hoc codesigns
# inside-out. Every one of those can break WITHOUT breaking the build:
# a parse that quietly matches nothing still emits a plist, and a plist
# with an empty CFBundleShortVersionString still assembles, still signs
# and still verifies. Until this landed the first thing that would ever
# have caught one was somebody cutting a release - which is the sentence
# .github/workflows/macapp.yml opens with about the Swift, one layer in.
#
# EVERY ARM HERE IS A FAILURE MODE SOMEBODY CAN STATE, not a checklist
# for its own sake. In arm order:
#
#   plist    A hand edit to the heredoc drops a </dict> or a </array>,
#            or the interpolated version carries an & or a <. The bundle
#            assembles and signs; macOS then refuses to launch it, and
#            nothing before the release notices.
#   version  make-app.sh reads the version with
#            `grep '^version' | head -1 | cut -d'"' -f2`. Move that key
#            to workspace inheritance (`version.workspace = true`) or
#            put any other `^version` line above it and the parse yields
#            the WRONG string or an EMPTY one, silently - this arm reads
#            the same file with a real TOML parser instead, so the two
#            cannot rot together.
#   beta     Same shape, and it is load-bearing: the wrapper compares
#            the serial in its own Info.plist against the RUNNING
#            engine's to decide whether an attach needs a restart (the
#            §98 upgrade restart), so a serial that reads 0 while the
#            engine was built at 2 means the wrapper attaches to a stale
#            engine and never says so.
#   icon     The sips loop writes ten members. Drop one - an edit to
#            that list, a sips that errors into a zero-byte png - and
#            the icns still builds; the app just renders wrong at one
#            size, in one place, on somebody else's Mac.
#   arch     make-app.sh builds the wrapper `--arch arm64 --arch x86_64`.
#            Lose one arch and the app is silently Apple-Silicon-only:
#            no build error, no signing error, an Intel Mac just cannot
#            open it.
#   payload  The engine has to be IN the bundle, executable, and a real
#            Mach-O. A cp that lands the wrong path fails loudly; a
#            chmod that does not is what this arm is for.
#   sign     make-app.sh signs the nested engine FIRST and then the app,
#            and its comment says why (arm64 refuses unsigned Mach-Os,
#            and lipo output has no signature to inherit). The outer
#            seal covers the engine as a RESOURCE, which means an
#            UNSIGNED engine seals perfectly well - so `--verify --deep
#            --strict` on the app cannot see the defect that ordering
#            exists to prevent, and the engine gets its own verify.
#            Checked here rather than trusted to the script's own final
#            verify line, because a future edit can delete that line and
#            nothing else would say so.
#
# NOT CHECKED, deliberately: that the ENGINE is universal. CI hands
# make-app.sh a stub through ENGINE=, so there is nothing real to
# measure; the release lipo is packaging/build-bundles.sh's business.
set -uo pipefail
# Resolve the target BEFORE the cd, so a path given from the repo root
# (which is where CI runs this from) means what the caller typed.
ARG="${1:-}"; ARG2="${2:-}"
abspath() { case "$1" in ''|/*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }
[ "$ARG" = "--selftest" ] && ARG2=$(abspath "$ARG2") || ARG=$(abspath "$ARG")
cd "$(dirname "$0")"
REPO="$(cd .. && pwd)"

FAILED=0
fail() { echo "FAIL $1: $2"; FAILED=1; }
ok()   { printf '   ok   %-8s %s\n' "$1" "$2"; }
# codesign reports on two lines and leads with the full path; keep every
# word of it (the architecture is on the second line) but on one line.
tidy() { local m=${1//$2/}; echo "${m//$'\n'/ }" | sed 's/^: //'; }

# A missing tool must REFUSE, never skip. An arm that silently does not
# run is the rubber stamp this file exists to avoid being.
need() {
    command -v "$1" >/dev/null 2>&1 || { echo "REFUSE: $1 not on PATH"; exit 2; }
}

check_app() {
    local app="$1"
    [ -d "$app" ] || { echo "REFUSE: no bundle at $app"; return 2; }
    local plist="$app/Contents/Info.plist"
    [ -f "$plist" ] || { echo "REFUSE: no Info.plist in $app"; return 2; }
    echo "== checking $app"

    # --- plist ---------------------------------------------------------
    local lint
    if lint=$(plutil -lint "$plist" 2>&1); then
        ok plist "Info.plist parses"
    else
        fail plist "${lint##*: }"
    fi

    # --- version -------------------------------------------------------
    local want got gotv
    want=$(python3 - "$REPO" <<'PY'
import sys, tomllib, pathlib
repo = pathlib.Path(sys.argv[1])
d = tomllib.loads((repo / "crates/nzbfast/Cargo.toml").read_text())
v = d["package"]["version"]
if isinstance(v, dict):   # version.workspace = true
    v = tomllib.loads((repo / "Cargo.toml").read_text())["workspace"]["package"]["version"]
print(v)
PY
)
    got=$(plutil -extract CFBundleShortVersionString raw -o - "$plist" 2>/dev/null)
    gotv=$(plutil -extract CFBundleVersion raw -o - "$plist" 2>/dev/null)
    if [ -z "$want" ]; then
        fail version "could not read package.version from crates/nzbfast/Cargo.toml"
    elif [ "$got" != "$want" ]; then
        fail version "CFBundleShortVersionString is '$got', Cargo.toml says '$want'"
    elif [ "$gotv" != "$want" ]; then
        fail version "CFBundleVersion is '$gotv', Cargo.toml says '$want'"
    else
        ok version "$got, from crates/nzbfast/Cargo.toml"
    fi

    # --- beta ----------------------------------------------------------
    # The "0 or missing = release" rule, spelled out here rather than
    # borrowed, so a change to make-app.sh's parse shows up as a
    # DISAGREEMENT. Note the limit: this does not read the engine's own
    # build.rs, so a change to the rule ITSELF has to move both.
    local wantbeta gotbeta
    wantbeta=$(tr -d '[:space:]' < "$REPO/packaging/beta-serial.txt" 2>/dev/null)
    case "$wantbeta" in ''|*[!0-9]*) wantbeta=0 ;; esac
    gotbeta=$(plutil -extract NzbFastBetaSerial raw -o - "$plist" 2>/dev/null)
    if [ "$gotbeta" != "$wantbeta" ]; then
        fail beta "NzbFastBetaSerial is '$gotbeta', packaging/beta-serial.txt says '$wantbeta'"
    else
        ok beta "serial $gotbeta"
    fi

    # --- icon ----------------------------------------------------------
    local icns tmp members
    icns="$app/Contents/Resources/NzbFast.icns"
    if [ ! -s "$icns" ]; then
        fail icon "NzbFast.icns missing or empty"
    else
        tmp=$(mktemp -d)
        if iconutil -c iconset "$icns" -o "$tmp/back.iconset" >/dev/null 2>&1; then
            members=$(ls "$tmp/back.iconset" | wc -l | tr -d ' ')
            if [ "$members" != "10" ]; then
                fail icon "icns carries $members members, make-app.sh writes 10"
            else
                ok icon "icns, all 10 members"
            fi
        else
            fail icon "iconutil cannot read the icns back"
        fi
        rm -rf "$tmp"
    fi

    # --- arch ----------------------------------------------------------
    local wrapper archs
    wrapper="$app/Contents/MacOS/NzbFast"
    if [ ! -f "$wrapper" ]; then
        fail arch "no Contents/MacOS/NzbFast"
    else
        archs=$(lipo -archs "$wrapper" 2>/dev/null)
        case " $archs " in
            *" arm64 "*) case " $archs " in
                             *" x86_64 "*) ok arch "wrapper is universal ($archs)" ;;
                             *) fail arch "wrapper has no x86_64 slice ($archs)" ;;
                         esac ;;
            *) fail arch "wrapper has no arm64 slice ($archs)" ;;
        esac
    fi

    # --- payload -------------------------------------------------------
    local engine
    engine="$app/Contents/Resources/bin/nzbfast"
    if [ ! -f "$engine" ]; then
        fail payload "no Contents/Resources/bin/nzbfast"
    elif [ ! -x "$engine" ]; then
        fail payload "the bundled engine is not executable"
    elif ! file -b "$engine" | grep -q 'Mach-O'; then
        fail payload "the bundled engine is not a Mach-O"
    else
        ok payload "engine present, executable, Mach-O"
    fi

    # --- sign ----------------------------------------------------------
    local err
    if err=$(codesign --verify --deep --strict "$app" 2>&1); then
        if [ -f "$engine" ] && ! err=$(codesign --verify --strict "$engine" 2>&1); then
            fail sign "the nested engine: $(tidy "$err" "$app")"
        else
            ok sign "app verifies --deep --strict, engine signed"
        fi
    else
        fail sign "$(tidy "$err" "$app")"
    fi

    return $FAILED
}

# ---------------------------------------------------------------------
# THE CANARY. Every arm above is driven at a bundle mutated to break it
# exactly, and must NAME that arm. Without this the whole file is a
# green line nobody can tell from a dead one - the failure mode
# CLAUDE.md's gate list keeps growing to refuse (the dead picker arm in
# web/i18n/nav-regen.py reported every picker current while matching
# none of them, and site-crosslink.py printed OK on both arms with its
# one regex broken).
selftest() {
    local src="$1" rc=0
    [ -d "$src" ] || { echo "REFUSE: --selftest needs a real bundle; none at $src"; exit 2; }
    local root; root=$(mktemp -d)

    # A copy that is NOT mutated has to pass, or every case below proves
    # nothing but that the checker is broken.
    ditto "$src" "$root/control/NzbFast.app"
    if (FAILED=0; check_app "$root/control/NzbFast.app" >/dev/null); then
        printf '   ok   %-8s %s\n' control "an unmutated copy passes"
    else
        echo "SELFTEST FAIL control: an unmutated copy does not pass"
        check_app "$root/control/NzbFast.app"
        rc=1
    fi

    local case app out
    for case in plist version beta icon arch payload sign; do
        app="$root/$case/NzbFast.app"
        ditto "$src" "$app"
        case "$case" in
        # A dropped closing tag, which is the modelled defect. NOT
        # trailing junk after </plist>: plutil -lint ACCEPTS that
        # (measured 24 Aug 2026), so a canary built on it would report
        # this arm dead when it is merely tolerant.
        plist)   sed -i '' '$d' "$app/Contents/Info.plist" ;;
        version) plutil -replace CFBundleShortVersionString -string 9.9.9-canary \
                     "$app/Contents/Info.plist" ;;
        beta)    plutil -replace NzbFastBetaSerial -string 424242 \
                     "$app/Contents/Info.plist" ;;
        icon)    local t; t=$(mktemp -d)
                 iconutil -c iconset "$app/Contents/Resources/NzbFast.icns" \
                     -o "$t/i.iconset" >/dev/null 2>&1
                 rm -f "$t/i.iconset/icon_16x16@2x.png"
                 iconutil -c icns "$t/i.iconset" \
                     -o "$app/Contents/Resources/NzbFast.icns" >/dev/null 2>&1
                 rm -rf "$t" ;;
        arch)    lipo -thin arm64 "$app/Contents/MacOS/NzbFast" \
                     -output "$app/Contents/MacOS/NzbFast.thin" >/dev/null 2>&1
                 mv "$app/Contents/MacOS/NzbFast.thin" "$app/Contents/MacOS/NzbFast" ;;
        payload) chmod -x "$app/Contents/Resources/bin/nzbfast" ;;
        sign)    codesign --remove-signature "$app" >/dev/null 2>&1 ;;
        esac
        out=$(FAILED=0; check_app "$app" 2>&1)
        if echo "$out" | grep -q "^FAIL $case:"; then
            printf '   ok   %-8s %s\n' "$case" "refused, as it must be"
        else
            echo "SELFTEST FAIL $case: the mutation was not refused by the $case arm"
            echo "$out" | sed 's/^/      /'
            rc=1
        fi
    done

    # And the refusal that is not an arm: no bundle at all.
    out=$(check_app "$root/nothing-here.app" 2>&1); local absent_rc=$?
    if [ $absent_rc -eq 2 ]; then
        printf '   ok   %-8s %s\n' absent "a missing bundle refuses"
    else
        echo "SELFTEST FAIL absent: a missing bundle did not refuse"
        rc=1
    fi

    rm -rf "$root"
    [ $rc -eq 0 ] && echo "selftest: every arm bites"
    return $rc
}

need plutil; need lipo; need codesign; need iconutil; need python3; need ditto

if [ "$ARG" = "--selftest" ]; then
    selftest "${ARG2:-build/NzbFast.app}"
    exit $?
fi

check_app "${ARG:-build/NzbFast.app}"
rc=$?
[ $rc -eq 0 ] && echo "NzbFast.app: all checks pass"
exit $rc
