#!/usr/bin/env bash
# build-parfast-gui-bundles.sh [dist-dir] [arch...]
#
# Build the parfast DESKTOP APP assets: a macOS DMG and zip, a Windows
# zip and Inno installer. The apps are `apps/parfast/mac` (SwiftUI) and
# `apps/parfast/windows` (WinUI 3) over the C ABI of
# `apps/parfast/crates/parfast-ffi`, which lives with its sibling in a
# DETACHED cargo workspace at `apps/parfast/Cargo.toml` that the root
# manifest never names (decision D2a). Every cargo line here therefore
# carries `--manifest-path`, and the artefacts land in
# `apps/parfast/target/`, not the root one. Design record:
# research/PLAN-PARFAST-GUI-2026-09-12.md, sections 4.4 and 6.3
# (TODO 342).
#
#   dist-dir   where the assets land (default ./dist-parfast-gui)
#   arch...    a subset of: macos-universal windows-x64
#              (default: macos-universal on a Mac, nothing elsewhere)
#
#   --check    report what is present and what is missing, build nothing
#   --remote H the ssh host that builds the Windows half (required for
#              windows-x64; there is deliberately no default, see below)
#   --skip-build   package what is already built, compile nothing
#
# WHY A THIRD BUNDLE SCRIPT. packaging/build-bundles.sh packages the
# nzbfast daemon; packaging/build-parfast-bundles.sh packages the
# parfast CLI, and its header argues at length why threading a second
# product through the first one's machinery buys a product test in every
# step of it. That argument is not weaker for a third product, it is
# stronger: this one is a pair of NATIVE GUI APPS with a code-signing
# story, a bundle layout, a .NET publish and an installer between them,
# and it shares with the CLI only the version string and the `-beta`
# convention. Same reasoning, same answer, own file.
#
# `-beta` IN EVERY FILENAME, for build-parfast-bundles.sh's reason and
# one more of its own. That script's header: the release notes are one
# page a downloader may never read, and an asset list is what they
# actually click, so the filename has to carry the warning. The extra
# reason here is that these apps are PRIVATE (plan decision D2), so
# these bundles go to the maintainer and to testers by hand, one at a
# time, with no release page around them to carry a caveat at all.
#
# THE WINDOWS HOST IS NOT NAMED IN THIS FILE, and that is a decision
# rather than an omission. Two reasons, and the second is the one that
# matters:
#
#   * every fleet hostname is refused in a file that ships publicly
#     (packaging/private-patterns.txt), and `packaging` is on
#     PUBLIC_MANIFEST wholesale. packaging/windows/make-installer.sh
#     answers that by being stripped from the export AND exempted from
#     the name scan - two hand-maintained lists that must stay in sync -
#     and this script is stripped anyway (see the next block), so it
#     could have gone the same way.
#   * it did not, because the machine roster's first rule is to ASK THE
#     BOX before writing to its tree: the claims ledger records who
#     INTENDS to work an item and cannot see a build, and a lane once
#     moved another lane's warm target directory out from under a
#     running test suite on exactly this box. A script with the host
#     baked in is an invitation to skip that question. `--remote` with
#     no default makes choosing the box a thing you did on purpose.
#
#     Which box, and how to reach it, is in the private machine roster
#     in the maintainer notes - the same place the rig-lock and ledger rules for
#     it live. Read that before pointing this at anything.
#
# WHY THIS IS IN apps/parfast/packaging/ AND NOT packaging/, where every
# other bundle script in this repo lives. It was in packaging/ for one
# day, held out of the public export by a removal line in
# publish-public.sh beside make-installer.sh's, and that worked. It is
# here instead because of the rule plan 4.4 gained on 12 Sep 2026:
#
#   PREFER MOVING A FILE INTO apps/parfast/ OVER ADDING A REMOVAL LINE.
#
# A removal line is a STRIP RULE, and a strip rule that stops matching
# ships the file in silence. Both of this repository's historical publish
# breakages were exactly that, and neither was noticed until somebody
# went to cut a release. A path that is simply not on the manifest cannot
# fail that way: there is no rule to stop matching. So a removal line is
# for a location we do not CONTROL, which in practice means a GitHub
# workflow, since `.github/workflows/` is where GitHub looks - which is
# why `.github/workflows/parfast-gui.yml` keeps its removal line and this
# file gave its up.
#
# The cost is the convention: a reader looking for the parfast GUI
# bundler in packaging/ will not find it. That is what this paragraph and
# the plan's section 9.3 are for, and it is the cheaper of the two costs.
#
# Publishing the GUI later is now ONE edit rather than two: add
# `apps/parfast` to packaging/PUBLIC_MANIFEST. Nothing here needs
# touching.
#
# Prereqs:
#   macos-universal  rustup target add aarch64-apple-darwin x86_64-apple-darwin
#                    Xcode command line tools (swift build, lipo, hdiutil)
#   windows-x64      an ssh-reachable Windows box with VS Build Tools,
#                    the .NET 8 SDK, the Windows App SDK and Inno Setup
set -euo pipefail
# apps/parfast/packaging/ -> the repo root is THREE up, not one. It was
# one while this lived in packaging/; see the header for why it moved.
cd "$(dirname "$0")/../../.."
ROOT=$(pwd)
[ -f packaging/PUBLIC_MANIFEST ] || {
    echo "not at the repo root after cd - this script moved and its hop count is stale" >&2; exit 1; }

# The GUI's NUMBER tracks the CLI's, which tracks nzbfast's (plan decision
# D2, inheriting the publication spec's D3). One source, read the same way
# build-parfast-bundles.sh reads it.
CLI_VERSION=$(grep -m1 '^version' crates/parfast/Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
[ -n "$CLI_VERSION" ] || { echo "cannot read parfast version" >&2; exit 1; }

# ...BUT ITS STAGE DOES NOT, AND THAT IS THE POINT OF THESE FOUR LINES.
# The CLI is at 1.5.0-beta.1: it has shipped, been benchmarked against six
# other tools and published round after round. The desktop app was first
# compiled on 12 Sep 2026 and has never been driven by hand by anybody.
# Calling both of them "beta" because they share an engine tells a tester
# the wrong thing about the one they just downloaded, so the GUI carries
# its own stage - a maintainer decision, 12 Sep 2026.
#
# Only the PRE-RELEASE part diverges. The x.y.z stays the CLI's, so the
# two products still move together and a bug report still names a number
# that means something. Bump GUI_STAGE, not the number, as the app firms
# up; when it is genuinely beta this becomes beta.N and the filenames
# follow with no other edit.
GUI_STAGE=alpha.4
VERSION="${CLI_VERSION%%-*}-$GUI_STAGE"

# The stage in the filename, exactly once. $VERSION now always carries one,
# so this never appends a second - it stays because the day the GUI reaches
# a bare x.y.z with no stage at all, a bundle that says nothing is wrong.
case $VERSION in
    *beta*|*alpha*|*rc*) BETA_SUFFIX="" ;;
    *)                   BETA_SUFFIX="-beta" ;;
esac

MAC_APP_DIR=apps/parfast/mac
WIN_APP_DIR=apps/parfast/windows
# The same path as the remote spells it, for the PowerShell half.
WIN_APP_DIR_WIN=${WIN_APP_DIR//\//\\}
WIN_ISS_WIN=${WIN_ISS//\//\\}
# Moved under apps/parfast on 12 Sep 2026 (chip C, b641ffea23): with the
# script in packaging/ the pre-commit leak scan reported it as a public
# file shipping verbatim, which decision D2a forbids. This is a path this
# script DRIVES, not just names, so the stale spelling was a live defect
# and not a stale comment: `--check` would have reported the installer
# missing for ever and the ISCC call would have named a file that is not
# there.
WIN_ISS=apps/parfast/windows/packaging/parfast-gui.iss
# The detached cargo workspace holding parfast-session and parfast-ffi.
# Reached by manifest path and never by a `-p` line from the root.
FFI_MANIFEST=apps/parfast/Cargo.toml
MAC_MAKE_APP="$MAC_APP_DIR/make-app.sh"
APP_NAME="parfast.app"

CHECK_ONLY=0
SKIP_BUILD=0
REMOTE=${PARFAST_GUI_REMOTE:-}
ARGS=()
while [ $# -gt 0 ]; do
    case $1 in
        --check)       CHECK_ONLY=1 ;;
        --skip-build)  SKIP_BUILD=1 ;;
        --remote)      REMOTE=${2:-}; shift ;;
        --remote=*)    REMOTE=${1#--remote=} ;;
        -h|--help)     sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*)            echo "unknown option: $1" >&2; exit 1 ;;
        *)             ARGS+=("$1") ;;
    esac
    shift
done

DIST=${ARGS[0]:-dist-parfast-gui}
if [ ${#ARGS[@]} -gt 1 ]; then
    ARCHES="${ARGS[*]:1}"
elif [ "$(uname -s)" = Darwin ]; then
    ARCHES="macos-universal"
else
    ARCHES=""
fi

# ---------------------------------------------------------------------
# Preconditions, said in full rather than one at a time.
#
# NEITHER APP TREE EXISTS YET as this script lands: chips B and C of the
# plan build them, and this is the QA tail's chip, which runs first by
# design so the packaging is ready the day the apps are. So the failure
# mode this script must get right is not "the build broke", it is "the
# thing I package has not been written yet" - and a reader hitting that
# needs to be told which lane owns it rather than being handed a missing
# file error from three commands deep.
#
# `--check` reports the whole picture in one pass and builds nothing.
# Every build path calls the same function first, so the two can never
# disagree about what is needed.
# ---------------------------------------------------------------------
MISSING=0
report() {  # report <state> <what> <detail>
    case $1 in
        ok)      printf '  ✓ %-34s %s\n' "$2" "$3" ;;
        missing) printf '  ✗ %-34s %s\n' "$2" "$3"; MISSING=$((MISSING + 1)) ;;
        note)    printf '  · %-34s %s\n' "$2" "$3" ;;
    esac
}

check_mac() {
    echo "macos-universal:"
    [ -d "$MAC_APP_DIR" ] \
        && report ok "$MAC_APP_DIR" "the SwiftUI app tree" \
        || report missing "$MAC_APP_DIR" "not written yet - claim parfast-gui-mac (plan chip B)"
    [ -x "$MAC_MAKE_APP" ] \
        && report ok "$MAC_MAKE_APP" "builds and signs $APP_NAME" \
        || report missing "$MAC_MAKE_APP" "the app builder this script drives"
    [ -f "$FFI_MANIFEST" ] \
        && report ok "$FFI_MANIFEST" "the detached workspace (D2a)" \
        || report missing "$FFI_MANIFEST" "not written yet - claim parfast-gui-core (plan chip A)"
    command -v lipo >/dev/null 2>&1 \
        && report ok "lipo" "universal binary check" \
        || report missing "lipo" "Xcode command line tools"
    command -v hdiutil >/dev/null 2>&1 \
        && report ok "hdiutil" "DMG creation" \
        || report missing "hdiutil" "macOS only"
}

check_win() {
    echo "windows-x64:"
    [ -d "$WIN_APP_DIR" ] \
        && report ok "$WIN_APP_DIR" "the WinUI 3 app tree" \
        || report missing "$WIN_APP_DIR" "not written yet - claim parfast-gui-win (plan chip C)"
    [ -f "$WIN_ISS" ] \
        && report ok "$WIN_ISS" "the Inno Setup script" \
        || report missing "$WIN_ISS" "not written yet - claim parfast-gui-win (plan chip C)"
    [ -f "$FFI_MANIFEST" ] \
        && report ok "$FFI_MANIFEST" "the detached workspace (D2a)" \
        || report missing "$FFI_MANIFEST" "not written yet - claim parfast-gui-core (plan chip A)"
    if [ -n "$REMOTE" ]; then
        report ok "--remote $REMOTE" "the Windows build box"
    else
        report missing "--remote HOST" "no default on purpose - read the header"
    fi
}

# ---------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------
build_mac() {
    local work inner dmg zip stage
    if [ "$SKIP_BUILD" = 0 ]; then
        echo "== building $APP_NAME =="
        "$MAC_MAKE_APP"
    fi
    local app="$MAC_APP_DIR/build/$APP_NAME"
    [ -d "$app" ] || { echo "✗ no app at $app" >&2; exit 1; }

    # Assert the positive, exactly as build-parfast-bundles.sh does on
    # its CLI binary: a `lipo -create` that quietly produced a thin
    # binary is a mac asset that will not start on half the machines it
    # is for, and the failure is at the user's end, not here.
    local exe
    exe=$(ls "$app/Contents/MacOS/"* 2>/dev/null | head -1)
    [ -n "$exe" ] || { echo "✗ $app has no executable" >&2; exit 1; }
    lipo -info "$exe" | grep -q 'arm64 x86_64\|x86_64 arm64' || {
        echo "✗ not a universal binary: $(lipo -info "$exe")" >&2; exit 1; }

    # And assert that it STARTS. An ad-hoc signature that did not take
    # leaves a bundle that launches to an immediate kill with nothing on
    # screen, which looks identical to a bundle that works until somebody
    # double-clicks it.
    codesign --verify --deep --strict "$app" \
        || { echo "✗ $app fails signature verification" >&2; exit 1; }

    work=$(mktemp -d); inner="$work/parfast-gui-$VERSION-macos"
    mkdir -p "$inner"
    cp -R "$app" "$inner/$APP_NAME"
    cp LICENSE COPYRIGHT.md "$inner/"
    write_readme "$inner"
    zip="parfast-gui-$VERSION-macos-universal$BETA_SUFFIX.zip"
    ( cd "$work" && zip -q -r -X "$DIST/$zip" "$(basename "$inner")" )
    echo "  -> $DIST/$zip"

    # The DMG: app, an Applications symlink to drag it to, and the same
    # two licence files. Deliberately NOT the styled image
    # packaging/mac/make-dmg.sh builds for nzbfast - that one renders a
    # committed SVG background and writes a Finder layout with ds-store
    # and mac-alias, a pip install this script must not require of a
    # tester's Mac. The styled version is a v1 item for the day these
    # bundles go to a download page rather than to one person.
    stage=$(mktemp -d)/dmg; mkdir -p "$stage"
    cp -R "$app" "$stage/$APP_NAME"
    ln -s /Applications "$stage/Applications"
    cp LICENSE "$stage/LICENSE"
    write_readme "$stage"
    dmg="parfast-gui-$VERSION-macos-universal$BETA_SUFFIX.dmg"
    rm -f "$DIST/$dmg"
    hdiutil create -srcfolder "$stage" -volname "parfast $VERSION" \
        -fs HFS+ -format UDZO -imagekey zlib-level=9 -ov "$DIST/$dmg" >/dev/null
    echo "  -> $DIST/$dmg"
    rm -rf "$work" "$stage"
}

# ---------------------------------------------------------------------
# Windows, built over ssh on a box that has the toolchain.
#
# The shape is packaging/windows/make-installer.sh's, because that is
# the one that works here: the remote shell is not bash, `ssh host 'a; b'`
# does not do what it looks like, and the reliable form is one command
# per ssh invocation or a single powershell -Command. Nothing is killed
# by pattern on the remote box (CLAUDE.md invariant 2a reaches inside
# ssh), and nothing is deleted from its tree.
# ---------------------------------------------------------------------
# One PowerShell command on the remote, one ssh invocation. The remote
# shell on these boxes IS PowerShell (sshd's DefaultShell; see the machine
# roster), so the command below is handed straight to it. Nothing here
# kills anything by pattern: CLAUDE.md's invariant about pattern kills
# reaches inside ssh, and a hook refuses those spellings.
#
# IT WRAPPED EVERY COMMAND IN `powershell -NoProfile -Command "..."` UNTIL
# 12 SEP 2026, AND THAT IS A DOUBLE HOP THAT EATS ITS OWN ARGUMENT. The
# login shell is already PowerShell, so it parses the wrapper line first
# and expands anything `$`-shaped inside those double quotes BEFORE the
# inner powershell ever sees it. The first line of build_win asks the box
# for its own home directory, and what the inner process received was not
# a variable but its VALUE, as a bare command:
#
#   C:\Users\<you> : The term 'C:\Users\<you>' is not recognized as the name
#   of a cmdlet, function, script file, or operable program.
#
# So the Windows arm could not get past resolving the remote home, which
# is why this was found the first time anyone ran it (the mac arm has no
# equivalent hop and was fine). One hop, and `$env:USERPROFILE` is
# expanded exactly once, by the shell that owns it.
#
# AND THE BARE FORM ASSUMED THE DEFAULT SHELL IS POWERSHELL, WHICH IS NOT
# TRUE OF EVERY WINDOWS BUILD BOX (16 Sep 2026). `sshd`'s DefaultShell is
# PowerShell on the box this arm was written against and **cmd.exe on the
# second one it was pointed at**, so the plain text above reached cmd,
# which answered `The filename, directory name, or volume label syntax is
# incorrect.` at the very first hop and took the build down with it -
# correctly, via `set -e`, but with an error that says nothing about the
# cause. The cmd.exe box is not the odd one: cmd.exe is the OpenSSH
# default, and PowerShell is the thing somebody configured. So assume
# NEITHER; the machine roster in the maintainer notes says which is which.
#
# `-EncodedCommand` is the one spelling that serves both, and it is the
# same conclusion `.claude/tools/parfast-rigs.sh` reached for the same
# fleet - read its `windows_probe` header, which names this exact split.
# The payload is base64 of UTF-16LE, so it is opaque to whichever shell
# unwraps it: cmd has nothing to mangle, and PowerShell has no `$` to
# expand early, which is what the double-hop paragraph above is about. The
# single-expansion property that paragraph earned is therefore KEPT, not
# traded away - the argument is preserved, its assumption is not.
#
# Do not "simplify" this back to `powershell -NoProfile -Command "$1"`:
# that is the double hop, and it is the bug this comment's first half
# documents.
#
# `$ProgressPreference` is set in the payload rather than left alone
# because `-EncodedCommand` turns every progress record into a CLIXML
# blob on stderr - `Compress-Archive` alone emitted 160 KB of
# `<Obj S="progress">` into the build log on the first run of this form.
# It is prepended, so the caller's own last statement is still the last
# statement and an `rsh` used for its VALUE (the `$env:USERPROFILE` hop
# below) returns exactly what it did before. stdout is untouched either
# way; this only stops the log being unreadable.
rsh() {
    local b64
    b64=$(printf '%s' "\$ProgressPreference='SilentlyContinue'; $1" \
        | iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n')
    ssh "$REMOTE" "powershell -NoProfile -EncodedCommand $b64"
}

build_win() {
    [ -n "$REMOTE" ] || { echo "✗ windows-x64 needs --remote HOST" >&2; exit 1; }
    echo "== windows-x64 on $REMOTE =="

    # Resolve the remote's own paths ONCE, on the remote, into literals
    # this script then uses for both ssh and scp. Two reasons it is not
    # written down here instead: a literal user profile path is a fleet
    # detail in a file that is scanned for exactly that, and it is wrong
    # on any box whose account is not the one whoever typed it was using.
    # It has to be a literal by the time scp sees it - scp's remote half
    # is expanded by the remote SHELL, which on these boxes is PowerShell
    # and not the shell whose quoting rules the rest of this line reads
    # like.
    local home iscc rroot
    home=$(rsh "\$env:USERPROFILE" | tr -d '\r')
    [ -n "$home" ] || { echo "✗ could not resolve the remote home" >&2; exit 1; }
    rroot="$home\\parfast-gui"

    if [ "$SKIP_BUILD" = 0 ]; then
        # Ship the sources the remote needs. A tar over ssh rather than a
        # clone: the Windows boxes hold no repo credentials, which is why
        # every other remote build here works the same way. Nothing on
        # the remote is DELETED first - another lane's warm target
        # directory has been moved out from under a running test suite on
        # one of these boxes before, and the machine roster's first rule
        # is the consequence.
        echo "  syncing sources"
        # `apps/parfast` carries the app tree, the detached workspace AND
        # the installer script since the 12 Sep move; `crates` is the
        # engine the workspace reaches by relative path.
        #
        # AND `vendor`, WITHOUT WHICH THE CDYLIB STEP BELOW CANNOT RUN. It
        # was missing until 12 Sep 2026, when this script's Windows arm was
        # first exercised end to end: parfast-ffi reaches parfast-session ->
        # nzbkit -> `rars`, which is a PATH dependency on vendor/rars, so
        # cargo refused before compiling anything with
        #
        #   error: failed to load source for dependency `rars`
        #   ... unable to update <root>\vendor\rars
        #
        # It is 12 MB and five forks (rars, tiny_http, lzma-rust2,
        # rapidyenc, sevenz-rust2); taking the directory wholesale rather
        # than naming rars keeps it correct when the next first-party crate
        # picks up a second fork.
        # A STAGED TARBALL AND AN scp, NOT A PIPE INTO THE REMOTE TAR.
        # The obvious `git archive ... | rsh "tar -x"` is what this did
        # until 12 Sep 2026 and it completes SILENTLY WITH EXIT 0 having
        # written nothing: ssh's stdin reaches the remote PowerShell, not
        # the `tar` inside the command it runs, so the archive goes
        # nowhere and the next step fails somewhere else entirely. Found
        # the first time this arm was run.
        local tarball
        tarball=$(mktemp -t parfast-gui-src)
        # LICENSE is on this list because the INSTALLER needs it: the .iss
        # declares LicenseFile={#StageDir}\LICENSE and build.ps1 stages it
        # from the repo root. Without it ISCC aborts on line 86 with "Could
        # not read ...\stage-gui\LICENSE", several steps after the actual
        # omission.
        git archive --format=tar -o "$tarball" HEAD -- apps/parfast crates vendor \
            Cargo.toml Cargo.lock rust-toolchain.toml LICENSE
        rsh "New-Item -ItemType Directory -Force -Path '$rroot' | Out-Null"
        scp -q "$tarball" "$REMOTE:$rroot\\src.tar"
        rm -f "$tarball"
        rsh "Set-Location '$rroot'; tar -xf src.tar; Remove-Item src.tar"
        echo "  building the cdylib"
        # REMAP THE BUILD PATHS, computed ON THE BOX. The repo's
        # .cargo/config.toml remaps the maintainer's macOS home, a macOS path:
        # a cross-compile from the Mac is covered by it and this NATIVE
        # Windows build is not, so without this the cdylib ships the
        # build machine's directory layout. Measured on the 1.5.0-alpha.1
        # bundle: 256 occurrences in parfast_ffi.dll, both the source
        # tree and the whole .cargo\registry path of the aws-lc-sys C
        # sources.
        #
        # `RUSTFLAGS` REPLACES a matching `[target.*]` section rather than
        # adding to it - the trap that shipped host paths in the first
        # v1.0.0 exe - so it is only safe here because there is NO
        # `[target.x86_64-pc-windows-msvc]` section in .cargo/config.toml
        # to lose. Checked at the time of writing; if one is ever added,
        # this has to move into it instead.
        #
        # Two prefixes because there are two roots: the sync root this
        # script made, and the user profile that holds the cargo
        # registry. Both are computed on the remote rather than written
        # here, which keeps every fleet hostname and account name out of
        # a file that ships publicly.
        # AND THE C COMPILER'S OWN PATHS, which are a SECOND source and
        # not covered by the line above. `--remap-path-prefix` is a
        # RUSTC flag; `aws-lc-sys` compiles a few hundred .c files
        # through cc-rs, and those carry their own paths (aws-lc records
        # __FILE__ in its error stack, so this is not debug info that
        # stripping would remove). 63 survived the rustc remap on the
        # first attempt, every one a `\.cargo\registry\...aws-lc-sys`
        # path under the build account.
        #
        # `/d1trimfile:` is cl.exe's path-trimming flag. Set through
        # `CFLAGS_<target>`, which is the spelling cc-rs reads for a
        # specific target, so nothing else on the box is affected.
        rsh "\$env:RUSTFLAGS = '--remap-path-prefix=' + \$env:USERPROFILE + '=/build --remap-path-prefix=$rroot=/build'; \$env:CFLAGS_x86_64_pc_windows_msvc = '/d1trimfile:' + \$env:USERPROFILE + '\\'; Set-Location '$rroot'; cargo build --manifest-path apps\\parfast\\Cargo.toml --release --locked -p parfast-ffi"
        echo "  building the app"
        # THROUGH THE APP'S OWN build.ps1, not a `dotnet publish` spelled
        # again here. That script is the one that gets run by hand on the
        # box and it carries the four things a bare publish does not: the
        # self-contained + WindowsAppSDKSelfContained + WindowsPackageType
        # trio that makes the output run on a clean machine, the check
        # that the generated sources are current, the test run, and the
        # Unblock-File pass (a MOTW-stamped exe hangs headless).
        #
        # The version it stamps is THIS script's, which is the whole point
        # of reading it from crates/parfast/Cargo.toml once at the top.
        #
        # It also fixes what this line used to be, which never produced a
        # publishable tree: run from the app directory with no project
        # argument, `dotnet publish` takes the SOLUTION, and MSBuild warns
        # NETSDK1194 that `--output` is not supported for one - then
        # publishes all six projects on top of each other in one
        # directory.
        #
        # `powershell -ExecutionPolicy Bypass -File` rather than `& script`:
        # the boxes run the default execution policy, so dot-invoking a .ps1
        # that arrived over scp fails with UnauthorizedAccess ("running
        # scripts is disabled on this system"). -File with Bypass is the
        # form the rest of the fleet's remote scripts use, and it is scoped
        # to this one child process rather than changing a machine setting.
        rsh "\$env:PATH = 'C:\\Program Files\\dotnet;' + \$env:PATH; powershell -NoProfile -ExecutionPolicy Bypass -File '$rroot\\$WIN_APP_DIR_WIN\\tools\\build.ps1' -Publish -Installer -Version '$VERSION'"
    fi

    echo "  packaging"
    # build.ps1 publishes into apps/parfast/windows/out/publish and, with
    # -Installer, compiles the Inno script into
    # apps/parfast/windows/packaging/out. Both are under the app tree, not
    # the sync root, which is what the paths below say.
    local winout="$rroot\\$WIN_APP_DIR_WIN\\out\\publish"
    local zip="parfast-gui-$VERSION-windows-x64$BETA_SUFFIX.zip"
    rsh "Compress-Archive -Force -Path '$winout\\*' -DestinationPath '$rroot\\$zip'"
    # FORWARD SLASHES FOR scp's REMOTE HALF, backslashes everywhere else.
    # scp runs its remote end through the box's default shell, which here is
    # PowerShell, and PowerShell hands the path on with every backslash
    # DOUBLED - the failure reads as the file not existing, and names a path
    # with `\\` in it that nobody wrote:
    #
    #   scp: C:\\Users\\<you>\\parfast-gui\\parfast-gui-1.5.0-beta.1-windows-x64.zip:
    #        No such file or directory
    #
    # Windows takes forward slashes in a path perfectly well, and they
    # survive the hop unaltered. The PowerShell commands above keep
    # backslashes, because those are consumed by PowerShell itself.
    scp -q "$REMOTE:$(printf '%s' "$rroot/$zip" | tr '\\' '/')" "$DIST/$zip"
    echo "  -> $DIST/$zip"

    # The installer is compiled by build.ps1 -Installer above rather than by
    # a second ISCC invocation here: that script already resolves ISCC out
    # of the remote's LOCALAPPDATA (it is a PER-USER install on these boxes,
    # so every Program Files probe finds nothing and reads like a missing
    # toolchain), stages the payload and copies the licence in beside it.
    # The name is the .iss's OutputBaseFilename, which is why that line and
    # the zip line above have to agree about the `parfast-gui-` prefix.
    local setup="parfast-gui-$VERSION-windows-x64-setup.exe"
    scp -q "$REMOTE:$(printf '%s' "$rroot/$WIN_APP_DIR/packaging/out/$setup" | tr '\\' '/')" "$DIST/$setup"
    echo "  -> $DIST/$setup"
}

# ---------------------------------------------------------------------
# The note that ships beside the app. Short on purpose: the manual is
# apps/parfast/docs/PARFAST-GUI.md and the app has a help menu; this
# answers only "what is this and why is it unsigned".
# ---------------------------------------------------------------------
write_readme() {
    cat > "$1/README.txt" <<README
parfast $VERSION - make, check and repair PAR2 recovery sets

parfast protects a set of files with PAR2 recovery data, checks a set
you already have, and repairs one that has lost or damaged files. It is
the desktop app over the same engine as the parfast command line tool.

THIS IS A PRIVATE ALPHA. The app is early: it has been built, tested
against a measured acceptance corpus and screenshotted, but it has not
been lived with. Expect rough edges, and please say how you got on -
hearing that it worked is as useful as hearing that it did not.

The ENGINE underneath is the same one the parfast command line tool
ships, which is further along; it is the app around it that is new.

Repairing rewrites files in place, which is what repairing is. Keep a
copy of anything you cannot lose, the same as with any other such tool.

This build is not signed yet, so the first launch needs a little help:
on macOS, right click the app and choose Open, then Open again. On
Windows, choose More info and then Run anyway.

Licence: GPL-3.0-or-later. See LICENSE beside this file.
README
}

# ---------------------------------------------------------------------

if [ "$CHECK_ONLY" = 1 ]; then
    echo "parfast GUI bundles $VERSION$BETA_SUFFIX"
    echo
    check_mac
    echo
    check_win
    echo
    if [ "$MISSING" = 0 ]; then
        echo "ready to build"
    else
        echo "$MISSING precondition(s) not met - nothing was built."
        echo "A missing app tree or workspace is the expected state until the"
        echo "plan chip that owns it lands, and is not a defect in this script."
        echo "A missing --remote never resolves on its own: it is an argument,"
        echo "and the header says why it has no default."
    fi
    exit 0
fi

[ -n "$ARCHES" ] || { echo "nothing to build on $(uname -s); name an arch" >&2; exit 1; }
mkdir -p "$DIST"; DIST=$(cd "$DIST" && pwd)

for arch in $ARCHES; do
    MISSING=0
    case $arch in
        macos-universal) check_mac ;;
        windows-x64)     check_win ;;
        *) echo "unknown arch: $arch" >&2; exit 1 ;;
    esac
    [ "$MISSING" = 0 ] || {
        echo "✗ $arch: $MISSING precondition(s) not met - see --check" >&2
        exit 1; }
    case $arch in
        macos-universal) build_mac ;;
        windows-x64)     build_win ;;
    esac
done

echo
echo "== parfast GUI $VERSION =="
ls -lh "$DIST"
