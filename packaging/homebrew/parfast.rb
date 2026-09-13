# Homebrew formula for parfast (brew install nzbfast/tap/parfast).
#
# THIS FILE IS THE SOURCE OF TRUTH, the same way nzbfast.rb is. Edit here,
# never in the public tap.
#
# NOT YET WIRED INTO bump-tap.sh. That script hardcodes
# FORMULA="$ROOT/packaging/homebrew/nzbfast.rb", so the URLs and sha256 lines
# below are NOT rewritten at release time yet and are placeholders until the
# first parfast release exists to point at. Filling them by hand and pushing
# is a footgun; generalising bump-tap.sh to take a formula argument is the
# real fix and is tracked in research/SPEC-PARFAST-PUBLICATION-2026-09-10.md.
#
# TWO THINGS DIFFER FROM nzbfast.rb, both deliberate:
#
#   - There IS a `version` stanza here. nzbfast.rb omits it because brew
#     derives the version correctly from its URLs and declaring it as well
#     fails `brew audit` as redundant. parfast ships a PRE-RELEASE version
#     ("1.5.0-beta.1"), which the URL parser does not recover intact, so
#     here it is not redundant, it is the only correct source.
#   - Every URL carries a `#/...` fragment, not just the Linux ones. The
#     fragment renames the download locally (curl never sends it) and is
#     what the version parser reads. nzbfast.rb needs it only on Linux,
#     where `-linux-x64.tar.gz` parses as version **64**; parfast needs it
#     everywhere because its version contains a hyphen too.
class Parfast < Formula
  desc "PAR2 create, verify and repair with par2cmdline's command shape"
  homepage "https://github.com/nzbfast/nzbfast"
  license "GPL-3.0-or-later"
  version "1.5.0-beta.1"

  livecheck do
    url :stable
    strategy :github_latest
  end

  on_macos do
    on_arm do
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.5.0/parfast-1.5.0-beta.1-macos-universal.tar.gz#/parfast-macos-universal-1.5.0-beta.1.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.5.0/parfast-1.5.0-beta.1-macos-universal.tar.gz#/parfast-macos-universal-1.5.0-beta.1.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.5.0/parfast-1.5.0-beta.1-linux-x64.tar.gz#/parfast-linux-x64-1.5.0-beta.1.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_arm do
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.5.0/parfast-1.5.0-beta.1-linux-arm64.tar.gz#/parfast-linux-arm64-1.5.0-beta.1.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  # No dependencies, and none are coming: the PAR2 engine is native to the
  # binary. Notably it does NOT depend on par2cmdline, which it replaces.

  def install
    bin.install "parfast"
    doc.install "README.txt"
  end

  def caveats
    <<~EOS
      parfast is a BETA. It takes par2cmdline's arguments and exit codes, so
      a script that calls par2 can call parfast instead:

        parfast c set.par2 file1 file2    create
        parfast v set.par2                verify
        parfast r set.par2                repair

      Repairing rewrites files in place. Keep a copy of anything you cannot
      lose. Please report what you find, working or not:
      https://github.com/nzbfast/nzbfast/issues
    EOS
  end

  test do
    assert_match "parfast", shell_output("#{bin}/parfast --version")

    # Create a set, then verify it. Exercises the encoder and the verifier
    # end to end, offline, with no fixture to ship.
    (testpath/"a.bin").write("nzbfast parfast formula test payload" * 400)
    system bin/"parfast", "c", "-q", "t.par2", "a.bin"
    assert_predicate testpath/"t.par2", :exist?
    # par2cmdline's exit code 0 is "all files are correct".
    system bin/"parfast", "v", "-q", "t.par2"
  end
end
