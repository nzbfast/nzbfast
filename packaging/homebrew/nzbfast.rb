# Homebrew formula for nzbfast (brew install nzbfast/tap/nzbfast).
#
# THIS FILE IS THE SOURCE OF TRUTH. packaging/homebrew/bump-tap.sh rewrites
# the download URLs and the sha256 lines at release time and pushes a copy to
# the public tap repo (nzbfast/homebrew-tap). Edit here, never in the tap.
# It rewrites only lines carrying a release-download URL and the sha256 line
# under each, so do not put a version number anywhere else in this file: it
# would not be updated and would rot.
#
# It points at the same archives a person downloads by hand from the release
# page, on purpose. The per-target-triple tarballs on the same release come
# from a manually dispatched CI workflow, so they are not guaranteed to exist
# for every tag, and their Linux builds link glibc 2.39, which will not start
# on Debian 12 or Ubuntu 22.04. The release archives below are static musl on
# Linux and a universal binary on macOS, so they run everywhere.
class Nzbfast < Formula
  desc "Fast Usenet (NZB) downloader with one-pass verify, repair and extract"
  homepage "https://github.com/nzbfast/nzbfast"
  license "GPL-3.0-or-later"

  livecheck do
    url :stable
    strategy :github_latest
  end

  # There is deliberately no `version` stanza. Homebrew derives the version
  # from the URL, and every URL here is written so that it derives the right
  # one. Declaring it as well is what `brew audit` calls redundant, and that
  # fails the audit on macOS.
  #
  # The `#/...` suffixes on the Linux URLs are load-bearing, not decoration.
  # Homebrew parses a `...-linux-x64.tar.gz` filename as version **64**, off
  # the `-x64`, and would install to Cellar/nzbfast/64. The fragment renames
  # the download locally (curl never sends it) and is what the version parser
  # reads, so it puts the version last where nothing can be mistaken for it.
  # macOS needs no fragment: `-macos-universal.zip` parses correctly already.
  #
  # macOS ships one universal binary rather than a per-architecture build, so
  # both arches point at the same archive. It has to be spelled out per arch
  # because `on_macos` itself may not contain a `url`.
  on_macos do
    on_arm do
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.2.2/nzbfast-1.2.2-macos-universal.zip"
      sha256 "8f74f84fce08e51c0a97c3caf7a68353b5cb0a8cb6f412ad0d345f18079491a4"
    end
    on_intel do
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.2.2/nzbfast-1.2.2-macos-universal.zip"
      sha256 "8f74f84fce08e51c0a97c3caf7a68353b5cb0a8cb6f412ad0d345f18079491a4"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.2.2/nzbfast-1.2.2-linux-x64.tar.gz#/nzbfast-linux-x64-1.2.2.tar.gz"
      sha256 "3b555a03bee699076c7f91aa1af244af41b0c198be4498cd1e2f499caf21bd7d"
    end
    on_arm do
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.2.2/nzbfast-1.2.2-linux-arm64.tar.gz#/nzbfast-linux-arm64-1.2.2.tar.gz"
      sha256 "9d683d95118bf4d9832ad0296a4d3aec467de41d0036ba7ca4667478a4529365"
    end
  end

  # No runtime dependencies on purpose: PAR2 repair and RAR extraction are
  # native to the binary. A par2 or unrar already on PATH is still honoured
  # as a fallback, but nothing here requires one.

  def install
    bin.install "nzbfast"
    doc.install "MANUAL.html"
  end

  # Nothing creates directories here because nothing needs to: the daemon
  # creates its config directory and its download directory on demand, and
  # `brew services` creates working_dir and the log parent before it starts
  # anything. A watch folder that does not exist yet is polled without error
  # and picked up as soon as it appears.
  #
  # etc/nzbfast and var/nzbfast mirror the /etc/nzbfast + /var/lib/nzbfast
  # split of packaging/systemd/nzbfast.service. The daemon keeps its API key,
  # settings and job spool beside the config file, and its index database in
  # the working directory.
  service do
    run [opt_bin/"nzbfast", "serve",
         "--config", etc/"nzbfast/config.json",
         "--out", var/"nzbfast/downloads",
         "--watch", var/"nzbfast/watch"]
    keep_alive true
    working_dir var/"nzbfast"
    log_path var/"log/nzbfast.log"
    error_log_path var/"log/nzbfast.log"
  end

  def caveats
    <<~EOS
      There is no config file to edit. Start the daemon, then add your
      Usenet server through the web UI:

        brew services start nzbfast
        open http://localhost:6789

      Settings, API key and job state live in #{etc}/nzbfast; downloads and
      the watch folder in #{var}/nzbfast. Both survive upgrade and uninstall.

      Prefer the terminal? "nzbfast setup" does the same thing.
      Sonarr and Radarr connect to http://localhost:6789/api as a SABnzbd or
      NZBGet download client; the API key is on the Settings page.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/nzbfast --version")

    # Parse a hand-written NZB end to end. Exercises the real XML parser and
    # the segment accounting offline, with no network and no config.
    (testpath/"demo.nzb").write <<~XML
      <?xml version="1.0" encoding="iso-8859-1" ?>
      <nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
      <file poster="p@example.com" date="1700000000" subject="&quot;demo.rar&quot; yEnc (1/1)">
      <groups><group>alt.binaries.test</group></groups>
      <segments><segment bytes="100" number="1">abc@example</segment></segments>
      </file>
      </nzb>
    XML

    assert_match "demo.rar", shell_output("#{bin}/nzbfast inspect #{testpath}/demo.nzb")
  end
end
