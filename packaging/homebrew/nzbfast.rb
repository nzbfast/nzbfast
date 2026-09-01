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
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.3.0/nzbfast-1.3.0-macos-universal.zip"
      sha256 "94e00f44ed45eee331153bf638b59590ff51f0cfeab34662bf8f960463ed6e77"
    end
    on_intel do
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.3.0/nzbfast-1.3.0-macos-universal.zip"
      sha256 "94e00f44ed45eee331153bf638b59590ff51f0cfeab34662bf8f960463ed6e77"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.3.0/nzbfast-1.3.0-linux-x64.tar.gz#/nzbfast-linux-x64-1.3.0.tar.gz"
      sha256 "c7a1688216d0c9c3458420a99ee5a58f9b0d511db7c533db139bd0b817c13fe7"
    end
    on_arm do
      url "https://github.com/nzbfast/nzbfast/releases/download/v1.3.0/nzbfast-1.3.0-linux-arm64.tar.gz#/nzbfast-linux-arm64-1.3.0.tar.gz"
      sha256 "90badaef74327f74c88ba764e7fab92a3e3327fdd69b0896a357413e8e3f3b2e"
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
