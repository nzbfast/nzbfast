# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, so a fix can ship
before details are public:

- **Preferred:** GitHub private vulnerability reporting - the
  ["Report a vulnerability"](https://github.com/nzbfast/nzbfast/security/advisories/new)
  button on this repository's Security tab.
- **Email:** nzbfast@pm.me

You can expect an acknowledgement within 48 hours. Please include steps
to reproduce and the version (`nzbfast --version` or the dashboard
footer). Credit is given in the release notes unless you prefer
otherwise.

## Update security

- nzbfast is **notify-only** since v1.0.5: it never downloads or
  replaces its own binary. There is no self-update code in the source.
- A newer release only raises a dashboard notice; its download link is
  hard-coded to the official download page and never comes from the
  update manifest.
- The version check itself can be turned off (Settings > "Check for
  updates", or an empty update check URL) - then nzbfast makes no
  update-related requests at all.

## Verifying downloads

Release binaries carry SHA-256 checksums (`SHA256SUMS.txt` on every
release) and, from v1.0.5 onward, GitHub build-provenance attestations
for the CI-built binaries - see "Verifying a download" in the README.

## Supported versions

The latest release receives security fixes. There is no LTS branch;
upgrading is always the fix path.
