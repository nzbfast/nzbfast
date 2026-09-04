# winget manifests

`manifests/<version>/` holds the three winget manifest files
(version, installer, defaultLocale) for `winget install nzbfast`.
They are GENERATED - run `packaging/make-pkg-manifests.sh <version>`
after a release is published; it reads the release's SHA256SUMS.txt so
the hashes are what GitHub actually serves.

The package identifier is `nzbfast.nzbfast`. The installer entry points
at the Inno Setup exe (`nzbfast-<version>-windows-x64-setup.exe`); the
portable zip is Scoop's job, not winget's.

## Submitting a version to microsoft/winget-pkgs

Community packages live in the shared repo, one PR per version, files at
`manifests/n/nzbfast/nzbfast/<version>/`. Their CI validates the schema
and installs the package in a sandbox; a human moderator approves new
packages. All operations run as the release account:

```sh
export GH_CONFIG_DIR=~/.config/gh-nzbfast   # gh api user -> nzbfast
gh repo fork microsoft/winget-pkgs --clone=false   # once
git clone --depth 1 https://github.com/nzbfast/winget-pkgs /tmp/winget-pkgs
cd /tmp/winget-pkgs
git checkout -b nzbfast-<version>
mkdir -p manifests/n/nzbfast/nzbfast/<version>
cp <repo>/packaging/winget/manifests/<version>/*.yaml manifests/n/nzbfast/nzbfast/<version>/
git -c user.name=nzbfast -c user.email=307209046+nzbfast@users.noreply.github.com add manifests/n/nzbfast/nzbfast/<version>
git -c user.name=nzbfast -c user.email=307209046+nzbfast@users.noreply.github.com commit -m "New version: nzbfast.nzbfast version <version>"
git push origin nzbfast-<version>
gh pr create --repo microsoft/winget-pkgs --title "New version: nzbfast.nzbfast version <version>" --body "..."
```

After the first version is merged, `komac update nzbfast.nzbfast
--version <version> --urls <installer-url> --submit` (with a token from
the release account) automates the whole PR; komac is cross-platform.

Notes:

- **The commit author email is the `nzbfast` account's GitHub noreply
  address, and that is load-bearing rather than cosmetic.** It was
  `releases@nzbfast.com` until 1 Sep 2026, and nzbfast.com is
  deliberately unwired (TODO 736) - so that address is attached to no
  GitHub account, `author.login` reads NULL on every commit, and the
  policy bot cannot match the PR to the signed CLA. Measured: `Needs-CLA`
  was re-applied to EVERY new PR and a human had to re-assert the
  agreement by comment each time (#417149, #423063, #423649). The noreply
  form always resolves to the account, needs no mailbox and no
  verification step, and publishes no real inbox into a Microsoft repo's
  permanent history. Do NOT "tidy" it back to a domain address, and do
  not put a real inbox here instead. Untested until the next PR - the
  first submission after 1 Sep 2026 is what proves it.
- The manifests cannot be validated end-to-end from this Mac
  (`winget validate` and the install test need Windows); the repo's CI
  is the real gate, so watch the PR checks rather than assuming.
- ManifestVersion tracks winget-pkgs' current schema (1.12.0 as of
  Aug 2026); bump it when their validation asks for it.
- The installer is not yet code-signed, so the sandbox install relies on
  Defender not flagging the exe that day. If validation fails on a
  reputation hit, that is the known signing gap, not a manifest bug.
