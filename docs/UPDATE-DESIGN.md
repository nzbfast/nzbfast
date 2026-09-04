# How nzbfast handles updates

This document describes the update mechanism as it exists today, and the
design for the optional self-update we intend to restore. It is published
before that feature ships, on purpose: if the design does not survive
public reading, the feature should not survive either. Criticism of the
original 1.0.x auto-updater was correct, and this is the replacement
trust model, written down so it can be checked rather than taken on
faith.

## Today: notify-only

Since 1.0.5 the app does not modify itself. The daemon periodically
fetches a static manifest (`latest.json`) from GitHub Releases, verifies
it (see below), and at most shows a banner with the new version and a
link. Installing is a human action with the platform's normal download
flow. Bundled installs (the macOS app wrapper, the Windows installer)
additionally never self-swap, and their banner links to the download
page.

What leaves your machine for an update check: one HTTPS GET for
`latest.json` and one for `latest.json.sig`. No identifiers, no version
report, no telemetry. Turning the check off entirely is a setting.

## The verification chain

1. **The manifest is signed.** `latest.json.sig` is a detached ed25519
   signature over the exact manifest bytes. The public key is compiled
   into the binary:

   ```
   ed25519 863349474b98569e9a00d06ad3a7385f564b76aed97a7ff60fca713b9c4731ba
   ```

   Verification happens before parsing; a missing or wrong signature is
   a hard refusal. Controlling the download origin (the GitHub account,
   a mirror, or a network position) is not enough to feed the app a
   manifest; the offline private key would also be needed.

2. **The payload hash comes only from the signed manifest.** Each
   platform entry carries the sha256 of its artifact. Nothing the
   download server says can influence acceptance; transport security is
   not the trust anchor, the signature is.

3. **Anti-rollback serial, enforced.** The signed body carries a
   monotonic `serial`. Clients persist the highest serial they have ever
   seen and refuse any manifest that fails to beat it, so a replayed
   old-but-validly-signed manifest is recognised as stale and no update
   is offered from it. The serial is compared only against the client's
   own stored value, never against the clock, so a machine with a wrong
   clock cannot lock itself out. The exact rules:

   - A **higher** serial is accepted and becomes the new floor.
   - The **same** serial is accepted and writes nothing. This is the
     ordinary six-hourly re-check.
   - A **lower** serial is refused.
   - A **missing or unparseable** serial is refused once this install has
     already seen a real one, and accepted before that. A channel that
     has shown it emits serials cannot then drop one, because a manifest
     without a serial is indistinguishable from a replay of one that
     predates them, and accepting it would make stripping the field the
     way around the whole mechanism. An install that has never seen a
     serial has no floor to duck under and nothing to refuse, which is
     what keeps a serial-less private mirror working.

   A refused manifest never lowers the stored floor, whatever it
   contains, and never takes down a banner an earlier accepted manifest
   raised. Feeding an install junk can therefore stop it learning
   something new; it cannot make it forget something true.

   Shipped read-only from 28 Jul 2026 and enforcing from 2 Sep 2026. The
   gap was deliberate: enforcement had to arrive after a release cycle of
   evidence that serials really do turn up. That evidence is public and
   checkable - `serial` is present in every manifest from v1.0.11 to
   v1.3.1 and strictly increases across all 26 of them.

   **Resetting the floor.** The ratchet is one-way and local, with no
   server-side reset, so a wrong serial published once would wedge the
   channel on every install that recorded it and no later release could
   unwedge it. The way out is deliberately a local one: stop nzbfast,
   delete the `"update_serial_seen"` line from `settings.json` in the
   config folder, and start it again. Every refusal message prints that
   file's real path. This is the reset you need if you point `update_url`
   at your own channel whose serials do not line up with ours.

   It is not exposed as a setting, and that is the safety argument for
   enforcing at all. The API is reachable over the LAN, so a settable
   reset would let the network lower an install's rollback floor, which
   is the attack the ratchet exists to stop. Needing a shell on the
   machine and a stopped daemon is the property that makes the escape
   hatch safe.

4. **Version comparison.** A manifest advertising a version at or below
   the running one is not an update, whatever it is signed with.

## The payload format

Each `payloads` entry names one artifact: its URL, the sha256 of the
exact bytes at that URL, and its compression. The field is `payloads`,
deliberately NOT the pre-TODO 107 `platforms`: the retired pre-1.0.5
self-updater read `platforms[<key>]`, hashed the fetched bytes, and
wrote them over the executable - a gzip entry under the old name would
sha-verify and be installed as the binary. Under the new name any such
ghost install finds nothing, stages nothing, and keeps its working
notify banner. `version`/`serial`/`notes` stay top-level, which is all
any 1.0.5+ client reads.

```json
"macos-arm64": {
  "url": ".../nzbfast-updater-1.0.17-macos-arm64.gz",
  "sha256": "<sha256 of the .gz bytes>",
  "compression": "gzip"
}
```

Rules a client must follow, fixed now so the first self-update client is
written against them:

- **Verify, then decompress - never the reverse.** The sha256 covers the
  compressed bytes as fetched, so the hash check completes before any
  byte reaches a decompressor. Nothing unauthenticated is ever parsed.
- **Pick the exact platform key first** (`macos-arm64`, `macos-x64`,
  `linux-x64`, ...), falling back to `macos-universal` only when the
  running arch has no entry. The per-arch payloads exist because an
  update fetch was measured at 51.4 MB universal-raw against 10.6 MB
  thin-gzipped - a 79% cut; the universal entry stays as the fallback.
- **An unknown `compression` value is a refusal**, not a passthrough. A
  client that predates a future format must fail closed and leave the
  notify banner, never write bytes it cannot interpret. An ABSENT
  `compression` field means raw passthrough with the sha256 over the
  raw bytes - and a manifest with no `payloads` field at all (a stale
  or mirrored pre-TODO 107 copy) is a notify-only manifest, not an
  error.

The human downloads are unaffected: the DMG stays universal on purpose.
A person can pick the wrong arch and get a confusing failure; a manifest
lookup cannot, so only the machine path is arch-split.

Known limitation, stated plainly: none of this catches a freeze, where
an attacker serves the newest valid manifest forever so the client never
learns of a later release. Catching that requires manifest expiry, which
we have deferred because a missed re-sign would strand every install in
warning state. It is on the list, gated on release cadence.

## Build provenance

Signing proves a release is ours; it does not prove the binary matches
the public source. For that, release tarballs are built by a public
GitHub Actions workflow from the tagged commit and carry SLSA build
provenance attestations. Anyone can check that an artifact was built by
that workflow from that tag:

```sh
gh attestation verify nzbfast-<target>.tar.gz --repo nzbfast/nzbfast
```

The attestation names the repository, the workflow file, and the commit
digest of the tag. The same attestation is attached to the release as
`nzbfast-<target>.tar.gz.intoto.jsonl`, so it can be verified from the
downloaded files alone (`--bundle <that file>`) and archived alongside
them.

Scope, stated plainly: this covers the `nzbfast-<target>.tar.gz`
binaries. The convenience packages - the macOS disk image and the
Windows installer, which is what most people download - are built and
signed through separate channels and carry no build-provenance
attestation.

Work to make builds bit-for-bit repeatable is in progress and documented
separately; we do not claim it until a released tag has been
independently rebuilt to the same digest.

## Verifying a download by hand

No part of this requires trusting the app:

```sh
# 1. Artifact matches the published checksums
shasum -a 256 -c SHA256SUMS --ignore-missing

# 2. Manifest signature (python3 + the `cryptography` package)
python3 - <<'EOF'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
pub = bytes.fromhex("863349474b98569e9a00d06ad3a7385f564b76aed97a7ff60fca713b9c4731ba")
sig = bytes.fromhex(open("latest.json.sig").read().strip())
Ed25519PublicKey.from_public_bytes(pub).verify(sig, open("latest.json","rb").read())
print("manifest signature OK")
EOF

# 3. Build provenance
gh attestation verify nzbfast-<target>.tar.gz --repo nzbfast/nzbfast
```

## The planned opt-in self-update

The staged apply path will return under these rules, all of which are
design commitments, not defaults to be revisited quietly:

- **Off by default, forever.** Opt-in per install, in Settings, with the
  full chain above enforced (including the serial ratchet). No release
  will ever switch it on for someone who did not, and a saved setting
  from the pre-1.0.5 updater is deliberately ignored.
- **Nothing silent.** Updates are staged on check and applied only on an
  explicit action or in a window the user chose; never mid-download,
  never mid-repair. The version, changelog link and artifact hash are
  shown before applying. A restart is a user-visible event.
- **Managed installs refuse.** Docker, Homebrew, winget, Unraid and the
  bundled macOS/Windows installers own their binaries; self-update stays
  off there regardless of the setting, and the UI says why.
- **Atomic and reversible.** Full verification completes before anything
  is written into place; the swap is an atomic rename on the same
  filesystem; the previous binary is kept for one-command rollback; low
  disk refuses rather than degrades.
- **Windows waits for code signing.** An unsigned executable replacing
  itself is indistinguishable from malware heuristics, so the Windows
  leg ships only signed.

## Key management

The signing key was generated offline and stays offline. Rotation
policy: a release carrying the new public key ships before anything is
signed with the new private key, because existing installs trust only
the key they have. The key fingerprint above is also the one place a
rotation will be announced.

Questions, holes, or attacks we have not thought of: open an issue. This
mechanism only earns trust if poking at it is welcome.
