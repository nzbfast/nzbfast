//! Password resolution for the on-disk extraction ladder: harvesting
//! candidates from a level's own outputs, and the per-container probes
//! (RAR check value, 7z open+decode, zip entry verifier) that decide
//! which of them an extraction is worth spending on.
//!
//! A child module file rather than an inline block: unpack.rs is at the
//! TODO 106 size-gate ceiling and the numbers only go down. Same pattern
//! as `pwfile_tests`, whose cases cover this file.

use super::*;
use tracing::{info, warn};

/// Ceiling on password candidates tested per level. Each candidate costs
/// one PBKDF2-HMAC-SHA256 derivation (2^lg2 rounds - intentionally slow),
/// so the cap bounds the KDF work a crafted post can force: fifty
/// candidates at the common 2^15 count run well under a second, and a real
/// password sidecar carries one line, not fifty.
pub(crate) const MAX_PW_CANDIDATES: usize = 50;

/// How many verifier-passing values an EXTRACTION will be spent on.
///
/// The verifier is a filter, not a verdict (a ZipCrypto check byte is
/// one byte; a capped 7z probe may never reach the checksum at all), so
/// the shortlist that survives it is retried through the real
/// extraction - but an extraction is real work, so the retry list is
/// short where the candidate list is long.
pub(crate) const MAX_PW_EXTRACT_TRIES: usize = 8;

/// Largest text sidecar scanned for passwords. A real password note
/// (.txt/.nfo/.diz) is tiny; a multi-megabyte "nfo" is a payload file, not
/// a hint, and re-reading it at every level would be unbounded work.
pub(crate) const PW_SIDECAR_MAX: u64 = 64 * 1024;

/// KDF-depth ceiling for UNSTRUCTURED candidates (sidecar lines, file
/// stems - anything a crafted post can mass-produce). The iteration
/// count comes from the archive header, so a hostile archive can demand
/// 2^24 rounds (~10 s of PBKDF2 per candidate) and turn the candidate
/// sweep into minutes of CPU. Above this depth only the job's own
/// password is tried; the archive keeps today's park/unrar path on a
/// miss. 2^19 keeps the full 50-candidate sweep in low single-digit
/// seconds while covering every count real archivers emit by default.
pub(crate) const PW_KDF_MAX_LG2: u8 = 19;

/// Wall-clock ceiling for one level's whole candidate sweep - the
/// total-work backstop for costs the header does not advertise (the 7z
/// probe decodes up to 64 MB per candidate).
pub(crate) const PW_PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// May this candidate pay for a KDF this deep? Structured candidates
/// (the operator-supplied job password) always may; harvested ones only
/// up to [`PW_KDF_MAX_LG2`].
pub(crate) fn kdf_candidate_allowed(lg2_count: u8, structured: bool) -> bool {
    structured || lg2_count <= PW_KDF_MAX_LG2
}

/// A harvested password candidate and where it came from (for the unlock
/// log line: knowing the source file is the whole point of the chain).
/// `structured` marks the operator-supplied job password - the one
/// source a crafted post cannot mass-produce - which alone is exempt
/// from the KDF-depth gate.
pub(crate) struct PwCandidate {
    pub(crate) value: String,
    pub(crate) source: String,
    pub(crate) structured: bool,
}

/// Harvest bounded password candidates from a level's on-disk siblings -
/// the nested password-chain unlock, where level k's extraction drops
/// level k+1's password in a text file beside it. Sources, most-likely
/// first: the job's own password (M24 ordering, resolved upstream), then
/// trimmed lines of small .txt/.nfo/.diz sidecars, then the release stem
/// and sibling file stems. Deduped and capped at [`MAX_PW_CANDIDATES`].
pub(crate) fn harvest_password_candidates(
    dir: &std::path::Path,
    provided: Option<&str>,
) -> Vec<PwCandidate> {
    use nzbkit::extract::release_stem;
    let mut out: Vec<PwCandidate> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut push = |value: &str, source: &str, structured: bool, out: &mut Vec<PwCandidate>| {
        let v = value.trim();
        // A password line, not a paragraph of prose or a binary blob.
        if v.is_empty() || v.chars().count() > 128 || v.contains(['\r', '\n', '\0']) {
            return;
        }
        if out.len() < MAX_PW_CANDIDATES && seen.insert(v.to_string()) {
            out.push(PwCandidate {
                value: v.to_string(),
                source: source.to_string(),
                structured,
            });
        }
    };

    if let Some(p) = provided {
        push(p, "job password", true, &mut out);
    }

    // The operator's own passwords file (SAB/NZBGet parity), ABOVE the
    // scraped sidecars: curated beats harvested, the same ranking the
    // in-stream probe applies to the same file. Structured, because the
    // operator typed these - so the KDF-depth gate never refuses one, and
    // a hostile post cannot price the operator's answer out of the sweep.
    //
    // Without this the file was reachable only from the RAR check-value
    // probe and the post-completion unlock, so the two shapes that reach
    // the disk ladder with no check to probe - a header-encrypted 7z, an
    // encrypted zip - failed the job (or left it packed) with the right
    // password sitting in a file we had already read (advQ/advP, the four-
    // way correctness round, 12 Aug).
    for pw in crate::smart::operator_passwords() {
        push(&pw, "passwords file", true, &mut out);
    }

    // Small text sidecars: each line is a candidate, and a "password: xxx"
    // / "pass = xxx" line also yields its tail (poster notes vary).
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in &entries {
        let is_sidecar = path.extension().is_some_and(|x| {
            let x = x.to_string_lossy().to_lowercase();
            x == "txt" || x == "nfo" || x == "diz"
        });
        if !is_sidecar {
            continue;
        }
        // symlink_metadata: a planted link must not pull text from
        // outside the job dir (or size-check a different file than the
        // one read below).
        let readable = std::fs::symlink_metadata(path)
            .map(|m| m.is_file() && m.len() <= PW_SIDECAR_MAX)
            .unwrap_or(false);
        if !readable {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let fname = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        for line in text.lines() {
            push(line, &fname, false, &mut out);
            if let Some(tail) = strip_password_label(line) {
                push(tail, &fname, false, &mut out);
            }
            if out.len() >= MAX_PW_CANDIDATES {
                break;
            }
        }
    }

    // Release stem and sibling file stems: some posters use the release
    // name (or a same-named marker file) as the password.
    for path in &entries {
        if let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) {
            let stem = release_stem(&name);
            push(&stem, "release/sibling stem", false, &mut out);
        }
        if out.len() >= MAX_PW_CANDIDATES {
            break;
        }
    }

    out
}

/// If `line` reads like `password: xxx` / `pass = xxx` / `pw - xxx`,
/// return the trimmed value after the label; else None.
pub(crate) fn strip_password_label(line: &str) -> Option<&str> {
    let t = line.trim();
    let lower = t.to_ascii_lowercase();
    for label in ["password", "passwort", "pass", "pwd", "pw"] {
        if let Some(rest) = lower.strip_prefix(label) {
            let rest = rest.trim_start();
            if let Some(after) = rest.strip_prefix([':', '=', '-']) {
                // Map the offset in `lower` back onto `t` (same length -
                // ASCII lowercasing preserves byte positions).
                let cut = t.len() - after.len();
                let val = t[cut..].trim();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// The first RAR volume in `dir` that needs a password (named or
/// magic-bearing). Any volume of an encrypted set carries the crypt
/// record - a multi-volume set repeats it in every volume's header - so
/// the first match is enough to probe candidates.
pub(crate) fn first_encrypted_rar(dir: &std::path::Path) -> Option<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .collect();
    paths.sort();
    paths
        .into_iter()
        .find(|p| (looks_like_named_rar(p) || rar_magic(p)) && nzbkit::rar::needs_password(p))
}

/// What a bounded 7z key check can honestly say.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SevenzKey {
    /// The first data entry decoded to its END, so its checksum ran.
    Opens,
    /// The container refused to open, or the entry failed to decode.
    Fails,
    /// The read hit [`SEVENZ_PROBE_CAP`] before the entry ended, so no
    /// checksum was ever reached. NOT a pass.
    Unknown,
}

/// How much of a 7z entry a key check will decode before giving up.
pub(crate) const SEVENZ_PROBE_CAP: u64 = 64 << 20;

/// Does this 7z container open AND decode its first file entry with
/// `password`? Header-encrypted archives fail to open on a wrong
/// password; data-encrypted ones open with plaintext headers and only
/// fail on decode, so the first real entry's bytes are pulled (bounded,
/// to a sink) to force the AES/decompress failure before we trust it.
///
/// The bound is why the answer has three states. What actually rejects
/// a wrong key on a data-encrypted entry is the entry's CHECKSUM at its
/// end, and a first member bigger than the cap never reaches it - so a
/// capped read used to come back "opens" for any value at all, and the
/// first candidate tried won (Codex sweep M, 13 Aug 2026: a 65 MiB
/// Copy entry answered `capped=true` for a wrong password whose full
/// read answers false). Reaching the cap is `Unknown`, and only the
/// extraction can settle it.
///
/// "First file entry" means the first that can actually judge the key:
/// where the metadata names an AES block, entries outside one are
/// skipped, because a plaintext entry decodes to its checksum under
/// every value at all (see [`sevenz_encrypted_entry_names`]).
pub(crate) fn sevenz_password_check(parts: &[PathBuf], password: Option<&str>) -> SevenzKey {
    sevenz_password_check_capped(parts, password, SEVENZ_PROBE_CAP)
}

/// [`sevenz_password_check`] with the read bound spelled out, so a test
/// can reach the capped branch without a 65 MiB fixture.
pub(crate) fn sevenz_password_check_capped(
    parts: &[PathBuf],
    password: Option<&str>,
    cap: u64,
) -> SevenzKey {
    // Bomb-gated like nzbkit's sevenz_needs_password: a container whose
    // end header declares an oversized decode is refused before the
    // library allocates on the declaration's say-so - "does this
    // password open it" is a question only a readable 7z gets to ask,
    // and this probe runs per candidate on the demoted container the
    // in-stream gate just refused. `open_sevenz` holds that gate and
    // reads a split set where it lies (TODO 212): a header-encrypted
    // `.7z.NNN` set answers off its last part, unjoined.
    let Ok(mut reader) = crate::rarfix::open_sevenz(parts, password) else {
        return SevenzKey::Fails;
    };
    // Only an entry whose own block passes through AES can judge a key.
    // A container may MIX blocks - `7z a` a file plain, then add a
    // second with `-p -mhe=off`, and block 0 is plaintext while block 1
    // is encrypted - and entries arrive in block order, so the first
    // data entry was block 0's and decoded to its checksum under ANY
    // value, `None` included (Codex sweep F-10, 23 Aug 2026). That
    // `Opens` settled the shortlist at the caller's value and the
    // sidecar password the later block needs was never harvested.
    // Empty means nothing in here is encrypted, and then the first data
    // entry is the right one to read, exactly as before.
    let encrypted = sevenz_encrypted_entry_names(reader.archive());
    let capped = std::cell::Cell::new(false);
    let probed = std::cell::Cell::new(false);
    let res = reader.for_each_entries(|entry, rd| {
        if entry.is_directory || !entry.has_stream {
            return Ok(true); // need a real data stream to verify the key
        }
        if !encrypted.is_empty() && !encrypted.contains(&entry.name) {
            return Ok(true); // a plaintext entry decodes under any value
        }
        probed.set(true);
        let mut sink = std::io::sink();
        // Reading the (verification-only) first entry to end trips CRC as
        // well as decode errors; bound it so a huge first member can't
        // stall the probe. One byte PAST the cap is how the read learns
        // it stopped short of the checksum rather than at it.
        let mut limited = std::io::Read::take(rd, cap + 1);
        let n = std::io::copy(&mut limited, &mut sink)?;
        capped.set(n > cap);
        Ok(false) // stop after the first data entry
    });
    // An encrypted entry the walk never reached settles nothing either:
    // fail closed so the caller harvests rather than trusting a value
    // no AES coder ever saw.
    let missed = !encrypted.is_empty() && !probed.get();
    match (res.is_ok() && !missed, capped.get()) {
        (false, _) => SevenzKey::Fails,
        (true, true) => SevenzKey::Unknown,
        (true, false) => SevenzKey::Opens,
    }
}

/// The names of the entries a 7z key check may honestly read: those
/// whose block passes through the AES-256-SHA256 coder. Empty for a
/// container with no encrypted data block at all.
///
/// `file_block_index` is the archive's own file-to-block map, and an
/// entry with no block (an empty file) is not one a key check can use.
fn sevenz_encrypted_entry_names(
    archive: &sevenz_rust2::Archive,
) -> std::collections::HashSet<String> {
    let aes = |bi: usize| {
        archive.blocks.get(bi).is_some_and(|b| {
            b.coders
                .iter()
                .any(|c| c.encoder_method_id() == sevenz_rust2::EncoderMethod::ID_AES256_SHA256)
        })
    };
    archive
        .files
        .iter()
        .enumerate()
        .filter(|&(i, _)| {
            archive
                .stream_map
                .file_block_index
                .get(i)
                .copied()
                .flatten()
                .is_some_and(aes)
        })
        .map(|(_, f)| f.name.clone())
        .collect()
}

/// [`sevenz_password_check`] as the two-state question its callers ask
/// when they only need "is this worth trying" - an indeterminate answer
/// counts as yes, because the extraction is what settles it.
pub(crate) fn sevenz_password_opens(parts: &[PathBuf], password: Option<&str>) -> bool {
    sevenz_password_check(parts, password) != SevenzKey::Fails
}

/// The one auto-unlock announcement in the tree, so its wording cannot
/// drift again. It did: three sites printed "auto-unlocked {name} with
/// password from {source}" and two more printed the same event without
/// the name, or with "a harvested password" and no source at all (TODO
/// 162 item 5). One shape, and it names both halves the user needs -
/// which archive opened, and where the key came from.
pub(crate) fn log_auto_unlocked(archive: &std::path::Path, source: &str) {
    info!(
        target: "password",
        "🔑 auto-unlocked {} with password from {}",
        archive.file_name().unwrap_or_default().to_string_lossy(),
        source
    );
}

/// Resolve the working password for this level's encrypted archive by
/// harvesting candidates from the level's own outputs. Returns `Some(pw)`
/// once a candidate is proven correct - RAR via the stored check value (no
/// data decrypted), 7z via a real open+decode attempt - or `None` to keep
/// the provided password (it already works, the set is check-less, or
/// nothing matched: today's park behavior is preserved).
pub(crate) fn resolve_level_password(
    dir: &std::path::Path,
    provided: Option<&str>,
) -> Option<String> {
    if let Some(rar) = first_encrypted_rar(dir) {
        return resolve_rar_password(&rar, dir, provided);
    }
    // Single-container 7z only. The probe can read a split set unjoined
    // now (TODO 212), but this level-wide resolve keeps its v1 shape:
    // `extract_sevenz` resolves per CONTAINER and covers the split case.
    if let Ok(jobs) = collect_sevenz_archives(dir)
        && let Some(z) = jobs.iter().find(|p| p.len() == 1)
        // Header-first, same reason as in `sevenz_password_candidates`:
        // an unencrypted container has always opened unkeyed here, so
        // the probe's only job on this arm was to spend a 64 MB decode
        // confirming it. The metadata answers it for free, and a false
        // is the only answer that short-circuits.
        && crate::rarfix::sevenz_set_is_encrypted(z)
        && !sevenz_password_opens(z, None)
    {
        return resolve_sevenz_password(z, dir, provided);
    }
    // Encrypted zip. Both schemes carry a verifier in the entry framing,
    // so a candidate is settled without decoding a byte - which makes
    // this the cheapest of the three probes, not the most expensive.
    if let Some(zip) = first_encrypted_zip(dir) {
        return resolve_zip_password(&zip, dir, provided);
    }
    None
}

/// The first password-protected zip container in `dir`, if any - parts
/// in read order, so a spanned or byte-split set probes as one archive.
pub(crate) fn first_encrypted_zip(dir: &std::path::Path) -> Option<Vec<PathBuf>> {
    nzbkit::zip::scan(dir)
        .into_iter()
        .map(|f| f.parts)
        .find(|parts| nzbkit::zip::needs_password(parts))
}

/// Candidate sweep for an encrypted zip.
///
/// Unlike the RAR and 7z twins this needs no wall-clock budget of its
/// own: `password_opens` reads a salt and a two-byte verifier (AE) or a
/// twelve-byte header (ZipCrypto) and derives one key, so a candidate
/// costs microseconds rather than a decode - there is no cost for a
/// hostile post to inflate. The budget stays anyway, because the
/// candidate LIST is attacker-influenced (harvested sidecars) even when
/// each try is cheap, and one bound is easier to reason about than a
/// special case.
///
/// A ZipCrypto check byte accepts a wrong password once in 256 tries, so
/// the winner returned here is a candidate, not a verdict: the
/// extraction's CRC32 is what proves it, and a false accept costs one
/// failed unpack, exactly as it did before this probe existed.
/// EVERY value worth spending an extraction on for this container,
/// best first - not just the first one the verifier likes.
///
/// `password_opens` reads one check byte on a ZipCrypto entry, so it
/// accepts a wrong value once in 256 tries; that was always documented
/// as "a candidate, not a verdict", but the caller then stopped at the
/// first hit and never came back, so a 1-in-256 accident ahead of the
/// real value left the archive packed with the answer in hand (Codex
/// sweep F, 13 Aug 2026: the checked-in `zipcrypto.zip` is opened by
/// `wrong-93` as well as by `SECRET`). The extraction's CRC32 is the
/// only authority, so hand the caller the whole shortlist and let it
/// keep going until one of them actually produces the payload.
///
/// `None` in the returned list means "no password" - what an
/// unencrypted container gets, and what preserves today's park path
/// when nothing matched.
pub(crate) fn zip_password_candidates(
    dir: &std::path::Path,
    parts: &[PathBuf],
    provided: Option<&str>,
) -> Vec<(Option<String>, String)> {
    let keep = || vec![(provided.map(str::to_string), String::from("job password"))];
    if !nzbkit::zip::needs_password(parts) {
        return keep();
    }
    let mut out: Vec<(Option<String>, String)> = Vec::new();
    let t0 = std::time::Instant::now();
    // `harvest_password_candidates` leads with the provided password,
    // so the working-password case still costs one verifier read.
    for cand in harvest_password_candidates(dir, provided) {
        if t0.elapsed() > PW_PROBE_BUDGET {
            warn!(target: "password", "password probe budget exhausted - keeping the park path");
            break;
        }
        if nzbkit::zip::password_opens(parts, Some(&cand.value)) {
            out.push((Some(cand.value), cand.source));
        }
    }
    out.truncate(MAX_PW_EXTRACT_TRIES);
    if out.is_empty() { keep() } else { out }
}

pub(crate) fn resolve_zip_password(
    parts: &[PathBuf],
    dir: &std::path::Path,
    provided: Option<&str>,
) -> Option<String> {
    if let Some(p) = provided
        && nzbkit::zip::password_opens(parts, Some(p))
    {
        return None; // provided password already works
    }
    let t0 = std::time::Instant::now();
    for cand in harvest_password_candidates(dir, provided) {
        if t0.elapsed() > PW_PROBE_BUDGET {
            warn!(target: "password", "password probe budget exhausted - keeping the park path");
            break;
        }
        if nzbkit::zip::password_opens(parts, Some(&cand.value)) {
            // Deliberately silent: the zip arm re-harvests this same
            // directory per container and announces the unlock that
            // really produced the payload, so announcing here too
            // printed the identical line twice for one event.
            return Some(cand.value);
        }
    }
    None
}

/// The GROUP-scoped twin of [`resolve_rar_password`]: resolve a working
/// password for one named-RAR stem group by probing that group's own
/// crypt record.
///
/// The level-wide resolver probes only the first encrypted RAR it finds
/// in the directory, and its answer used to be handed to every group -
/// so with two encrypted sets under different passwords, the second was
/// tried with the first one's value, failed as "wrong password", and
/// stayed packed while the run reported success (Codex sweep 13 Aug U1).
/// Returns `None` to keep the caller's password (it already verifies,
/// the set is check-less, or nothing matched).
pub(crate) fn resolve_rar_group_password(
    dir: &std::path::Path,
    group: &[PathBuf],
    provided: Option<&str>,
) -> Option<String> {
    let enc = group.iter().find(|p| nzbkit::rar::needs_password(p))?;
    resolve_rar_password(enc, dir, provided)
}

pub(crate) fn resolve_rar_password(
    rar: &std::path::Path,
    dir: &std::path::Path,
    provided: Option<&str>,
) -> Option<String> {
    use nzbkit::rar::PwVerdict;
    let probe = nzbkit::rar::crypt_probe(rar)?;
    // Check-less set: a wrong password can't be vetoed before it writes
    // garbage, so we never guess - hand it to today's path (unrar, or a
    // manual 🔑).
    probe.check?;
    if let Some(p) = provided
        && matches!(probe.verify(p), PwVerdict::Verified)
    {
        return None; // provided password already works
    }
    let t0 = std::time::Instant::now();
    for cand in harvest_password_candidates(dir, provided) {
        // KDF cost gates: the header's iteration depth is attacker-
        // controlled, so harvested candidates never pay for a deep
        // derivation, and the sweep as a whole is wall-time bounded.
        if !kdf_candidate_allowed(probe.lg2_count, cand.structured) {
            continue;
        }
        if t0.elapsed() > PW_PROBE_BUDGET {
            warn!(target: "password", "password probe budget exhausted - keeping the park path");
            break;
        }
        if matches!(probe.verify(&cand.value), PwVerdict::Verified) {
            log_auto_unlocked(rar, &cand.source);
            return Some(cand.value);
        }
    }
    None
}

/// The 7z twin of [`zip_password_candidates`]: every value worth
/// spending an extraction on for THIS container, best first.
///
/// Ordered PROVEN before INDETERMINATE. A value whose probe decoded the
/// first entry to its checksum is settled; one that only reached the
/// 64 MB cap is not (see [`sevenz_password_check`]), and putting those
/// last keeps the normal case at one extraction while still letting a
/// big-first-member archive reach the value that really opens it.
///
/// An unencrypted container needs no candidate list at all, and says so
/// from its end header ([`crate::rarfix::sevenz_set_is_encrypted`]) with
/// nothing decoded. Failing that, what the caller already holds is
/// probed FIRST - and that includes holding nothing, which is what
/// settles a container the header check could not prove clean.
pub(crate) fn sevenz_password_candidates(
    z: &[PathBuf],
    dir: &std::path::Path,
    provided: Option<&str>,
) -> Vec<(Option<String>, String)> {
    let keep = || vec![(provided.map(str::to_string), String::from("job password"))];
    // Cheapest settle first: ask the END HEADER whether there is any
    // encrypted coder in the container at all. A plain archive answers
    // no from its parsed metadata alone, and that is the same verdict
    // the probe below reaches by decoding up to 64 MB of the first
    // entry - a full LZMA pass whose only finding is that there was
    // nothing to decrypt, over bytes the real extraction decodes again
    // moments later. `sevenz_set_is_encrypted` fails closed, so every
    // header-encrypted, malformed or unprovable shape falls through to
    // exactly the probe ordering below.
    if !crate::rarfix::sevenz_set_is_encrypted(z) {
        return keep(); // settled off the header: nothing to decrypt
    }
    // Probe what the caller actually has - a password, or NOTHING - and
    // settle on `Opens` either way. The None arm is the whole point: an
    // unencrypted container opens under every value at all (7-Zip
    // ignores a password it has no use for), so without it the
    // no-password case fell through to the harvest, the first stem
    // found there probed as "proven", and the extraction ran with a
    // password it never needed and announced a false auto-unlock - up
    // to 64 MB of decode per candidate, against `PW_PROBE_BUDGET`, to
    // buy a line that reads as "this release was passworded" (23 Aug
    // 2026, seen while verifying TODO 94 C). `Fails` (header-encrypted,
    // or plaintext headers over encrypted data) and `Unknown` (a first
    // member past the 64 MB cap) both fall through to the harvest
    // exactly as before, one fast failing probe later.
    if sevenz_password_check(z, provided) == SevenzKey::Opens {
        return keep(); // settled: this is what the extraction needs
    }
    // The 7z header does not advertise its KDF depth up front and each
    // probe may decode up to 64 MB, so the wall-clock budget is the
    // whole defense here.
    let t0 = std::time::Instant::now();
    let (mut proven, mut maybe) = (Vec::new(), Vec::new());
    for cand in harvest_password_candidates(dir, provided) {
        if t0.elapsed() > PW_PROBE_BUDGET {
            warn!(target: "password", "password probe budget exhausted - keeping the park path");
            break;
        }
        match sevenz_password_check(z, Some(&cand.value)) {
            SevenzKey::Opens => proven.push((Some(cand.value), cand.source)),
            SevenzKey::Unknown => maybe.push((Some(cand.value), cand.source)),
            SevenzKey::Fails => {}
        }
    }
    proven.append(&mut maybe);
    proven.truncate(MAX_PW_EXTRACT_TRIES);
    if proven.is_empty() { keep() } else { proven }
}

pub(crate) fn resolve_sevenz_password(
    z: &[PathBuf],
    dir: &std::path::Path,
    provided: Option<&str>,
) -> Option<String> {
    let best = sevenz_password_candidates(z, dir, provided)
        .into_iter()
        .next()?
        .0?;
    if provided == Some(best.as_str()) {
        return None; // the provided password IS the answer
    }
    // No announcement here. This is the head of a SHORTLIST, not a
    // settled answer - a probe that hit the 64 MB cap never reached the
    // entry's checksum - and `extract_sevenz` prints the line for
    // whichever candidate actually produced the payload.
    Some(best)
}
