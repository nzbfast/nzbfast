//! The finish-time verdict on every encrypted store output of the
//! healthy groups: does its plaintext match the checksum the archive
//! stored for it, and if not, is that damage or the wrong password?
//!
//! Hoisted out of `crypto.rs` on 22 Aug 2026 because the legacy decrypt
//! pass this walk was gathering jobs for sat nine lines under the size
//! gate's 500-line function ceiling (TODO 106 pattern, as
//! `check_sweep.rs`, `fleet_knobs.rs` and `extract/names.rs`). That pass
//! was deleted under TODO 27 phase 3 on 23 Aug 2026, once every
//! encrypted store shape - RAR4 and check-less RAR5 included - took the
//! plaintext-once route; what survives here is the adjudication it
//! carried, applied to bytes that are already on disk.
//!
//! The order of the checks is the order they always ran in, and
//! deliberately so - this is the encrypted-RAR path, where a reordered
//! check is a silently-corrupt volume. `crypto_tests.rs` is the proof.

use super::*;

/// What one finish walk decided, before it takes the routing lock again
/// to act. The fields are the two verdicts the legacy gather produced
/// alongside its job list, under their own names.
pub(super) struct Verdicts {
    /// Groups that must DEMOTE: an incomplete cipher record, an output
    /// nothing can adjudicate, or a checksum miss on a password no
    /// stored check ever proved (which is the wrong password, not
    /// damage). Their volumes materialize through the re-encrypt shim
    /// and the disk path takes over.
    pub(super) failed: std::collections::HashSet<String>,
    /// The subset of `failed` whose demote is a WRONG PASSWORD rather
    /// than an incomplete or unadjudicable set - a checksum miss on a
    /// password no stored check ever proved. It only changes the reason
    /// string, and the reason string is what the user reads.
    pub(super) late: std::collections::HashSet<String>,
    /// ...and the outputs that verified: decrypted, on disk, published.
    pub(super) done: Vec<String>,
}

/// TODO 100 test rig: `NZBFAST_DECRYPT_ENOSPC_ONCE=pre|post` makes the
/// encrypted finish verdict fail ONCE per process with a disk-full
/// error - before any output is judged (`pre`), or after every verdict
/// landed (`post`, the exact journal state an unpack-stage failure after
/// a finished download leaves behind). The daemon retry e2e asserts the
/// second attempt refetches ~nothing, and the post-proc lane suite uses
/// it to fail a job inside its finishing window.
///
/// It hooked the legacy decrypt pass until TODO 27 phase 3; the stages
/// are the same two instants, now either side of a verdict that moves no
/// byte rather than of an AES pass that moved every one of them.
fn injected_enospc(stage: &str) -> Option<io::Error> {
    use std::sync::atomic::AtomicBool;
    static FIRED: AtomicBool = AtomicBool::new(false);
    if std::env::var("NZBFAST_DECRYPT_ENOSPC_ONCE").ok().as_deref() == Some(stage)
        && !FIRED.swap(true, Ordering::Relaxed)
    {
        return Some(io::Error::new(
            io::ErrorKind::StorageFull,
            "injected decrypt disk-full (NZBFAST_DECRYPT_ENOSPC_ONCE)",
        ));
    }
    None
}

impl Extractor {
    /// Adjudicate every encrypted store output of the healthy groups and
    /// demote the groups that fail. Returns the output names that
    /// verified, for the finish report's "decrypted" notice.
    ///
    /// Nothing here moves a byte of payload. The plaintext is already on
    /// disk (it was decrypted at article-write time) and the posted
    /// bytes behind it are reproducible from it through the re-encrypt
    /// shim, so a demote at this point still materializes byte-exact
    /// volumes - which is what lets an UNPROVABLE password decrypt
    /// in-stream at all (see [`Extractor::instream_decrypt_allowed`]).
    ///
    /// A group decrypts ALL of its files or NONE: once one file is
    /// published, a fallback would rebuild volumes for a set the user
    /// has already been handed part of, so any failure condemns the
    /// whole group.
    pub(in crate::extract) fn verify_encrypted_outputs(&self) -> io::Result<Vec<String>> {
        let Verdicts {
            failed,
            late,
            mut done,
        } = self.encrypted_verdicts()?;
        if !done.is_empty()
            && let Some(e) = injected_enospc("pre")
        {
            return Err(e);
        }
        if !failed.is_empty() {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            for key in failed {
                if inner.groups.contains_key(&key) {
                    // Two very different demotes reach here, and the
                    // reason is what the user reads. A late CRC miss on a
                    // password nothing could verify up front (every RAR4
                    // set, and a check-less RAR5 one) is a WRONG PASSWORD
                    // on a complete download - "incomplete" would send
                    // the reader hunting for articles that all arrived.
                    // Both keep the "encrypted" substring the finish
                    // ladder routes remediation on.
                    let why = match late.contains(&key) {
                        true => "encrypted data failed its checksum (wrong password)",
                        false => "encrypted data incomplete",
                    };
                    self.fallback_group(inner, &key, why)?;
                }
            }
        }
        done.sort();
        if !done.is_empty()
            && let Some(e) = injected_enospc("post")
        {
            return Err(e);
        }
        Ok(done)
    }

    /// The read-only half of [`Self::verify_encrypted_outputs`]: walk the
    /// healthy groups under the routing lock and decide each encrypted
    /// output's fate without changing anything.
    fn encrypted_verdicts(&self) -> io::Result<Verdicts> {
        let mut failed: std::collections::HashSet<String> = Default::default();
        let mut late: std::collections::HashSet<String> = Default::default();
        let mut done: Vec<String> = Vec::new();
        {
            let g = self.inner.lock_ok();
            let inner = &*g;
            for (key, grp) in &inner.groups {
                if grp.fallback {
                    continue;
                }
                // The WHOLE-FILE checksum lives on the entry's LAST piece
                // (`split_after == false`) - per the RAR5 spec, earlier
                // pieces carry only their own volume's bytes, which is
                // why a multi-volume encrypted set used to have no
                // verifiable checksum at all. By finish every volume has
                // arrived, so the tail is simply here to be read. The
                // tail's own crypt record rides along: it owns the stored
                // value, so ITS tweaked-checksum flag (and salt) decide
                // the comparison - real `rar` sets the flag on the tail
                // alone, and a gate built from the head's record
                // false-failed every intact split set.
                let mut tail_crcs: HashMap<&str, (u32, Option<&EntryCrypt>)> = HashMap::new();
                // ...and, from the same piece, whether the entry states a
                // digest instead of a CRC32. Read off the TAIL for the
                // same reason: the whole-file checks live there.
                let mut tail_hash_only: std::collections::HashSet<&str> = Default::default();
                for &si in &grp.slots {
                    let Some(m) = inner.slots[si].mapper.as_ref() else {
                        continue;
                    };
                    for e in &m.entries {
                        if e.is_dir || !e.encrypted || e.split_after {
                            continue;
                        }
                        match e.file_crc {
                            Some(crc) => {
                                tail_crcs.insert(e.name.as_str(), (crc, e.crypt.as_ref()));
                            }
                            None if e.hash.is_some() => {
                                tail_hash_only.insert(e.name.as_str());
                            }
                            None => {}
                        }
                    }
                }
                // One verdict per inner FILE, keyed off its head piece
                // (split_before == false - whose IV started the stream).
                let mut heads: HashMap<&str, (String, u64)> = HashMap::new();
                for &si in &grp.slots {
                    let Some(m) = inner.slots[si].mapper.as_ref() else {
                        continue;
                    };
                    for e in &m.entries {
                        if e.is_dir || !e.encrypted || e.split_before || e.crypt.is_none() {
                            continue;
                        }
                        // out_names is keyed on the RAW name; the
                        // sanitized form is the on-disk fallback. Key
                        // `heads` by raw name too so distinct raw names
                        // get distinct verdicts.
                        let out = grp
                            .out_names
                            .get(&e.name)
                            .cloned()
                            .unwrap_or_else(|| sanitize_out_name(&e.name));
                        heads
                            .entry(e.name.as_str())
                            .or_insert((out, e.unpacked_size));
                    }
                }
                for (fname, (out, unp)) in heads {
                    if !inner.inner_writers.contains_key(&out) {
                        continue;
                    }
                    // The record that OWNS the stored whole-file CRC (the
                    // tail piece's, for a split entry) - the one whose
                    // tweaked flag and salt the gate must use.
                    let crc_owner = tail_crcs.get(fname).and_then(|&(_, c)| c);
                    let whole_crc = tail_crcs.get(fname).map(|&(c, _)| c);
                    let hash_only = whole_crc.is_none() && tail_hash_only.contains(fname);
                    let Some(cs) = inner.crypto_files.get(&out) else {
                        // No plaintext-once state behind an encrypted
                        // output: its bytes are the posted CIPHERTEXT.
                        // Since TODO 27 phase 3 nothing decrypts those at
                        // finish, so the group demotes and the disk path
                        // - which derives the key itself and can check a
                        // digest this build cannot compute - takes over.
                        // Reached by the `rar a -htb` veto, and by a
                        // resume of a journal an older build wrote.
                        failed.insert(key.clone());
                        continue;
                    };
                    // Unsplit: the state's own gate. Split: the gate
                    // could not exist at state creation (the tail may not
                    // have been mapped) - resolve it NOW from the tail's
                    // stored CRC; the plain runs composed all along
                    // (`track_plain`).
                    let verdict = if cs.expect_crc.is_some() {
                        cs.crc_verdict()
                    } else {
                        crc_gate_from(whole_crc, crc_owner, inner.password.as_deref())
                            .and_then(|gate| cs.crc_verdict_with(&gate))
                    };
                    // The hash-only backstop, and the only ORDER-
                    // INDEPENDENT place to put it.
                    // `instream_decrypt_allowed` resolves its check
                    // fields across the whole file, but a fact that has
                    // not arrived cannot veto: only the TAIL fragment
                    // carries the whole-file checks, so a head mapped
                    // alone reads `hash: None, file_crc: None`, answers
                    // "allowed" and latches the plaintext-once route for
                    // the whole file (`crypto_files` caches by output
                    // name, first decision wins). Whether that happens
                    // therefore depends on which volume is mapped first,
                    // and without this the head-first order published
                    // plaintext with no integrity verdict at all. By
                    // finish every volume is mapped, so `hash_only` is
                    // the truth: demote, and the shim reproduces the
                    // posted bytes for the fallback (Codex sweep 12 Aug
                    // F2). The route may still differ by arrival order;
                    // what it may never be is MIXED, which is the gate's
                    // own contract.
                    if unp > 0 && hash_only {
                        failed.insert(key.clone());
                        continue;
                    }
                    match verdict {
                        // A checksum MISS means two different things, and
                        // only the stored password check tells them
                        // apart. On a verified password the key is proven
                        // right, so the plaintext under it is wrong -
                        // ciphertext damaged before it was posted, which
                        // every outer yEnc/PAR2 check agreed with - and
                        // that is a hard failure. On a password nothing
                        // could prove (RAR4, or a check-less RAR5 set)
                        // the likelier reading by far is simply the WRONG
                        // password on an intact download, so the group
                        // demotes and the disk path re-tries with the
                        // password itself.
                        Some(false) if cs.pw_verified => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "encrypted RAR file failed its stored CRC after decryption",
                            ));
                        }
                        Some(false) => {
                            late.insert(key.clone());
                            failed.insert(key.clone());
                        }
                        // Nothing checkable AND nothing that proved the
                        // password: this output has been adjudicated by
                        // no one, so publishing it would hand over bytes
                        // nobody vouched for. Demote instead - precisely
                        // where the mapper used to send such a set the
                        // moment it saw a missing check. A zero-length
                        // entry has no plaintext to check and must not
                        // drag its group to disk over it.
                        None if !cs.pw_verified && unp > 0 => {
                            failed.insert(key.clone());
                        }
                        _ if unp == 0 || cs.complete() => done.push(out),
                        // Posted cipher that never fully arrived: the
                        // same coverage hole the legacy pass condemned a
                        // group for.
                        _ => {
                            failed.insert(key.clone());
                        }
                    }
                }
            }
        }
        Ok(Verdicts { failed, late, done })
    }
}
