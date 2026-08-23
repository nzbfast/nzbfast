//! Encrypted-store crypto: the per-entry AES state machine, the
//! plaintext-once decrypt path with its journal events and chain
//! checkpoints, the finish-time verdict that adjudicates each decrypted
//! output, and password probing/awaits.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43
//! recipe: a verbatim move, not a redesign. The legacy finish()-time
//! decrypt pass it also carried - scratch temps, shards, the publish
//! barrier and the /stream ciphertext reader - was deleted under TODO 27
//! phase 3 on 23 Aug 2026, once every encrypted store shape took the
//! plaintext-once route.

use super::*;
use crate::sync::MutexExt;
use tracing::info;

/// Chain-checkpoint stride for in-stream decrypted files (multiple of
/// 16). One 16-byte cipher block is kept per stride, bounding the
/// posted-bytes shim's worst-case re-encrypt walk; ~1 MB of checkpoints
/// per 60 GB file.
pub(super) const CRYPTO_CHUNK: u64 = 1 << 20;

/// Journal-bound facts about an in-stream decrypted file, drained by the
/// caller (`drain_crypto_events`) and written as `E`/`K`/`T` journal
/// lines. Together with the `D` placement records they let a resume run
/// RE-ENCRYPT the on-disk plaintext back into posted volume bytes
/// instead of refetching (phase 2 of plaintext-once): `Params` carries
/// the KDF inputs and IV, `Checkpoint` a chain block per stride so the
/// rebuild can restart across coverage holes, and `TailPad` the final
/// block's beyond-`unp` plaintext without which the last block cannot
/// re-encrypt byte-exactly.
pub enum CryptoJournalEvent {
    Params {
        name: String,
        salt: [u8; 16],
        lg2: u8,
        iv: [u8; 16],
        unp: u64,
        /// Stored password check (8-byte value + 4-byte csum): lets a
        /// resume PROVE the password before re-encrypting anything - a
        /// wrong key would otherwise rebuild garbage posted bytes.
        check: Option<[u8; 12]>,
    },
    Checkpoint {
        name: String,
        off: u64,
        block: [u8; 16],
    },
    TailPad {
        name: String,
        pad: Vec<u8>,
    },
}

/// Event sink shared by every [`CryptoState`] of an extractor chain
/// (children inherit it like the holds budget, so nested encrypted
/// outputs journal through the same drain).
pub(super) type CryptoEventSink = Arc<Mutex<Vec<CryptoJournalEvent>>>;

/// One encrypted store output being decrypted in-stream. Owned by the
/// level's `Inner` (keyed by output name), shared into `WriteJob`s so
/// the AES work runs outside the routing lock under this state's own
/// How a decrypted file's stored checksum is compared against the CRC32
/// composed from its plaintext (Increment B).
///
/// `hash_key` absent is WinRAR's default: the stored value IS a plain
/// CRC32 of the plaintext. Present means the crypt record set the
/// tweaked-checksum flag (0x02) and the stored value is the keyed fold
/// of that CRC - which the download can still verify, because deriving
/// `hash_key` needs only the password we are decrypting with. Folding
/// the computed CRC and comparing checks the same two things a plain
/// comparison does (the key is right, the plaintext is intact), so a
/// tweaked entry is no longer un-verifiable and no longer has to be
/// handed to unrar.
#[derive(Clone, Copy)]
pub(super) struct CrcGate {
    pub(super) stored: u32,
    pub(super) hash_key: Option<[u8; 32]>,
}

impl CrcGate {
    /// The stored checksum as this gate compares it: plain, or the
    /// keyed fold of `computed`.
    pub(super) fn accepts(&self, computed: u32) -> bool {
        match &self.hash_key {
            None => computed == self.stored,
            Some(hk) => rarcrypt::mac_crc32_with_key(hk, computed) == self.stored,
        }
    }
}

/// Build the gate for an encrypted entry: `None` when nothing is
/// checkable (no stored CRC, or a split entry whose stored CRC covers
/// only the last piece), else plain or keyed per the tweaked flag.
pub(super) fn crc_gate(
    file_crc: Option<u32>,
    c: &EntryCrypt,
    keys: &rarcrypt::EntryKeys,
) -> Option<CrcGate> {
    file_crc.map(|stored| CrcGate {
        stored,
        // RAR4 has no tweaked-checksum flag: its header CRC is always the
        // bare plaintext CRC32, so the gate compares it directly.
        hash_key: c.tweaked_checksum().then_some(keys.hash_key).flatten(),
    })
}

/// Build the gate for a stored whole-file CRC whose OWNING piece is
/// known - the piece whose header actually stored the value. For a split
/// entry that is the TAIL piece, and its record is the one that decides
/// the comparison: real `rar` sets the tweaked-checksum flag on the tail
/// alone (the earlier pieces store their own volume's plain CRC), so a
/// gate built from the head's record compared the bare CRC against the
/// tail's keyed fold and false-failed every intact split set. The fold
/// key also derives from the owner's own salt, not the head's.
///
/// `None` when nothing is checkable: no stored value, or a tweaked value
/// whose fold key cannot be derived (no password / RAR4-shaped record) -
/// a plain comparison against a folded value would false-fail.
pub(super) fn crc_gate_from(
    stored: Option<u32>,
    owner: Option<&EntryCrypt>,
    pw: Option<&str>,
) -> Option<CrcGate> {
    let stored = stored?;
    let hash_key = if owner.is_some_and(|c| c.tweaked_checksum()) {
        Some(owner?.derive(pw?)?.hash_key?)
    } else {
        None
    };
    Some(CrcGate { stored, hash_key })
}

/// per-file mutex.
pub(super) struct CryptoState {
    pub(super) key: rarcrypt::AesKey,
    pub(super) iv: [u8; 16],
    /// Plaintext length (the head entry's `unpacked_size`).
    pub(super) unp: u64,
    /// Posted ciphertext length = align16(unp).
    pub(super) cipher_len: u64,
    /// Stored plaintext checksum when checkable at creation (single-piece
    /// entry); verified at finish from the composed runs, through the
    /// keyed fold when the entry's checksum is tweaked. A SPLIT entry's
    /// whole-file CRC lives on its tail piece, which may not have arrived
    /// when this state is created - `None` here, and
    /// `verify_encrypted_outputs` resolves the gate then and adjudicates
    /// via [`Self::crc_verdict_with`].
    pub(super) expect_crc: Option<CrcGate>,
    /// Maintain the plaintext CRC runs. True when `expect_crc` is set OR
    /// the entry is split (its tail piece's stored CRC becomes checkable
    /// at finish); false only when no whole-file value can ever exist,
    /// where the composition would be a pure extra pass.
    pub(super) track_plain: bool,
    /// Did the entry's stored check PROVE this password before a byte
    /// was decrypted? False for RAR4 (the format stores no check) and
    /// for a check-less or malformed-check RAR5 set. Such a file still
    /// decrypts in-stream - the shim rebuilds byte-exact volumes under a
    /// wrong key - but its finish verdict DEMOTES on a checksum miss
    /// where a verified file's miss is a hard error: an unprovable set
    /// that fails its checksum is the wrong password, not damage.
    pub(super) pw_verified: bool,
    /// Output name + shared sink for the resume-journal events.
    pub(super) out_name: String,
    pub(super) events: CryptoEventSink,
    pub(super) st: Mutex<CryptoSt>,
}

#[derive(Default)]
pub(super) struct CryptoSt {
    /// Contiguous ciphertext runs received, keyed by cipher start.
    /// Cipher offsets equal output-file offsets (store mapping), so one
    /// coordinate space serves both views.
    pub(super) runs: BTreeMap<u64, CryptoRun>,
    /// Chunk boundary c -> cipher block [c-16, c), captured from the
    /// wire as spans stream past. Pure posted bytes; repair refreshes
    /// any it overwrites.
    pub(super) checkpoints: HashMap<u64, [u8; 16]>,
    /// Plaintext CRC composition (maintained only when `track_plain` is
    /// set - otherwise it would be a pure extra pass).
    pub(super) plain: CrcRuns,
    /// Plaintext of the final cipher block beyond `unp` (the <=15
    /// padding bytes). Never written to disk; required to re-encrypt
    /// the last block byte-exactly.
    pub(super) tail_pad: Vec<u8>,
    pub(super) tail_done: bool,
}

/// One contiguous ciphertext run. Plaintext has been written for
/// [p_lo, p_hi) (clipped to `unp` on disk). The run retains only the
/// cipher slivers the seams need:
/// - `head` = cipher [start, p_lo): undecryptable until the predecessor
///   arrives (its last 16 bytes are the chain anchor into p_lo). Empty
///   iff start == 0. For a run too small to decrypt anything
///   (p_lo == p_hi == start), `head` holds the ENTIRE run's cipher.
/// - `tail` = cipher [p_hi - 16, end): the chain block into the tail
///   plus the partial tail block, for extension and the right seam.
///   Empty when nothing is decrypted (head carries everything).
pub(super) struct CryptoRun {
    pub(super) end: u64,
    pub(super) p_lo: u64,
    pub(super) p_hi: u64,
    pub(super) head: Vec<u8>,
    pub(super) tail: Vec<u8>,
}

impl CryptoRun {
    pub(super) fn decrypted(&self) -> bool {
        self.p_hi > self.p_lo || (self.p_lo == 0 && self.p_hi == 0 && self.head.is_empty())
    }
}

impl CryptoState {
    pub(super) fn new(
        key: rarcrypt::AesKey,
        iv: [u8; 16],
        unp: u64,
        expect_crc: Option<CrcGate>,
        track_plain: bool,
        pw_verified: bool,
        out_name: String,
        events: CryptoEventSink,
    ) -> CryptoState {
        CryptoState {
            key,
            iv,
            unp,
            cipher_len: rarcrypt::align16(unp),
            track_plain: track_plain || expect_crc.is_some(),
            expect_crc,
            pw_verified,
            out_name,
            events,
            st: Mutex::new(CryptoSt::default()),
        }
    }

    /// Decrypt the full blocks of `cipher` (absolute cipher offset `at`,
    /// 16-aligned), chained from `chain` (= cipher block [at-16, at), or
    /// the IV at offset 0). Writes the plaintext (clipped to unp; final-
    /// block padding goes to tail_pad), extends the CRC runs, captures
    /// checkpoints. Returns the decrypted byte count (a multiple of 16)
    /// - the caller keeps the partial remainder as tail cipher.
    pub(super) fn advance(
        &self,
        st: &mut CryptoSt,
        w: &FileWriter,
        chain: [u8; 16],
        at: u64,
        cipher: &[u8],
        overwrite_crc: bool,
    ) -> io::Result<u64> {
        debug_assert_eq!(at % 16, 0);
        let full = cipher.len() - cipher.len() % 16;
        if full == 0 {
            return Ok(0);
        }
        // Journal a chain anchor for THIS decrypt boundary: every
        // decrypted region then begins at a journaled K, which is what
        // lets a resume's re-encrypt walk stay inside known-good
        // plaintext instead of marching through a coverage hole.
        self.events.lock_ok().push(CryptoJournalEvent::Checkpoint {
            name: self.out_name.clone(),
            off: at,
            block: chain,
        });
        // Checkpoints come from the ciphertext itself, before decrypt-in-
        // place destroys it.
        let mut c = at.next_multiple_of(CRYPTO_CHUNK).max(CRYPTO_CHUNK);
        while c <= at + full as u64 {
            // At an exact CRYPTO_CHUNK boundary the checkpoint's previous
            // block is the caller-supplied chain. `c - 16 - at` used to
            // underflow before its cast to i64 in overflow-checked builds.
            let block: [u8; 16] = match c.checked_sub(16).and_then(|p| p.checked_sub(at)) {
                Some(s) => cipher[s as usize..s as usize + 16].try_into().unwrap(),
                None => chain,
            };
            st.checkpoints.insert(c, block);
            self.events.lock_ok().push(CryptoJournalEvent::Checkpoint {
                name: self.out_name.clone(),
                off: c,
                block,
            });
            c += CRYPTO_CHUNK;
        }
        let mut buf = cipher[..full].to_vec();
        rarcrypt::CbcStream::new(&self.key, &chain).decrypt(&mut buf);
        // Clip the on-disk write (and the CRC) to the plaintext length;
        // the padding beyond unp only ever lives in tail_pad.
        let plain_end = (at + full as u64).min(self.unp);
        if plain_end > at {
            let n = (plain_end - at) as usize;
            w.write_at(at, &buf[..n])?;
            if self.track_plain {
                if overwrite_crc {
                    st.plain.overwrite(at, &buf[..n]);
                } else {
                    st.plain.add(at, &buf[..n]);
                }
            }
        }
        if at + full as u64 == self.cipher_len {
            st.tail_pad = buf[(self.unp - at) as usize..].to_vec();
            st.tail_done = true;
            self.events.lock_ok().push(CryptoJournalEvent::TailPad {
                name: self.out_name.clone(),
                pad: st.tail_pad.clone(),
            });
        }
        Ok(full as u64)
    }

    /// Build a standalone run for novel cipher `[at, at+cipher.len())`,
    /// decrypting whatever its own bytes allow. Neighbor seams are the
    /// caller's job (`merge_at`).
    pub(super) fn fresh_run(
        &self,
        st: &mut CryptoSt,
        w: &FileWriter,
        at: u64,
        cipher: &[u8],
    ) -> io::Result<CryptoRun> {
        let end = at + cipher.len() as u64;
        if at == 0 {
            let done = self.advance(st, w, self.iv, 0, cipher, false)?;
            return Ok(if done == 0 {
                CryptoRun {
                    end,
                    p_lo: 0,
                    p_hi: 0,
                    head: cipher.to_vec(),
                    tail: Vec::new(),
                }
            } else {
                CryptoRun {
                    end,
                    p_lo: 0,
                    p_hi: done,
                    head: Vec::new(),
                    tail: cipher[(done - 16) as usize..].to_vec(),
                }
            });
        }
        // First decryptable block needs its full predecessor block, so
        // it starts one block past the first aligned boundary in-range.
        let p_lo = at.next_multiple_of(16) + 16;
        let decryptable = end.min(self.cipher_len).saturating_sub(p_lo);
        if decryptable < 16 {
            return Ok(CryptoRun {
                end,
                p_lo: at,
                p_hi: at,
                head: cipher.to_vec(),
                tail: Vec::new(),
            });
        }
        let chain: [u8; 16] = cipher[(p_lo - 16 - at) as usize..(p_lo - at) as usize]
            .try_into()
            .unwrap();
        let done = self.advance(st, w, chain, p_lo, &cipher[(p_lo - at) as usize..], false)?;
        Ok(if done == 0 {
            CryptoRun {
                end,
                p_lo: at,
                p_hi: at,
                head: cipher.to_vec(),
                tail: Vec::new(),
            }
        } else {
            CryptoRun {
                end,
                p_lo,
                p_hi: p_lo + done,
                head: cipher[..(p_lo - at) as usize].to_vec(),
                tail: cipher[(p_lo + done - 16 - at) as usize..].to_vec(),
            }
        })
    }

    /// Merge the run ending at `mid` with the run starting at `mid`,
    /// decrypting the seam between their plaintext regions from the
    /// retained cipher slivers. No-op unless both exist.
    pub(super) fn merge_at(&self, st: &mut CryptoSt, w: &FileWriter, mid: u64) -> io::Result<()> {
        let Some((&ls, _)) = st.runs.range(..mid).next_back() else {
            return Ok(());
        };
        let l_end = st.runs[&ls].end;
        if l_end != mid || !st.runs.contains_key(&mid) {
            return Ok(());
        }
        let left = st.runs.remove(&ls).unwrap();
        let right = st.runs.remove(&mid).unwrap();
        let left_dec = left.p_hi > left.p_lo;
        let merged = if left_dec || ls == 0 {
            // Left can chain forward: from its tail's chain block, or
            // from the IV when it is the (still undecrypted) offset-0
            // run. `glue` = contiguous cipher from the chain point to the
            // end of right's retained bytes (right's whole run when
            // undecrypted, its head seam otherwise).
            let (chain, at, mut glue): ([u8; 16], u64, Vec<u8>) = if left_dec {
                (
                    left.tail[..16].try_into().unwrap(),
                    left.p_hi,
                    left.tail[16..].to_vec(),
                )
            } else {
                (self.iv, 0, left.head.clone())
            };
            glue.extend_from_slice(&right.head);
            let done = self.advance(st, w, chain, at, &glue, false)?;
            let p_hi = at + done;
            if right.decrypted() {
                debug_assert_eq!(p_hi, right.p_lo, "seam must land on right's plaintext");
                CryptoRun {
                    end: right.end,
                    p_lo: if left_dec { left.p_lo } else { 0 },
                    p_hi: right.p_hi,
                    head: left.head,
                    tail: right.tail,
                }
            } else if p_hi > at || left_dec {
                // Right was head-only cipher; we decrypted into it. Keep
                // the chain block + remainder as the new tail:
                // glue currently spans [at - chain_len, right.end) where
                // chain_len is 16 for a decrypted left (tail carried it)
                // and 0 for the IV case - normalize via glue_start.
                let glue_start = if left_dec { at - 16 } else { 0 };
                let p_hi = p_hi.max(if left_dec { left.p_hi } else { 0 });
                let (head, tail) = if p_hi > 0 {
                    let mut full = if left_dec {
                        let mut v = left.tail[..16].to_vec();
                        v.extend_from_slice(&glue);
                        v
                    } else {
                        glue
                    };
                    let ts = (p_hi - 16 - glue_start) as usize;
                    full.drain(..ts);
                    (left.head, full)
                } else {
                    // ls == 0 and still nothing decrypted (< one block
                    // total): stay head-only.
                    (glue, Vec::new())
                };
                CryptoRun {
                    end: right.end,
                    p_lo: if left_dec { left.p_lo } else { 0 },
                    p_hi,
                    head,
                    tail,
                }
            } else {
                CryptoRun {
                    end: right.end,
                    p_lo: 0,
                    p_hi: 0,
                    head: glue,
                    tail: Vec::new(),
                }
            }
        } else {
            // Left is a head-only sliver at start > 0: all of its bytes
            // are cipher. Right decrypted: only the seam
            // [p_lo_new, right.p_lo) is missing, and the concatenated
            // slivers cover it. Right undecrypted: full cipher for both
            // is in hand - rebuild as one fresh run.
            let mut combined = left.head.clone();
            combined.extend_from_slice(&right.head);
            if right.decrypted() {
                let p_lo_new = (ls.next_multiple_of(16) + 16).min(right.p_lo);
                if p_lo_new < right.p_lo {
                    let chain: [u8; 16] = combined
                        [(p_lo_new - 16 - ls) as usize..(p_lo_new - ls) as usize]
                        .try_into()
                        .unwrap();
                    let done = self.advance(
                        st,
                        w,
                        chain,
                        p_lo_new,
                        &combined[(p_lo_new - ls) as usize..],
                        false,
                    )?;
                    debug_assert_eq!(p_lo_new + done, right.p_lo);
                    CryptoRun {
                        end: right.end,
                        p_lo: p_lo_new,
                        p_hi: right.p_hi,
                        head: combined[..(p_lo_new - ls) as usize].to_vec(),
                        tail: right.tail,
                    }
                } else {
                    CryptoRun {
                        end: right.end,
                        p_lo: right.p_lo,
                        p_hi: right.p_hi,
                        head: combined,
                        tail: right.tail,
                    }
                }
            } else {
                self.fresh_run(st, w, ls, &combined)?
            }
        };
        st.runs.insert(ls, merged);
        Ok(())
    }

    /// Ingest posted cipher for `[at, at+data.len())` - the in-stream
    /// write path. Duplicate/overlapping re-feeds clip to novel
    /// sub-ranges (posted bytes for a range never change outside repair,
    /// which goes through `patch`).
    pub(super) fn ingest(&self, w: &FileWriter, at: u64, data: &[u8]) -> io::Result<()> {
        let mut st = self.st.lock_ok();
        let st = &mut *st;
        let end = at + data.len() as u64;
        // Novel sub-ranges vs existing runs.
        let mut novel: Vec<(u64, u64)> = Vec::new();
        let mut cur = at;
        for (&s, r) in st.runs.range(..end) {
            let e = r.end;
            if e <= cur {
                continue;
            }
            if s > cur {
                novel.push((cur, s.min(end)));
            }
            cur = cur.max(e);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            novel.push((cur, end));
        }
        for (s, e) in novel {
            let run = self.fresh_run(st, w, s, &data[(s - at) as usize..(e - at) as usize])?;
            st.runs.insert(s, run);
            self.merge_at(st, w, s)?;
            self.merge_at(st, w, e)?;
        }
        Ok(())
    }

    /// Whether the PLAINTEXT for cipher range `[at, at+len)` is fully on
    /// disk (decrypted regions; the final block counts once its padding
    /// is captured, since the `T` record carries it for a resume). This
    /// gates the `D` journal record: a span whose seam slivers are still
    /// RAM-held must not journal - a kill would lose them, and a resume
    /// re-encrypting the zero-filled hole would write garbage posted
    /// bytes for an article the journal claims is restored.
    pub(super) fn plain_on_disk(&self, at: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        let st = self.st.lock_ok();
        let end = at + len;
        if end > self.cipher_len {
            return false;
        }
        let mut cur = at;
        for (_, r) in st.runs.range(..end) {
            if r.p_hi <= cur || r.p_lo > cur {
                continue;
            }
            cur = r.p_hi;
            if cur >= end {
                return true;
            }
        }
        cur >= end
    }

    /// Whether every posted byte of `[at, at+len)` has arrived.
    pub(super) fn covers(&self, at: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        let st = self.st.lock_ok();
        let end = at + len;
        let mut cur = at;
        for (&s, r) in st.runs.range(..end) {
            if r.end <= cur {
                continue;
            }
            if s > cur {
                return false;
            }
            cur = r.end;
            if cur >= end {
                return true;
            }
        }
        cur >= end
    }

    /// The arrived runs clipped to `[at, at+len)`, in POSTED-byte
    /// terms - the coverage answer for verification read-back, as
    /// intervals rather than the yes/no [`Self::covers`] gives.
    pub(super) fn intervals(&self, at: u64, len: u64) -> Vec<(u64, u64)> {
        let st = self.st.lock_ok();
        let end = at + len;
        let mut out = Vec::new();
        for (&s, r) in st.runs.range(..end) {
            let a = at.max(s);
            let b = end.min(r.end);
            if a < b {
                out.push((a, b));
            }
        }
        out
    }

    /// Whether every posted byte `[0, cipher_len)` has arrived and been
    /// decrypted into one seamless run.
    pub(super) fn complete(&self) -> bool {
        let st = self.st.lock_ok();
        st.runs.len() == 1
            && st
                .runs
                .get(&0)
                .is_some_and(|r| r.end == self.cipher_len && r.p_hi == self.cipher_len)
            && (st.tail_done || self.unp == self.cipher_len)
    }

    /// Finish-time plaintext CRC verdict: Some(true)=verified,
    /// Some(false)=MISMATCH, None=nothing checkable (no stored CRC, or
    /// the file is not complete).
    pub(super) fn crc_verdict(&self) -> Option<bool> {
        let gate = self.expect_crc?;
        self.crc_verdict_with(&gate)
    }

    /// [`Self::crc_verdict`] against a gate resolved at FINISH rather
    /// than at state creation: a split entry's whole-file CRC lives on
    /// its tail piece, which may not have been mapped when the first
    /// span latched this state. Meaningful only when `track_plain` was
    /// set - otherwise the runs are empty and the verdict is None.
    pub(super) fn crc_verdict_with(&self, gate: &CrcGate) -> Option<bool> {
        let st = self.st.lock_ok();
        let got = st.plain.whole(self.unp)?;
        Some(gate.accepts(got))
    }

    /// Repair rewrite of posted cipher `[at, at+data.len())` (mapped
    /// PAR2, via patch_volume_span). Never-seen sub-ranges are ordinary
    /// posted bytes and ingest normally; sub-ranges already decrypted
    /// rewrite coherently: CBC locality means patching cipher block X
    /// changes plaintext at X and X+16 only, so the rewrite re-decrypts
    /// the patched blocks plus the one following block, refreshes the
    /// checkpoints and stash slivers the patch overlaps, and overwrites
    /// the CRC runs (the stale-CRC-across-repair problem CrcRuns solves
    /// for the outer volumes).
    pub(super) fn patch(&self, w: &FileWriter, at: u64, data: &[u8]) -> io::Result<()> {
        let holes = {
            let mut st = self.st.lock_ok();
            self.patch_locked(&mut st, w, at, data)?
        };
        // Ranges nobody had yet are ordinary posted bytes wherever they
        // come from - ingest them (re-locks per range).
        for (s, e) in holes {
            self.ingest(w, s, &data[(s - at) as usize..(e - at) as usize])?;
        }
        Ok(())
    }

    pub(super) fn patch_locked(
        &self,
        st: &mut CryptoSt,
        w: &FileWriter,
        at: u64,
        data: &[u8],
    ) -> io::Result<Vec<(u64, u64)>> {
        let end = at + data.len() as u64;
        // 1. Splice patch bytes into any stash slivers they overlap -
        // stashes ARE posted bytes and repair redefines posted truth.
        // This runs before the region rewrite so that rewrite's chain
        // reads see the repaired bytes.
        for (&rs, run) in st.runs.iter_mut() {
            let head_at = rs;
            let tail_at = run.p_hi.saturating_sub(16);
            for (seg_at, is_head) in [(head_at, true), (tail_at, false)] {
                let stash = if is_head {
                    &mut run.head
                } else {
                    &mut run.tail
                };
                if stash.is_empty() {
                    continue;
                }
                let se = seg_at + stash.len() as u64;
                let lo = at.max(seg_at);
                let hi = end.min(se);
                if lo < hi {
                    stash[(lo - seg_at) as usize..(hi - seg_at) as usize]
                        .copy_from_slice(&data[(lo - at) as usize..(hi - at) as usize]);
                }
            }
        }
        // 2. Rewrite affected plaintext block-coherently. A patched
        // cipher block changes the plaintext at itself and at the block
        // after it, and a patch that ends inside a stash changes the
        // chain into the next decrypted block - one extra block of
        // margin on each side is a superset of every affected block, and
        // rewriting an UNaffected block is a byte-identical no-op.
        let regions: Vec<(u64, u64)> = st
            .runs
            .values()
            .filter(|r| r.p_hi > r.p_lo)
            .map(|r| (r.p_lo, r.p_hi))
            .collect();
        for (p_lo, p_hi) in regions {
            let lo = p_lo.max((at & !15).saturating_sub(16));
            let hi = p_hi.min(end.next_multiple_of(16) + 16).min(self.cipher_len);
            if lo >= hi {
                continue;
            }
            let mut chain = self.iv;
            if lo > 0 {
                self.read_posted_locked(st, w, lo - 16, &mut chain)?;
            }
            let mut fresh = vec![0u8; (hi - lo) as usize];
            self.read_posted_locked(st, w, lo, &mut fresh)?;
            let dlo = at.max(lo);
            let dhi = end.min(hi);
            if dlo < dhi {
                fresh[(dlo - lo) as usize..(dhi - lo) as usize]
                    .copy_from_slice(&data[(dlo - at) as usize..(dhi - at) as usize]);
            }
            self.advance(st, w, chain, lo, &fresh, true)?;
        }
        // 3. Report the never-seen sub-ranges for ingest by the caller.
        let mut holes: Vec<(u64, u64)> = Vec::new();
        let mut cur = at;
        for (&s, r) in st.runs.range(..end) {
            if r.end <= cur {
                continue;
            }
            if s > cur {
                holes.push((cur, s.min(end)));
            }
            cur = cur.max(r.end);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            holes.push((cur, end));
        }
        Ok(holes)
    }

    /// Read POSTED bytes for cipher range `[at, at+out.len())`: seam and
    /// tail slivers come from the retained cipher, decrypted regions are
    /// re-encrypted from the nearest chain anchor (checkpoint, run
    /// anchor, or the IV). Errors if any byte has not arrived.
    pub(super) fn read_posted(&self, w: &FileWriter, at: u64, out: &mut [u8]) -> io::Result<()> {
        let st = self.st.lock_ok();
        self.read_posted_locked(&st, w, at, out)
    }

    pub(super) fn read_posted_locked(
        &self,
        st: &CryptoSt,
        w: &FileWriter,
        at: u64,
        out: &mut [u8],
    ) -> io::Result<()> {
        let end = at + out.len() as u64;
        if end > self.cipher_len {
            return Err(nofile());
        }
        let mut pos = at;
        while pos < end {
            let (&rs, run) = st.runs.range(..=pos).next_back().ok_or_else(nofile)?;
            if run.end <= pos {
                return Err(nofile());
            }
            let stop = end.min(run.end);
            // Head sliver (or the whole run when undecrypted).
            let head_end = if run.decrypted() { run.p_lo } else { run.end };
            if pos < head_end {
                let take = stop.min(head_end);
                let src = &run.head[(pos - rs) as usize..(take - rs) as usize];
                out[(pos - at) as usize..(take - at) as usize].copy_from_slice(src);
                pos = take;
                continue;
            }
            // Tail sliver: cipher [p_hi - 16, end) is retained verbatim.
            if run.p_hi > run.p_lo && pos >= run.p_hi {
                let tail_at = run.p_hi - 16;
                let take = stop;
                let src = &run.tail[(pos - tail_at) as usize..(take - tail_at) as usize];
                out[(pos - at) as usize..(take - at) as usize].copy_from_slice(src);
                pos = take;
                continue;
            }
            // Decrypted region [p_lo, p_hi): re-encrypt from the nearest
            // anchor at or below the aligned start.
            let want_lo = pos & !15;
            let want_hi = stop.min(run.p_hi).next_multiple_of(16).min(self.cipher_len);
            let (chain, mut cpos): ([u8; 16], u64) = {
                let ck = (want_lo / CRYPTO_CHUNK) * CRYPTO_CHUNK;
                let mut best: Option<(u64, [u8; 16])> = None;
                let mut c = ck;
                while c >= run.p_lo.max(CRYPTO_CHUNK) {
                    if c > run.p_lo
                        && let Some(b) = st.checkpoints.get(&c)
                    {
                        best = Some((c, *b));
                        break;
                    }
                    if c < CRYPTO_CHUNK {
                        break;
                    }
                    c -= CRYPTO_CHUNK;
                }
                match best {
                    Some((c, b)) if c >= run.p_lo => (b, c),
                    _ if run.p_lo == 0 => (self.iv, 0),
                    _ => (
                        run.head[run.head.len() - 16..].try_into().unwrap(),
                        run.p_lo,
                    ),
                }
            };
            // Walk plaintext from the anchor to the requested window,
            // encrypting as we go; emit the requested slice.
            let mut buf = vec![0u8; 4096.min((want_hi - cpos) as usize).max(16)];
            let mut enc = rarcrypt::CbcEncStream::new(&self.key, &chain);
            while cpos < want_hi {
                let n = buf.len().min((want_hi - cpos) as usize);
                let block = &mut buf[..n];
                self.read_plain_block(st, w, cpos, block)?;
                enc.encrypt(block);
                let lo = cpos.max(pos);
                let hi = (cpos + n as u64).min(stop);
                if lo < hi {
                    out[(lo - at) as usize..(hi - at) as usize]
                        .copy_from_slice(&block[(lo - cpos) as usize..(hi - cpos) as usize]);
                }
                cpos += n as u64;
            }
            pos = stop.min(run.p_hi);
            if pos < stop && pos < run.end {
                continue; // tail sliver of the same run serves the rest
            }
        }
        Ok(())
    }

    /// Plaintext for `[at, at+block.len())` (16-aligned, within the
    /// decrypted region): disk bytes below `unp`, tail padding beyond.
    pub(super) fn read_plain_block(
        &self,
        st: &CryptoSt,
        w: &FileWriter,
        at: u64,
        block: &mut [u8],
    ) -> io::Result<()> {
        let end = at + block.len() as u64;
        let disk_end = end.min(self.unp);
        if disk_end > at {
            w.read_at(&mut block[..(disk_end - at) as usize], at)?;
        }
        if end > self.unp {
            if !st.tail_done {
                return Err(nofile());
            }
            let pad_off = (at.max(self.unp) - self.unp) as usize;
            let need = (end - at.max(self.unp)) as usize;
            block[(at.max(self.unp) - at) as usize..]
                .copy_from_slice(&st.tail_pad[pad_off..pad_off + need]);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Plaintext-once (in-stream decrypt): encrypted store entries decrypt at
// article-write time and the ciphertext never touches disk. 1x disk, no
// finish pass, no temp/barrier - see research/encrypted-store-plaintext-
// once-scope-2026-07-26.md. Since TODO 27 phase 3 there is no other
// route: an output that cannot take this one assembles posted ciphertext
// and DEMOTES at finish, exactly where the mapper used to send it.
//
// Every consumer of posted bytes is served without ciphertext on disk
// because CBC is invertible per block: the plaintext on disk is always
// D(wire cipher) - even for wire-DAMAGED regions - so re-encrypting it
// reproduces the posted bytes exactly, damage included. That is also why
// an UNVERIFIED password may decrypt in-stream (TODO 27 phase 3): a wrong
// key makes the plaintext garbage, but E_k(D_k(c)) = c for any k, so the
// shim still rebuilds byte-exact volumes for the demote that garbage
// earns. Chain state is one 16-byte cipher block, so periodic
// checkpoints captured from the wire make re-encryption seekable.
// ---------------------------------------------------------------------------

/// Increment A: how often the candidate-password probe re-runs while
/// slots sit parked. The sidecar carrying the password usually lands
/// within the head round, seconds after the archive blocks; probing on
/// this cadence (piggybacked on span arrivals, off the routing lock)
/// re-keys the mapper while the holds are still small. The hook itself
/// dedupes candidates, so a quiet directory costs a directory scan, not
/// repeated KDFs.
pub(super) const PW_REPROBE_EVERY: std::time::Duration = std::time::Duration::from_millis(750);

/// Every check field the plaintext-once route decision reads, resolved
/// across a whole inner FILE.
///
/// The route is latched per OUTPUT name (`crypto_files`) by whichever
/// fragment asks first, so a decision that reads its check fields off the
/// fragment in front of the writer can latch on a head and disagree with
/// its own tail. See [`Extractor::instream_decrypt_allowed`].
struct FileChecks {
    /// Some piece of the file refuses the plaintext-once route: it is
    /// unencrypted, or it states a plaintext digest this build cannot
    /// compute with no CRC32 beside it (`rar a -htb`, whose output
    /// nothing here could adjudicate).
    ///
    /// An UNPROVABLE password - RAR4, or a check-less or malformed-check
    /// RAR5 record - is deliberately NOT a veto since TODO 27 phase 3.
    /// It was one while a finish pass existed to adjudicate the
    /// ciphertext; with that pass gone, vetoing would only strand the
    /// file. Such a set decrypts in-stream and is adjudicated at finish
    /// against the whole-file checksum instead, demoting rather than
    /// failing when it misses - see [`CryptoState::pw_verified`].
    vetoed: bool,
    /// (slot, entry) of the head piece - `split_before` clear, the record
    /// whose IV starts the stream and which [`Extractor::crypto_for`]
    /// keys the whole file with. `None` while the head volume's headers
    /// are still in flight.
    head: Option<(usize, usize)>,
}

impl Extractor {
    /// Drain the chain's pending resume-journal crypto events (`E`/`K`/
    /// `T` facts - see [`CryptoJournalEvent`]). The caller writes them to
    /// the journal alongside the `D` placement records.
    pub fn drain_crypto_events(&self) -> Vec<CryptoJournalEvent> {
        let sink = self.inner.lock_ok().crypto_events.clone();
        let mut ev = sink.lock_ok();
        std::mem::take(&mut *ev)
    }

    /// Whether every plaintext-once fragment of a `PlacedCrypto` span is
    /// physically on disk (seams resolved, tail padding captured). The
    /// journal writer holds `D` records until this turns true - usually
    /// one neighboring article later - because a record for RAM-held
    /// slivers would survive a kill that the bytes did not.
    pub fn crypto_span_on_disk(&self, frags: &[Frag]) -> bool {
        frags.iter().all(|f| match self.find_crypto(&f.file) {
            Some(cs) => cs.plain_on_disk(f.file_off, f.len),
            None => true,
        })
    }

    /// Which fragments of a span landed in plaintext-once files. Rides
    /// into the `D` record so a resume knows which fragments restore by
    /// re-encryption and which are ordinary copies - a crypto fragment
    /// whose facts are missing must fail, never fall through to a copy.
    pub fn crypto_frag_mask(&self, frags: &[Frag]) -> Vec<bool> {
        frags
            .iter()
            .map(|f| self.find_crypto(&f.file).is_some())
            .collect()
    }

    pub(super) fn find_crypto(&self, name: &str) -> Option<Arc<CryptoState>> {
        let inner = self.inner_read();
        if let Some(cs) = inner.crypto_files.get(name) {
            return Some(cs.clone());
        }
        let child = inner.child.clone();
        drop(inner);
        child.and_then(|c| c.find_crypto(name))
    }

    /// Increment A: park a password-blocked slot instead of demoting it,
    /// while the candidate probe may still turn up the password. Returns
    /// true when the span was taken (held); false hands the blocker back
    /// to the demote path unchanged.
    ///
    /// Eligible only when a probe hit could actually rescue the slot:
    /// the hook is installed (root level - children never get one), the
    /// blocker is password-shaped rather than structural, and the
    /// archive carries a WELLFORMED stored check - without one no
    /// candidate can ever verify (that shape needs the tweaked-MAC gate,
    /// Increment B) and awaiting would just burn budget until finish.
    ///
    /// Held spans stay fully live: `read_at`/`covered` serve holds, so
    /// settle read-back and mapped PAR2 repair see the bytes; a repair
    /// span for a parked slot parks BEHIND the original in `holds`, and
    /// the ordered re-feed keeps last-writer-wins intact.
    pub(super) fn try_pw_await(
        &self,
        inner: &mut Inner,
        slot: usize,
        b: &MapBlocker,
        offset: u64,
        data: &[u8],
    ) -> io::Result<bool> {
        if inner.slots[slot].pw_await.is_none() {
            // First span since the blocker fired: decide eligibility once.
            if self.depth != 0
                || inner.pw_probe.is_none()
                || inner.protect_sources
                || !matches!(inner.slots[slot].mode, SlotMode::Rar)
            {
                return Ok(false);
            }
            let probeable = match b {
                // Headers opaque, or the start password failed its check:
                // the type-4 block's params are captured either way.
                // Encrypted store entries with no password at all: the
                // exact shape a found candidate rescues. (Compressed
                // entries return NotStore before the encryption check, so
                // this variant is store-method by construction; a RAR4
                // encrypted entry also lands here but has no RAR5 crypt
                // params, which the wellformed-check gate below filters.)
                MapBlocker::EncryptedHeaders
                | MapBlocker::BadPassword
                | MapBlocker::EncryptedNoPassword => true,
                // "Compressed or encrypted entries": only the encrypted
                // STORE flavor is rescuable - a password makes it
                // mappable. A compressed entry stays blocked with the
                // password in hand, so it goes to the chase/demote path.
                MapBlocker::NotStore => inner.slots[slot].mapper.as_ref().is_some_and(|m| {
                    m.entries
                        .last()
                        .is_some_and(|e| e.encrypted && matches!(e.method, Method::Store))
                }),
                _ => return Ok(false),
            };
            let has_check = probeable
                && inner.slots[slot]
                    .mapper
                    .as_ref()
                    .and_then(|m| m.crypt_probe_params())
                    .and_then(|p| p.check)
                    .is_some_and(|c| crate::rarcrypt::check_is_wellformed(&c));
            if !has_check {
                return Ok(false);
            }
            inner.slots[slot].pw_await = Some(blocker_reason(b));
            inner.pw_probe_due = true;
        }
        // Park the span. The header-region part of it is already in the
        // stash (retain_header_bytes ran before the blocker arm), so that
        // overlap is briefly double-charged - headers only, released with
        // whichever copy drops first, and both the fallback materialize
        // and a re-keyed re-parse tolerate the duplicate bytes.
        inner.budget.add(data.len());
        inner.slots[slot]
            .holds
            .push((offset, HoldSpan::Ram(data.to_vec())));
        // Parked ciphertext is cold until a probe hit or finish, so it
        // pages to scratch beyond a small window instead of riding RAM
        // to the holds cap (see `pw_await_spill`). A probe hit re-feeds
        // paged spans off disk through `reclaim_span`, and the finish
        // demote materializes them into volumes the same way.
        if inner.budget.len() > pw_await_spill(inner.budget.cap()) {
            self.page_pw_holds(inner, slot);
        }
        if inner.budget.over() && !self.page_out_holds(inner) {
            // Same arbiter as every other hold. Demote with the ORIGINAL
            // blocker's reason so the finish ladder's remediation (the
            // "encrypted"/"password" keying) is exactly what it would
            // have been without the wait.
            let reason = inner.slots[slot].pw_await.take().unwrap();
            self.fallback_slot_or_group(inner, slot, reason)?;
        }
        Ok(true)
    }

    /// Run the candidate probe for parked slots, off the routing lock
    /// (the hook does PBKDF2 work). `force` ignores the re-probe cadence
    /// - the finish path's last chance, when every sidecar has landed.
    /// On a hit the password applies under the lock and the parked slots
    /// re-key; the re-feeds may queue child forwards, so this flushes
    /// them like every other public entry point that re-feeds holds.
    pub(super) fn flush_pw_probe(&self, force: bool) -> io::Result<()> {
        let (hook, probes) = {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            let Some(hook) = inner.pw_probe.clone() else {
                return Ok(());
            };
            let due = force
                || inner.pw_probe_due
                || inner
                    .pw_probe_last
                    .is_none_or(|t| t.elapsed() >= PW_REPROBE_EVERY);
            if !due {
                return Ok(());
            }
            let mut probes: Vec<crate::rar::CryptProbe> = Vec::new();
            for s in &inner.slots {
                if s.pw_await.is_none() {
                    continue;
                }
                if let Some(p) = s.mapper.as_ref().and_then(|m| m.crypt_probe_params()) {
                    // One salt per archive; a multi-set job contributes
                    // one probe per distinct salt.
                    if !probes.contains(&p) {
                        probes.push(p);
                    }
                }
            }
            if probes.is_empty() {
                return Ok(());
            }
            inner.pw_probe_due = false;
            inner.pw_probe_last = Some(std::time::Instant::now());
            (hook, probes)
        };
        for p in &probes {
            if let Some(pw) = hook(p) {
                self.apply_probed_password(&pw)?;
                self.flush_pending_fwd()?;
                break;
            }
        }
        Ok(())
    }

    /// A probe candidate VERIFIED against some parked archive: install
    /// it and re-key every parked slot whose own stored check accepts it
    /// (two encrypted sets in one job may want different passwords - the
    /// others keep waiting for a later candidate). Re-keying is a fresh
    /// mapper plus a re-feed of everything retained; the parse runs
    /// exactly as if the password had been known at classification.
    pub(super) fn apply_probed_password(&self, pw: &str) -> io::Result<()> {
        let mut g = self.inner.lock_ok();
        let inner = &mut *g;
        inner.password = Some(std::sync::Arc::from(pw));
        for slot in 0..inner.slots.len() {
            if inner.slots[slot].pw_await.is_none() {
                continue;
            }
            let verified = inner.slots[slot]
                .mapper
                .as_ref()
                .and_then(|m| m.crypt_probe_params())
                .is_some_and(|p| p.verify(pw) == crate::rar::PwVerdict::Verified);
            if !verified {
                continue;
            }
            inner.slots[slot].pw_await = None;
            // TODO 211 (b): a split head's mapper spans the joined
            // volume - re-key it at the size it already knows, not
            // the part's.
            let size = match inner.slots[slot].mapper.as_ref() {
                Some(m) if inner.slots[slot].split_head.is_some() => m.volume_size(),
                _ => inner.slots[slot].size,
            };
            // Same base as the mapper being replaced: an SFX volume's
            // archive still starts behind its stub once keyed.
            let base = inner.slots[slot]
                .mapper
                .as_ref()
                .map_or(0, |m| m.archive_base());
            inner.slots[slot].mapper = Some(VolumeMapper::with_password_at(
                size,
                inner.password.clone(),
                base,
            ));
            // Feed the stash back through the keyed mapper. Uncharge
            // first: the re-parse re-stashes whatever is still header
            // (and maps the rest), so leaving the old charge would
            // double-bill every stashed byte.
            // The stash is OUT of the slot now, so a reclaim or a
            // re-parse that fails partway must uncharge every span it
            // never visited: dropping the rest of the vec frees the
            // memory but leaves the budget - and the scratch reservation
            // - charged for it, and the extractor then demotes on a
            // ceiling it is no longer using. Same shape as the chase and
            // 7z attach paths.
            let mut rest = std::mem::take(&mut inner.slots[slot].header_spans).into_iter();
            let mut failed = None;
            for (off, span) in rest.by_ref() {
                let fed = match Self::reclaim_span(inner, span) {
                    Ok(bytes) => self.rar_span(inner, slot, off, &bytes, None, false, None),
                    Err(e) => Err(e),
                };
                if let Err(e) = fed {
                    failed = Some(e);
                    break;
                }
            }
            if let Some(e) = failed {
                for (_, span) in rest {
                    Self::uncharge_span(inner, &span);
                }
                return Err(e);
            }
            self.drain_holds(inner, slot)?;
            info!(
                target: "password",
                "🔑 candidate password unlocked {} in-stream",
                inner.slots[slot].name
            );
        }
        Ok(())
    }

    /// Finish-time resolution for Increment A: one forced probe (every
    /// sidecar is on disk by now), then any slot still parked demotes
    /// with its original blocker reason - the exact outcome the await
    /// deferred, so the report and the ladder see nothing new.
    pub(super) fn resolve_pw_awaits(&self) -> io::Result<()> {
        self.flush_pw_probe(true)?;
        {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            for slot in 0..inner.slots.len() {
                if let Some(reason) = inner.slots[slot].pw_await.take() {
                    self.fallback_slot_or_group(inner, slot, reason)?;
                }
            }
        }
        self.flush_pending_fwd()
    }

    /// May this encrypted entry decrypt at WRITE time (plaintext-once),
    /// or must it assemble ciphertext and demote at finish?
    ///
    /// A wrong password writes plaintext-shaped garbage into the output
    /// file, and that file is supposed to BE the posted volume bytes -
    /// so this used to demand a stored check that PROVES the password
    /// first, and sent a check-less (or malformed-check, or RAR4) set
    /// down the ciphertext route for the finish pass to adjudicate.
    /// Phase 2's re-encrypt shim retired that requirement: CBC is
    /// invertible under ANY key, so E_k(D_k(c)) = c and the garbage
    /// re-encrypts to byte-exact volumes just as real plaintext does.
    /// The proof therefore only decides what a checksum MISS means -
    /// damage, or the wrong password - which is
    /// [`CryptoState::pw_verified`] and `verify_encrypted_outputs`'s
    /// job, not this gate's. What still vetoes is an output nothing can
    /// adjudicate at all (`rar a -htb`: a digest this build cannot
    /// compute, with no CRC32 beside it); that one assembles ciphertext
    /// and its group demotes to the disk path, which can check it.
    ///
    /// ONE ANSWER PER FILE, and never veto-then-allow. `crypto_files`
    /// caches the route by OUTPUT name and the first fragment to ask
    /// latches it for the whole file, so fragments that disagree would
    /// route half an output each way - and a half-plaintext file cannot
    /// be turned back into byte-exact volumes by the fallback shim. Two
    /// rules keep that unreachable:
    ///
    /// 1. Every check field consulted here is resolved across the whole
    ///    file by [`FileChecks`], which walks every mapped piece in the
    ///    group. None is read off the fragment in front of the writer.
    ///    Only the tail piece carries the whole-file checks, so reading
    ///    them off a head answered "allowed" for a split hash-only set
    ///    (Codex sweep 12 Aug F2) - and the same trap waits for any
    ///    per-file check field added later.
    /// 2. An output that already holds bytes with no `CryptoState`
    ///    behind it holds CIPHERTEXT, and may never latch plaintext-once
    ///    afterwards. Rule 1 makes the fields agree; rule 2 is what makes
    ///    a MIXED output impossible even where they cannot. It covers
    ///    what rule 1 does not: the live password cell, which a
    ///    mid-download re-key can flip from veto to allow under a file
    ///    already assembling ciphertext, and whatever the next field
    ///    turns out to be.
    ///
    /// What the two rules do NOT buy is the same ROUTE in every arrival
    /// order: a fact that has not arrived cannot veto, so a head mapped
    /// alone may latch plaintext-once for a file whose tail would have
    /// refused, and the same set fed tail-first assembles ciphertext.
    /// Both routes are whole-file, both are adjudicated at finish, and
    /// both reach the same published bytes.
    /// Route identity would mean holding every encrypted span until the
    /// last volume mapped, which is not a trade this path can make
    /// (TODO 158 item 2).
    ///
    /// Across a RESTART the route must not move either, and there the
    /// reason is the journal rather than the fallback: a resumed run
    /// rewrites every byte a prior run left (replay or refetch), but the
    /// replay never re-records, so an output whose route flipped holds
    /// bytes of one domain under records describing the other, and the
    /// resume after that restores garbage (TODO 158 item 2, closed 22
    /// Aug 2026). Both halves of rule 2 were empty on a resume - the
    /// latch is per process and the counter started at zero - so the
    /// journal's own records now seed them: a wire output is latched
    /// ciphertext before any span arrives (`seed_resumed_routes`), and a
    /// plaintext-once output with live `D` records is held to
    /// plaintext-once, re-latched only on the head record its `E` fact
    /// was taken from and a password that proves against its check;
    /// short of that the write is refused outright (`route_dest`'s
    /// stamp site), which is what "the route cannot be established"
    /// has to mean when guessing either way corrupts.
    pub(super) fn instream_decrypt_allowed(
        inner: &Inner,
        slot: usize,
        ei: usize,
        w: &FileWriter,
    ) -> bool {
        // Rule 2, and first because it is the cheapest test here and the
        // only one that still holds for a check field this function does
        // not know about yet. Bytes under an output with no crypto state
        // are ciphertext: the plaintext-once writes all go through one.
        //
        // TWO halves. The route latch is the authoritative one: it is
        // stamped at enqueue under the routing lock, where the decision
        // is actually made. The written() counter lags it - pwrites run
        // after the lock drops, so a routed-but-unwritten ciphertext
        // job was invisible here, and a span arriving in that window
        // (a live password candidate landing mid-file) latched
        // plaintext-once over it: a mixed output (Codex sweep 13 Aug
        // C1). The counter stays as the belt - it is what covers
        // resume, where bytes from a prior run sit under an output the
        // latch never saw.
        let out_name = w.path.file_name().map(|k| k.to_string_lossy());
        if out_name
            .as_deref()
            .is_some_and(|k| inner.ciphertext_files.contains(k))
        {
            return false;
        }
        // A resumed plaintext-once output: the decision was made by the
        // run that wrote it, and this run may only confirm it. The
        // arrival-order veto below is skipped on purpose - a tail that
        // would have refused the route cannot un-write the plaintext
        // already on disk, and the only alternative is the mix the
        // stamp site refuses. The HEAD record still has to be the one
        // the `E` fact names and the password still has to prove
        // against it, or the stream would be keyed differently from the
        // bytes the restore re-encrypted.
        let resumed = out_name
            .as_deref()
            .and_then(|k| inner.resumed_plaintext.get(k).copied());
        if w.written() > 0 && resumed.is_none() {
            return false;
        }
        let Some(pw) = inner.password.as_ref() else {
            return false;
        };
        let Some(m) = inner.slots[slot].mapper.as_ref() else {
            return false;
        };
        let Some(e) = m.entries.get(ei) else {
            return false;
        };
        let f = Self::file_checks(inner, slot, &e.name);
        if f.vetoed && resumed.is_none() {
            return false;
        }
        // The head piece's record is what `crypto_for` keys the whole
        // stream with, so the head's check is the one that has to verify.
        // While the head volume's headers are still in flight there is
        // nothing to latch onto at all: `crypto_for` returns None and the
        // span holds, which is what stops a continuation piece from
        // committing the file to a route its head never answered for.
        let Some((si, hi)) = f.head else {
            return true;
        };
        let Some(c) = inner.slots[si]
            .mapper
            .as_ref()
            .and_then(|m| m.entries.get(hi))
            .and_then(|e| e.crypt.as_ref())
        else {
            return false;
        };
        if let Some((salt, iv)) = resumed
            && !c.rar5().is_some_and(|r| r.salt == salt && r.iv == iv)
        {
            return false;
        }
        // One derive, for the head alone, because this runs per SPAN:
        // RAR4's schedule is 0x40000 SHA-1 rounds, and while the cache
        // makes a repeat cheap, an archive with a fresh salt per piece
        // would pay it again and again under the routing lock. A derive
        // that fails at all is a hostile RAR5 iteration count - no key,
        // so nothing to decrypt with either way.
        let Some(keys) = c.derive(pw) else {
            return false;
        };
        // A RESUMED plaintext-once file must still prove the password:
        // the restore re-encrypted local plaintext with it, and a
        // different password would have keyed those bytes differently
        // from this run's. Only a provable file is ever recorded as one
        // (`crypto_for` journals no `E` without a wellformed check), so
        // this is a belt on the seed rather than a new rule.
        if resumed.is_some() {
            return c.check_verifies(&keys);
        }
        // Fresh: a check that CAN prove the password must prove it - the
        // mapper already refuses one that rejects, so reaching here with
        // a wellformed check and no match would mean the two disagree.
        // No usable check just means the verdict waits for finish.
        !c.rar5()
            .and_then(|r| r.check)
            .is_some_and(|chk| crate::rarcrypt::check_is_wellformed(&chk))
            || c.check_verifies(&keys)
    }

    /// Seed the routes a resumed run inherits from its journal - see
    /// `Restored::wire_outputs` / `plaintext_outputs` in `journal.rs` and
    /// the restart paragraph on [`Self::instream_decrypt_allowed`]. Must
    /// run before the first span is fed: the wire latch is consulted at
    /// every encrypted span's enqueue, and a span that routed first would
    /// have decided the route on its own.
    pub fn seed_resumed_routes(
        &self,
        wire: &HashMap<String, u64>,
        plaintext: &HashMap<String, ([u8; 16], [u8; 16])>,
    ) {
        let mut inner = self.inner.lock_ok();
        for (name, &bytes) in wire {
            inner.ciphertext_files.insert(name.clone());
            *inner.resumed_wire.entry(name.clone()).or_default() += bytes;
        }
        for (name, &keys) in plaintext {
            inner.resumed_plaintext.insert(name.clone(), keys);
        }
    }

    /// Resolve [`FileChecks`] for inner file `name` over `slot`'s group.
    ///
    /// Every mapped piece is consulted, because the whole-file checks
    /// live on the tail piece alone and the answer has to be the same for
    /// every fragment of the file - see the caller. Pieces that have not
    /// arrived yet cannot contribute, which is why
    /// `verify_encrypted_outputs` re-asks once the set is complete.
    ///
    /// The digest veto reads the TAIL piece (`split_after` clear) and
    /// only it, because that is the piece whose stored value covers the
    /// whole plaintext - an earlier piece's CRC32 describes its own
    /// volume alone. `any digest && no CRC32 anywhere` was wrong for
    /// that reason (a head's CRC32 excused a tail saying "BLAKE2sp, no
    /// CRC32"); so was per-PIECE, which it was until TODO 27 phase 3 -
    /// that form vetoed a file whose HEAD states a digest and whose tail
    /// states a CRC32, and while a finish decrypt existed to adjudicate
    /// the ciphertext that cost nothing but a route. With the finish
    /// pass gone a veto is a DEMOTE, so vetoing an adjudicable file
    /// sends a perfectly good set to the disk path. A tail carrying both
    /// - the `rar a -htb` set that also stores a CRC32 - is fully
    /// adjudicable and routes one-pass either way.
    fn file_checks(inner: &Inner, slot: usize, name: &str) -> FileChecks {
        let mut out = FileChecks {
            vetoed: false,
            head: None,
        };
        let mut scan = |si: usize, m: &VolumeMapper| {
            for (ei, e) in m.entries.iter().enumerate() {
                if e.name != name || e.is_dir {
                    continue;
                }
                // An FHEXTRA_HASH digest (BLAKE2sp, `rar a -htb`) with no
                // CRC32 beside it has nothing the finish pass can
                // adjudicate: `crc_gate` returns None, so `crc_verdict` is
                // None rather than Some(false), and the plaintext is
                // published with NO integrity check at all.
                // `verify_inner_crcs` already refuses the unencrypted twin
                // of this shape for the same reason - its gate is `Store
                // && !encrypted`, so an encrypted entry never reached it.
                // Assembling ciphertext instead costs nothing: the volumes
                // stay byte-exact and can still materialize, and the disk
                // path verifies the BLAKE2sp properly
                // (`verify_integrity_with_keys`). nzbkit has no BLAKE2sp of
                // its own, so verifying in place is not an option here.
                let uncheckable = !e.split_after && e.hash.is_some() && e.file_crc.is_none();
                out.vetoed |= !e.encrypted || uncheckable;
                if !e.split_before && out.head.is_none() {
                    out.head = Some((si, ei));
                }
            }
        };
        match inner.slots[slot]
            .group
            .as_ref()
            .and_then(|gk| inner.groups.get(gk))
        {
            Some(g) => {
                for &si in &g.slots {
                    if let Some(m) = inner.slots[si].mapper.as_ref() {
                        scan(si, m);
                    }
                }
            }
            None => {
                if let Some(m) = inner.slots[slot].mapper.as_ref() {
                    scan(slot, m);
                }
            }
        }
        out
    }

    pub(super) fn crypto_for(
        inner: &mut Inner,
        slot: usize,
        ei: usize,
        w: &Arc<FileWriter>,
    ) -> Option<Arc<CryptoState>> {
        // Borrowed lookup first: the state exists for every span after
        // the first, and owning the key cost a String per encrypted span.
        let key = w.path.file_name()?.to_string_lossy();
        if let Some(cs) = inner.crypto_files.get(key.as_ref()) {
            return Some(cs.clone());
        }
        let key = key.into_owned();
        let name = Self::entry_name(inner, slot, ei);
        // The head piece (split_before == false) of this file - it may
        // live in another volume's mapper within the same group. Found by
        // the SAME walk the route gate uses, so the record that keys the
        // stream is the record whose check the gate verified; a slot-first
        // preference here and a group-order one there could pick two
        // different heads for one output.
        let (c, unp, file_crc, split_after) =
            Self::file_checks(inner, slot, name)
                .head
                .and_then(|(si, hi)| {
                    let e = inner.slots[si].mapper.as_ref()?.entries.get(hi)?;
                    Some((e.crypt.clone()?, e.unpacked_size, e.file_crc, e.split_after))
                })?;
        let pw = inner.password.as_ref()?;
        let keys = c.derive(pw)?;
        // Whether the stored check PROVED this password before a byte was
        // decrypted. Not a precondition since TODO 27 phase 3 (RAR4 and
        // check-less RAR5 sets take this route too) - it decides what a
        // finish checksum miss means, and whether the run may journal
        // resume facts at all.
        let pw_verified = c.check_verifies(&keys);
        // Only a single-piece entry's stored CRC covers the whole
        // plaintext. A tweaked checksum is keyed rather than useless -
        // the gate folds the computed CRC before comparing (Increment
        // B). A SPLIT entry's whole-file CRC lives on its tail piece,
        // which may not be mapped yet - no gate here, but the plain runs
        // still compose (`track_plain`) so the finish verdict can
        // adjudicate against the tail's stored value once every volume
        // is in.
        let expect_crc = crc_gate(file_crc.filter(|_| !split_after), &c, &keys);
        let cs = Arc::new(CryptoState::new(
            keys.aes.clone(),
            keys.iv,
            unp,
            expect_crc,
            split_after,
            pw_verified,
            key.clone(),
            inner.crypto_events.clone(),
        ));
        // Resume facts, and ONLY for a file a resumed run could prove the
        // password of: the `E` grammar is RAR5-shaped (RAR4's 8-byte salt
        // and SHA-1 schedule do not fit it), and a restore that
        // re-encrypted local plaintext under an unproven key would post
        // bytes nobody vouched for. Journalling nothing is the safe
        // answer, not a lossy one: the `D` records still ride along, and
        // a `D` whose `E` is missing simply refetches its article
        // (`journal_d_without_e_refetches`), which is what this file
        // would have done before it took this route at all.
        if pw_verified && let Some(r5) = c.rar5() {
            inner
                .crypto_events
                .lock_ok()
                .push(CryptoJournalEvent::Params {
                    name: key.clone(),
                    salt: r5.salt,
                    lg2: r5.lg2_count,
                    iv: r5.iv,
                    unp,
                    check: r5.check,
                });
        }
        inner.crypto_files.insert(key, cs.clone());
        Some(cs)
    }

    /// Read-side lookup: the in-stream decrypt state behind a writer,
    /// if that output is plaintext-once.
    pub(super) fn crypto_of(inner: &Inner, w: &FileWriter) -> Option<Arc<CryptoState>> {
        let key = w.path.file_name()?.to_string_lossy();
        inner.crypto_files.get(key.as_ref()).cloned()
    }
}

// The finish-time verdict on every encrypted output, hoisted out when the
// legacy decrypt pass it was gathered for reached the size gate's
// 500-line function ceiling.
#[path = "crypto_decrypt.rs"]
mod crypto_decrypt;

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod crypto_tests;
