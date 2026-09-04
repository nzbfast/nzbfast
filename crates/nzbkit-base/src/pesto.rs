//! The pesto uploader-family adapter (TODO 131, red-team 5a): the pure
//! half of the tiny-PAR2 naming rung - message-id grammar, the
//! counter/length linking math, and the 16k-MD5 payload gate. The
//! database half lives in `index::pesto`; the wire half in the daemon's
//! probe worker.
//!
//! The pesto poster tool fully obfuscates Subject, yEnc name, From and
//! Date, but posts a real-name PAR2 sidecar AFTER the payload, and its
//! message-id localpart follows a fixed grammar:
//!
//! ```text
//! <16-hex clock>.<4-or-5-hex counter>.<16-hex random>@<domain>
//! ```
//!
//! The counter is per posting session and increments per article - it
//! is the ONLY session key. The `@domain` is random per article, and
//! the Date header is randomized: neither may ever be used for
//! association (census, 10 Aug 2026).
//!
//! Everything here parses attacker-controlled input (message-ids come
//! straight off OVER headers) and is fuzzed (`pesto_msgid` target).

/// One decoded pesto message-id localpart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PestoId {
    /// The 16-hex leading field. Monotonic-ish per session; persisted
    /// for re-derivation and telemetry, never used to link.
    pub clock: u64,
    /// The 4-or-5-hex per-session article counter - the session key.
    pub counter: u32,
}

/// Parse a message-id (with or without angle brackets) against the
/// pesto grammar. Lowercase hex only, exactly as the tool emits it -
/// widening this invites coincidental matches from unrelated posters.
pub fn parse_msgid(msgid: &str) -> Option<PestoId> {
    let m = msgid.trim();
    let m = m.strip_prefix('<').unwrap_or(m);
    let m = m.strip_suffix('>').unwrap_or(m);
    let (local, domain) = m.split_once('@')?;
    if domain.is_empty() || domain.contains('@') {
        return None;
    }
    let mut parts = local.split('.');
    let (clock, counter, rand) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let lohex = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if clock.len() != 16 || !lohex(clock) {
        return None;
    }
    if !(4..=5).contains(&counter.len()) || !lohex(counter) {
        return None;
    }
    if rand.len() != 16 || !lohex(rand) {
        return None;
    }
    Some(PestoId {
        clock: u64::from_str_radix(clock, 16).ok()?,
        counter: u32::from_str_radix(counter, 16).ok()?,
    })
}

/// Upper bound of the on-wire/decoded length ratio for a candidate
/// link. Clean true links cluster 1.017-1.033 (median 1.032, yEnc
/// overhead); the census's false claimants all sat at >= 1.040. The
/// lower bound is 1.0 by construction - the wire always carries at
/// least the payload.
pub const LENGTH_RATIO_MAX: f64 = 1.035;

/// Does a payload's on-wire size fit a set's declared decoded size?
/// This is a PRE-FILTER, never a proof: counter containment plus this
/// band still mislinked 8/330 in the census. Only the 16k-MD5 gate
/// ([`match_filedesc`]) may write a name.
pub fn length_ratio_ok(on_wire_bytes: u64, sum_filedesc_len: u64) -> bool {
    sum_filedesc_len > 0
        && on_wire_bytes >= sum_filedesc_len
        && (on_wire_bytes as f64) / (sum_filedesc_len as f64) <= LENGTH_RATIO_MAX
}

/// One FileDesc as the linking side needs it - name, exact length, and
/// the two MD5s, hex-encoded for storage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PestoDesc {
    pub name: String,
    pub length: u64,
    /// Whole-file MD5, hex.
    pub md5: String,
    /// MD5 of the first min(16384, length) bytes, hex.
    pub md5_16k: String,
}

impl PestoDesc {
    pub fn from_set(set: &crate::par2::Par2Set) -> Vec<PestoDesc> {
        set.files
            .iter()
            .map(|f| PestoDesc {
                name: f.name.clone(),
                length: f.length,
                md5: crate::par2::hex16(&f.md5),
                md5_16k: crate::par2::hex16(&f.md5_16k),
            })
            .collect()
    }
}

/// THE hash gate (census section 4, non-negotiable): given the decoded
/// head of a candidate payload's first article, return the FileDesc
/// whose first-16-KiB MD5 the bytes actually match - or None, in which
/// case NO name may be written for this candidate. Matches ANY
/// FileDesc, not just the first: a multi-file set whose first-posted
/// file is not FileDesc[0] read as unresolved in the census when it
/// was actually linkable.
///
/// Only a FileDesc covering the FULL hash span may match. A shorter
/// declared length hashes only `length` bytes, and the sidecar author
/// chooses that length - a decoy desc of `length: 7` would reduce the
/// gate to seven bytes of guessable container magic ("Rar!..."), and
/// the name is then taken from a DIFFERENT desc (the biggest). Same
/// floor `par_hash_remember` applies. The trade: a set whose
/// first-posted file is under 16 KiB reads as unmatched and the
/// candidate stays dark - give-up, not a wrong name. What the gate
/// defends against is mis-association and cheap forgery; an adversary
/// who fetches the payload's public head can always satisfy it, so the
/// floor is defense-in-depth, not proof of authorship.
pub fn match_filedesc<'a>(descs: &'a [PestoDesc], head: &[u8]) -> Option<&'a PestoDesc> {
    descs.iter().find(|d| {
        d.length >= crate::par2::HASH16K_LEN as u64
            && crate::par2::md5_16k_of_head(head, d.length)
                .is_some_and(|h| crate::par2::hex16(&h) == d.md5_16k)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_grammar_parses_real_pesto_ids_and_nothing_else() {
        // Real ids from the census fixtures (bracketed and bare).
        let id = parse_msgid("<18ca0dc84ce1ff8c.1086.75d9c5a63ebd783a@qscvjtfykqf.com>").unwrap();
        assert_eq!(id.clock, 0x18ca0dc84ce1ff8c);
        assert_eq!(id.counter, 0x1086);
        // 5-hex counter (the Succession base-index example).
        let id = parse_msgid("18c9fdcb91466219.53fef.c0bfcfa8ab22c66a@gnelkiuqkum.org").unwrap();
        assert_eq!(id.counter, 0x53fef);

        for bad in [
            // Wrong field lengths.
            "18ca0dc84ce1ff8.1086.75d9c5a63ebd783a@x.com", // 15-hex clock
            "18ca0dc84ce1ff8c.108.75d9c5a63ebd783a@x.com", // 3-hex counter
            "18ca0dc84ce1ff8c.108662.75d9c5a63ebd783a@x.com", // 6-hex counter
            "18ca0dc84ce1ff8c.1086.75d9c5a63ebd783@x.com", // 15-hex random
            // Uppercase is not the tool's output.
            "18CA0DC84CE1FF8C.1086.75d9c5a63ebd783a@x.com",
            // Non-hex, missing fields, malformed domain.
            "18ca0dc84ce1ffgg.1086.75d9c5a63ebd783a@x.com",
            "18ca0dc84ce1ff8c.1086@x.com",
            "18ca0dc84ce1ff8c.1086.75d9c5a63ebd783a.f@x.com",
            "18ca0dc84ce1ff8c.1086.75d9c5a63ebd783a@",
            "18ca0dc84ce1ff8c.1086.75d9c5a63ebd783a",
            "part1of2.abc@news.example",
            "",
        ] {
            assert!(parse_msgid(bad).is_none(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn the_ratio_band_is_tight_and_one_sided() {
        // The census's clean cluster (1.017-1.033) passes...
        assert!(length_ratio_ok(1_025_000_000, 1_000_000_000));
        assert!(length_ratio_ok(1_033_000_000, 1_000_000_000));
        // ...the measured false claimants (>= 1.040) do not...
        assert!(!length_ratio_ok(1_040_000_000, 1_000_000_000));
        assert!(!length_ratio_ok(1_096_000_000, 1_000_000_000));
        // ...and a wire smaller than the declared payload is no link
        // (that shape was the 4.15 GB set pointing at a 76 MB payload).
        assert!(!length_ratio_ok(76_000_000, 4_150_000_000));
        assert!(!length_ratio_ok(0, 0));
        assert!(!length_ratio_ok(5, 0));
    }

    #[test]
    fn the_gate_matches_any_filedesc_not_just_the_first() {
        use crate::md5fast::{Digest, Md5};
        let head: Vec<u8> = (0..20_000u32).map(|i| (i * 31) as u8).collect();
        let h16k = crate::par2::hex16(&Md5::digest(&head[..16384]).into());
        let descs = vec![
            PestoDesc {
                name: "decoy.r00".into(),
                length: 50_000_000,
                md5: String::new(),
                md5_16k: "0".repeat(32),
            },
            PestoDesc {
                name: "Real.Show.S01E01.mkv".into(),
                length: 900_000_000,
                md5: String::new(),
                md5_16k: h16k,
            },
        ];
        assert_eq!(
            match_filedesc(&descs, &head).map(|d| d.name.as_str()),
            Some("Real.Show.S01E01.mkv"),
            "the match must consider every FileDesc"
        );
        // Mismatching bytes match nothing - no name, full stop.
        assert!(match_filedesc(&descs, &head[1..]).is_none());
        // A head shorter than min(16384, length) can prove nothing.
        assert!(match_filedesc(&descs, &head[..8000]).is_none());
        // A desc shorter than the hash span is REFUSED even when its
        // bytes genuinely match: the author of the sidecar picks the
        // length, so a short desc is the forgeable arm of the gate. A
        // crafted `length: 7` decoy carrying the MD5 of a container
        // magic must not pass on seven guessable bytes.
        let short = &head[..5000];
        let descs = vec![PestoDesc {
            name: "tiny.nfo".into(),
            length: 5000,
            md5: String::new(),
            md5_16k: crate::par2::hex16(&Md5::digest(short).into()),
        }];
        assert!(
            match_filedesc(&descs, &head).is_none(),
            "a sub-16KiB FileDesc must never satisfy the gate"
        );
        let magic = b"Rar!\x1a\x07\x01";
        let descs = vec![
            PestoDesc {
                name: "TotallyLegit.Movie.2026.mkv".into(),
                length: 900_000_000,
                md5: String::new(),
                md5_16k: "0".repeat(32),
            },
            PestoDesc {
                name: "decoy".into(),
                length: magic.len() as u64,
                md5: String::new(),
                md5_16k: crate::par2::hex16(&Md5::digest(magic).into()),
            },
        ];
        let mut rar_head = magic.to_vec();
        rar_head.extend_from_slice(&head);
        assert!(
            match_filedesc(&descs, &rar_head).is_none(),
            "the magic-prefix decoy must not open the gate"
        );
    }
}
