#![no_main]
//! Fuzz the fMP4 remuxer behind the in-page preview player.
//!
//! The remuxer is a harder target than the probe next door. The probe
//! reads a header and stops; this walks sample tables and block lacing,
//! which are exactly the structures where one number describes another
//! - a lace count that says how many sizes follow, a chunk table that
//!   says where payload begins, a declared size that says how far a frame
//!   extends. Every one of those is an attacker's lever, and all of them
//!   arrive off Usenet before PAR2 has verified a byte.
//!
//! Four properties beyond "does not crash":
//!
//! 1. **Determinism.** The same bytes must produce the same output. It
//!    is what makes a wall-clock budget inadmissible in the walk, and
//!    what lets the live path claim that a fragment does not depend on
//!    when its bytes arrived.
//! 2. **Termination.** Every walk ends. A cluster of unknown size, a
//!    chunk table that points backwards, an stsc run with no samples in
//!    it - each is a way to ask for an infinite loop.
//! 3. **Bounded allocation.** Nothing is sized by a declared length
//!    alone; the file's own size bounds it first. The rss limit below is
//!    what actually enforces this.
//! 4. **Arrival-order independence.** The same bytes served whole and
//!    served with a hole produce identical output up to the hole. This
//!    is the property the whole live-preview feature rests on, and the
//!    only place it can be tested against arbitrary input.
//!
//! Run with the rss limit:
//!
//!     cargo +nightly fuzz run remux -- -max_total_time=300 -rss_limit_mb=512

use libfuzzer_sys::fuzz_target;
use nzbkit::mediaprobe::session::{Emit, RemuxSession};
use nzbkit::mediaprobe::source::{MemSource, PartialSource, Source};
use std::time::Duration;

const NOW: Duration = Duration::ZERO;
/// Far more pulls than any input this size can legitimately need. A
/// walk that reaches it has failed to terminate.
const MAX_PULLS: usize = 20_000;

/// Drain a session, returning the concatenated output and whether it
/// stopped because it ran out of downloaded bytes.
fn drain(src: &dyn Source, s: &mut RemuxSession) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    for _ in 0..MAX_PULLS {
        match s.pull(src, NOW) {
            Ok(Emit::Init(b)) | Ok(Emit::Fragment(b)) => {
                // A single emitted blob is bounded by the fragment size
                // cap, whatever the input claimed.
                assert!(b.len() <= (80 << 20), "an emitted blob was unbounded");
                out.extend(b);
            }
            Ok(Emit::NotYet { .. }) => return (out, true),
            Ok(Emit::Eos) | Err(_) => return (out, false),
        }
    }
    panic!("the remux walk did not terminate");
}

fuzz_target!(|data: &[u8]| {
    // Anything shorter than a container header is uninteresting and
    // just slows the campaign down.
    if data.len() < 32 || data.len() > (8 << 20) {
        return;
    }

    let whole = MemSource(data.to_vec());
    let Ok(mut a) = RemuxSession::new(&whole, None, NOW) else {
        return;
    };
    let (first, _) = drain(&whole, &mut a);

    // 1. Determinism: a second session over the same bytes agrees.
    let mut b = RemuxSession::new(&whole, None, NOW).expect("reopening the same bytes failed");
    let (second, _) = drain(&whole, &mut b);
    assert!(first == second, "the remuxer disagreed with itself");

    // 4. Arrival order: the same file with only its first half landed
    // must emit a PREFIX of the whole-file output, never something
    // different. Everything it did emit, it emitted from bytes it had.
    let partial = PartialSource::new(data.to_vec());
    partial.land(0, data.len() as u64 / 2);
    // The tail too, because that is where an index lives and the live
    // path promotes it for exactly that reason.
    let tail = (data.len() as u64).saturating_sub(4_096);
    partial.land(tail, data.len() as u64 - tail);
    if let Ok(mut c) = RemuxSession::new(&partial, None, NOW) {
        let (early, blocked) = drain(&partial, &mut c);
        assert!(
            first.starts_with(&early),
            "a partially downloaded file emitted bytes the complete one did not"
        );
        // Finishing the download must reach exactly the same place.
        if blocked {
            partial.land_all();
            let (rest, still) = drain(&partial, &mut c);
            assert!(!still, "a complete file still reported missing bytes");
            let mut joined = early;
            joined.extend(rest);
            assert!(joined == first, "arrival order changed the remuxed output");
        }
    }

    // A seek into an arbitrary offset of an arbitrary file: it either
    // refuses or lands somewhere the walk can continue from, and either
    // way it terminates.
    let mut d = RemuxSession::new(&whole, None, NOW).expect("reopening the same bytes failed");
    let t_ms = u64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]])) % 3_600_000;
    if d.seek(&whole, t_ms, NOW).is_ok() {
        let _ = drain(&whole, &mut d);
    }

    // Selecting an audio track that does not exist must be a refusal,
    // never an index into a track list that is shorter than it claims.
    if let Ok(mut e) = RemuxSession::new(&whole, Some(usize::from(data[4])), NOW) {
        let _ = drain(&whole, &mut e);
    }
});
