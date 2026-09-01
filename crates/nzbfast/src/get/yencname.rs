//! M4-70: which ARTICLE's yEnc name a file is published under, when the
//! articles of one file disagree.
//!
//! A post carries a filename per ARTICLE, and nothing made those agree.
//! `unpack::slot_name::write_name` latched the first one and
//! `nzbkit::extract::Extractor`'s write path took a slot's name only
//! when it had none (`s.name.is_empty() && !name.is_empty()`), so every
//! later article's name was dropped on the floor with no `!=` anywhere -
//! the disagreement was never observed, let alone weighed or logged.
//!
//! MEASURED, both arrival orders, 30 Aug 2026
//! (`research/NORAR-M4-70-ARRIVAL-ORDER-NAME-2026-08-30.md`). One file,
//! four articles: the first declares `x.dat`, the other three
//! `Movie.2024.mkv`. Stall the three and the job publishes `x.dat`;
//! stall the one and the same post publishes `Movie.2024.mkv`. Identical
//! bytes on the wire. The filename was a function of the network.
//!
//! # Why this is a settle tier and not a better latch
//!
//! Nothing at the moment of a write is order-free. When the first
//! article lands there is exactly one name in hand, so first-wins,
//! last-wins and later-upgrades-weaker are each still a function of
//! arrival order with a different winner - and the file has to be called
//! something while it is being written. The evidence that settles the
//! question is what EVERY article declared, and that is not complete
//! until the last one has arrived. So the write still latches, the
//! articles' declarations are recorded as they pass
//! (`unpack::slot_name::NameVotes`), and the decision is re-made here.
//!
//! The rule is the family's (`2b7f5495e`): a weaker or earlier clue may
//! NOMINATE a file, and only the strongest available evidence may
//! finalize identity or overwrite a name. "First to arrive" is not
//! evidence of anything. What the post says MOST OFTEN is the strongest
//! thing a set of yEnc headers can say, and a decoy is by construction a
//! minority. A tie keeps the incumbent - see
//! `FileSlot::contested_yenc_name` for why no tiebreak is invented.
//!
//! # Why it is the WEAKEST tier, and runs after the sidecar one
//!
//! A yEnc header is the poster's unverified word about a name, with no
//! checksum behind it at all - weaker than `sfvname`'s, which is a
//! checksum computed over the full settled file, and far weaker than a
//! PAR2 FileDesc's MD5 pair. So it runs LAST, and three separate things
//! keep it from overwriting anything better:
//!
//! * it renames only a file still sitting under a name THIS tier put
//!   there - one of the names the articles themselves declared, or the
//!   slot's own posted hint. Anything else on disk means a stronger tier
//!   has already spoken, and it outranks a header;
//! * GH #63's hint rule applies unchanged (`filedesc_name_is_better`),
//!   so a majority of hashes cannot take a real posted subject name
//!   away;
//! * the publish goes through `publish_weak_name`, which declines rather
//!   than replacing a file already at the target (W4-03).
//!
//! The eligibility bar at the top of the loop - no par2 slot, no
//! skipped sample, no missing/incomplete/errored/abandoned articles, not
//! mapped, not chased - is inherited from the sidecar tier and is
//! CONSERVATIVE rather than measured: a slot that lost articles has no
//! finished file to rename, and its votes are a reading of a post we
//! only partly received. Stated rather than overclaimed - no fixture in
//! `e2e_norar::namelatch` exercises it, so removing it reddens nothing
//! there today.
//!
//! # What it deliberately does not reach
//!
//! The set-covered file, which needs no help: a covering FileDesc
//! already overrules the decoy in EITHER arrival order (measured, and
//! pinned by
//! `e2e_norar::namelatch::a_covering_filedesc_overrules_the_decoy_name_in_either_order`).
//! The tier still runs over those slots, and the on-disk test above is
//! what makes it a no-op there rather than a special case: the FileDesc
//! rename has already moved the file off every name the articles
//! declared.

use super::*;
use std::path::Path;
use std::sync::atomic::Ordering;
use tracing::{info, warn};

/// Re-decide the published name of every slot whose articles contradict
/// each other. See the module header; runs last, over settled files.
pub(super) fn land_contested_yenc_names(
    slots: &[Arc<FileSlot>],
    extractor: &nzbkit::extract::Extractor,
    out_dir: &Path,
    published_names: &mut crate::unpack::PublishedNames,
) {
    for (sidx, slot) in slots.iter().enumerate() {
        // The same eligibility bar the sidecar tier uses, and for the
        // same reason: a slot that lost articles or fed an extraction
        // has no finished file to rename. A slot missing articles is
        // also a slot whose votes are missing, so its majority is a
        // reading of a post we only partly received.
        if slot.is_par2()
            || slot.sample_skipped
            || slot.missing.load(Ordering::Relaxed) != 0
            || slot.remaining.load(Ordering::Relaxed) != 0
            || slot.errors.load(Ordering::Relaxed) != 0
            || slot.abandoned.load(Ordering::Relaxed) != 0
            || extractor.is_mapped(sidx)
            || extractor.is_chased(sidx)
        {
            continue;
        }
        let Some(contested) = slot.contested_yenc_name() else {
            continue;
        };
        // GH #63 unchanged: a name may not be taken away by one that
        // gives up what the post already told us.
        if !super::settle::filedesc_name_is_better(slot, &contested.winner) {
            continue;
        }
        let Some(path) = extractor.slot_path(sidx) else {
            continue;
        };
        // Only correct a name THIS tier is responsible for. Compared
        // against the out_dir-RELATIVE name, not the bare file name, so
        // a tree-preserved rename from a stronger tier is seen as the
        // move it is.
        let on_disk = nzbkit::disk::out_name_of(out_dir, &path);
        if !contested
            .declared
            .iter()
            .chain(std::iter::once(&slot.hint))
            .any(|n| nzbkit::disk::sanitize_out_name(n) == on_disk)
        {
            continue;
        }
        let Some(new) = publish_weak_name(&path, &contested.winner, out_dir, sidx, published_names)
        else {
            continue;
        };
        let landed = nzbkit::disk::out_name_of(out_dir, &new);
        extractor.note_slot_renamed(sidx, new);
        // Said out loud, because it is the one rename in the job with no
        // checksum behind it: the user gets the arithmetic that
        // justified it rather than a name that silently changed. What
        // LANDED is not always what was asked for - the registry pushes
        // a claim off a name another slot of this job already holds -
        // and the person reading the directory needs to be told that
        // happened rather than left to spot a `{slot:03}-` prefix and
        // wonder (W4-03).
        if landed == nzbkit::disk::sanitize_out_name(&contested.winner) {
            info!(
                target: "verify",
                "✔ {} - {} of this file's {} named articles call it that, so \
                 the post's own majority decides rather than whichever \
                 article decoded first (it was written as {on_disk})",
                contested.winner,
                contested.winner_votes,
                contested.total_votes
            );
        } else {
            warn!(
                target: "verify",
                "{} is what {} of this file's {} named articles call it, but \
                 another file of this job already holds that name, so it \
                 landed as {landed} rather than replacing it",
                contested.winner,
                contested.winner_votes,
                contested.total_votes
            );
        }
    }
}
