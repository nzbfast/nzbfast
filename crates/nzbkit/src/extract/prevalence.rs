//! Phase 0(b) nested-archive prevalence reporting: one line per inner
//! archive this level handled in-stream, with its type and disposition,
//! and the two classifiers (slot-level, group-level) the demote sites
//! and `finish` read the kind off. Moved out of `extract/mod.rs` bodily
//! (the TODO 106 size-gate pattern, same as `names.rs` and
//! `deliver.rs`) when the 22 Aug 2026 merges put that file over its
//! ceiling; a second `impl Extractor`, reached through `pub(super)`.

use super::*;

impl Extractor {
    /// Phase 0(b) prevalence: emit one line per inner archive this level
    /// handled in-stream, with its type and disposition. Nested levels
    /// only (`self.depth > 0`) - a single-layer job's outer archives are
    /// depth 0 and never counted. RAR inners live in `groups` (store and
    /// chase alike; the kind reads off the mapper's first entry, which
    /// survives a demote); an in-stream 7z is a group-less slot in
    /// `SevenZ` mode. A demoted inner is logged `demoted` (with the
    /// reason) and left for the disk post-pass to tally under `disk`, so
    /// it is never counted twice.
    pub(super) fn report_nested_prevalence(&self, inner: &Inner) {
        if self.depth == 0 {
            return;
        }
        for grp in inner.groups.values() {
            let kind = Self::group_inner_kind(inner, grp);
            match (grp.fallback, grp.fallback_reason.as_deref()) {
                (true, reason) => note_nested_level(
                    self.depth,
                    kind,
                    NestedDisposition::Demoted(reason.unwrap_or("demoted")),
                ),
                (false, _) => note_nested_level(self.depth, kind, NestedDisposition::InStream),
            }
        }
        // In-stream 7z inners are slot-level (not in `groups`): a slot
        // still in `SevenZ` mode at finish streamed successfully. A
        // demoted 7z is `RarFallback` by now - its `demoted` diagnostic
        // was emitted at the demote site (fallback_slot_or_group, which
        // still sees the `SevenZ` mode), and the materialized volume is
        // tallied under `disk` by the post-pass.
        for s in &inner.slots {
            if matches!(s.mode, SlotMode::SevenZ) && s.group.is_none() {
                note_nested_level(
                    self.depth,
                    s.container_fmt.noun(),
                    NestedDisposition::InStream,
                );
            }
        }
    }

    /// Classify a single group-less slot for a demote-site prevalence
    /// line, or `None` when it is not a nested archive. Only the three
    /// nested-archive modes count: a plain file, an unclassified span, or
    /// an already-demoted slot returns `None` and stays silent, so a
    /// demoting non-archive never biases the tally. Must be read BEFORE
    /// `fallback_slot` flips the slot to `RarFallback`. `RarChase` slots
    /// always own a group (handled at finish), so a group-less chase mode
    /// is defensive only.
    pub(super) fn slot_inner_kind(inner: &Inner, slot: usize) -> Option<&'static str> {
        match inner.slots[slot].mode {
            SlotMode::SevenZ => Some(inner.slots[slot].container_fmt.noun()),
            SlotMode::RarChase => Some("rar-compressed"),
            SlotMode::Rar => Some(
                match inner.slots[slot]
                    .mapper
                    .as_ref()
                    .and_then(|m| m.entries.first())
                {
                    Some(e) if e.encrypted || e.crypt.is_some() => "rar-encrypted",
                    Some(e) => match e.method {
                        Method::Store => "rar-store",
                        Method::Compressed => "rar-compressed",
                    },
                    // Mode Rar means it mapped as a store RAR, so this is
                    // effectively unreachable; classify as store rather than
                    // guess a sub-type.
                    None => "rar-store",
                },
            ),
            SlotMode::Unknown
            | SlotMode::Plain
            | SlotMode::RarFallback
            | SlotMode::Discard
            | SlotMode::SplitPart => None,
        }
    }

    /// Classify a RAR group for the prevalence line from its first mapped
    /// entry - encryption wins (it is the salient blocker), then the
    /// compression method. Reads the mapper, which outlives a demote, so a
    /// fallen-back group still classifies correctly.
    pub(super) fn group_inner_kind(inner: &Inner, grp: &Group) -> &'static str {
        for si in &grp.slots {
            if let Some(m) = inner.slots[*si].mapper.as_ref()
                && let Some(e) = m.entries.first()
            {
                if e.encrypted || e.crypt.is_some() {
                    return "rar-encrypted";
                }
                return match e.method {
                    Method::Store => "rar-store",
                    Method::Compressed => "rar-compressed",
                };
            }
        }
        "other"
    }
}
