use super::*;
use crate::codec::rar50::{
    encode_lz_member_pooled, encode_lz_member_with_options,
    encode_lz_member_with_options_and_progress, EncodeOptions, EncoderScratchPool, LiveSpanEncoder,
    Rar50FilterSpec, Unpack50Encoder, MAX_FILTER_BLOCK_LENGTH,
};
use crate::x86_filter_scan::auto_x86_filter_ranges;

fn borrow_progress<'a>(
    progress: &'a mut Option<&mut dyn FnMut(usize) -> bool>,
) -> Option<&'a mut dyn FnMut(usize) -> bool> {
    match progress {
        Some(report) => Some(&mut **report),
        None => None,
    }
}

#[cfg(test)]
pub(super) fn encode_member_with_filter_policy(
    data: &[u8],
    algorithm_version: u8,
    policy: FilterPolicy,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_member_with_filter_policy_and_progress(data, algorithm_version, policy, options, None)
}

fn encode_member_with_filter_policy_and_progress(
    data: &[u8],
    algorithm_version: u8,
    policy: FilterPolicy,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    match policy {
        FilterPolicy::None => match progress {
            Some(progress) => {
                encode_safe_lz_member_with_progress(data, algorithm_version, options, progress)
            }
            None => encode_safe_lz_member(data, algorithm_version, options),
        },
        FilterPolicy::Explicit(filter) => {
            encode_member_with_filter_progress(data, algorithm_version, filter, options, progress)
                .map_err(Error::from)
        }
        FilterPolicy::AutoSize => {
            encode_member_with_auto_size_filter_progress(data, algorithm_version, options, progress)
        }
        FilterPolicy::Sampled => {
            let filters = select_sampled_filters(data, options);
            if filters.is_empty() {
                return encode_member_with_filter_policy_and_progress(
                    data,
                    algorithm_version,
                    FilterPolicy::None,
                    options,
                    progress,
                );
            }
            encode_member_with_filter_specs_progress(
                data,
                algorithm_version,
                &filters,
                options,
                progress,
            )
            .map_err(Error::from)
        }
    }
}

/// [`encode_member_with_filter_policy_candidates_and_progress`] for a
/// member whose filters are already chosen: the writer resolves a
/// `Sampled` member's regions once and hands the list here, so the probes
/// are not paid again per candidate (nzbfast-local change, 7 Sep 2026;
/// see VENDORING.md).
pub(super) fn encode_member_with_filter_specs_candidates_and_progress(
    data: &[u8],
    algorithm_version: u8,
    filters: &[Rar50FilterSpec],
    candidates: &[EncodeOptions],
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    let mut candidates = candidates.iter().copied();
    let first = candidates.next().ok_or(Error::InvalidHeader(
        "RAR 5 compression level has no encoder options",
    ))?;
    let mut best = encode_member_with_filter_specs_progress(
        data,
        algorithm_version,
        filters,
        first,
        borrow_progress(&mut progress),
    )?;
    for options in candidates {
        let packed = encode_member_with_filter_specs_progress(
            data,
            algorithm_version,
            filters,
            options,
            borrow_progress(&mut progress),
        )?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    Ok(best)
}

/// Sample-guided regional filters, the [`FilterPolicy::Sampled`] selector
/// (nzbfast-local change, 7 Sep 2026; see VENDORING.md). The member is
/// walked in regions of one filter chunk ([`SAMPLED_FILTER_REGION`], the
/// codec's 262,143-byte cap, so a region's record never straddles two LZ
/// blocks) and every region votes on its own: three probes (front, middle,
/// back; [`SAMPLED_FILTER_PROBE_LEN`] each) are raw-encoded with a cheap
/// lazy parser, unfiltered and then under each candidate kind, and the
/// kind whose probes pack smallest takes the region if it beats the
/// unfiltered probes by [`SAMPLED_FILTER_MARGIN_PER_MILLE`]. A region whose
/// probes all read as text is not probed at all: text never wants a
/// filter, and it is a third of the mixed corpus. The probes are the whole
/// cost of the policy on a member that votes nothing - the writer sees an
/// empty list and resolves the member exactly as `None`, the pooled
/// unfiltered encoder, same bytes and same CPU.
///
/// This is the ratio lab's `regions::select` (review, 7 Sep 2026,
/// `research/rar5-ratio-lab`) in production shape: the lab's 64 KiB and
/// 256 KiB spans became the codec's own chunk, its full-strength probe
/// options became a cheap parser (a 16 KiB probe has no use for a 32 MiB
/// dictionary or a tree), and a margin replaced its "keep a complete
/// baseline archive" safety net, which a production writer cannot afford.
/// Probes are a heuristic: a kind that wins three 16 KiB windows can still
/// lose the region, and the margin is what keeps that rare. A member that
/// votes any filter is encoded by the filtered path, which is a serial
/// walk of 262,143-byte LZ blocks WITHOUT the tree finder and without the
/// pool; that cost, not the probes, is the policy's price on the members
/// it fires on (the 7 Sep 2026 measurements are in the private research
/// record beside the ratio lab's).
pub(super) const SAMPLED_FILTER_REGION: usize = MAX_FILTER_BLOCK_LENGTH;
const SAMPLED_FILTER_PROBE_LEN: usize = 16 << 10;
const SAMPLED_FILTER_PROBE_COUNT: usize = 3;
const SAMPLED_FILTER_MARGIN_PER_MILLE: usize = 20;
/// The lab's eleven kinds less the unfiltered control, in two stages: the
/// first is every family (the byte-lane deltas that win on samples and
/// images, and the two executable transforms); the second, the wider and
/// odd delta strides, is probed only where a delta already won the first,
/// which is where the lab's records show them winning. A region that
/// votes nothing pays six probes per window rather than eleven. `E8` is
/// left out on purpose: `E8E9` covers what it does and the two never
/// split a vote on the lab's records.
const SAMPLED_FILTER_KINDS: [FilterKind; 5] = [
    FilterKind::Delta { channels: 1 },
    FilterKind::Delta { channels: 2 },
    FilterKind::Delta { channels: 4 },
    FilterKind::E8E9,
    FilterKind::Arm,
];
const SAMPLED_FILTER_DELTA_KINDS: [FilterKind; 5] = [
    FilterKind::Delta { channels: 3 },
    FilterKind::Delta { channels: 8 },
    FilterKind::Delta { channels: 16 },
    FilterKind::Delta { channels: 24 },
    FilterKind::Delta { channels: 32 },
];

pub(super) fn select_sampled_filters(data: &[u8], options: EncodeOptions) -> Vec<Rar50FilterSpec> {
    // A storing level (no candidates) filters nothing, as `AutoSize` does.
    if options.max_match_candidates == 0 {
        return Vec::new();
    }
    let probe_options = EncodeOptions::new(8)
        .with_lazy_matching(true)
        .with_max_match_distance(
            options
                .max_match_distance
                .clamp(1, SAMPLED_FILTER_PROBE_LEN),
        );
    let mut specs = Vec::new();
    let mut start = 0usize;
    while start < data.len() {
        let end = (start + SAMPLED_FILTER_REGION).min(data.len());
        if let Some(kind) = select_region_filter(&data[start..end], probe_options) {
            specs.push(Rar50FilterSpec::range(kind, start..end));
        }
        start = end;
    }
    specs
}

/// The probe windows of one region: front, middle and back, collapsed
/// when a short region makes them coincide.
fn sampled_filter_probe_windows(region_len: usize) -> Vec<std::ops::Range<usize>> {
    let probe_len = region_len.min(SAMPLED_FILTER_PROBE_LEN);
    let last_start = region_len - probe_len;
    let mut windows: Vec<std::ops::Range<usize>> = Vec::with_capacity(SAMPLED_FILTER_PROBE_COUNT);
    for start in [0, last_start / 2, last_start] {
        if !windows.iter().any(|window| window.start == start) {
            windows.push(start..start + probe_len);
        }
    }
    windows
}

fn select_region_filter(region: &[u8], probe_options: EncodeOptions) -> Option<FilterKind> {
    if region.is_empty() {
        return None;
    }
    let windows = sampled_filter_probe_windows(region.len());
    if windows
        .iter()
        .all(|window| is_text_like_filter_skip_candidate(&region[window.clone()]))
    {
        return None;
    }
    // Keep scratch only for this region's probes, never dictionary history.
    // Every candidate still starts fresh; the pool is released before the
    // full member encode (nzbfast-local change, 8 Sep 2026).
    let scratch = EncoderScratchPool::new();
    let probe = |kind: Option<FilterKind>| -> usize {
        windows
            .iter()
            .map(|window| {
                let sample = &region[window.clone()];
                encode_sampled_filter_probe(sample, kind, probe_options, &scratch)
                    .map_or(usize::MAX, |packed| packed.len())
            })
            .fold(0usize, usize::saturating_add)
    };
    let unfiltered = probe(None);
    let ceiling = unfiltered.saturating_mul(1000 - SAMPLED_FILTER_MARGIN_PER_MILLE) / 1000;
    let mut best: Option<(usize, FilterKind)> = None;
    let mut vote = |kind: FilterKind, best: &mut Option<(usize, FilterKind)>| {
        let cost = probe(Some(kind));
        if cost <= ceiling && best.is_none_or(|(best_cost, _)| cost < best_cost) {
            *best = Some((cost, kind));
        }
    };
    for kind in SAMPLED_FILTER_KINDS {
        vote(kind, &mut best);
    }
    if matches!(best, Some((_, FilterKind::Delta { .. }))) {
        for kind in SAMPLED_FILTER_DELTA_KINDS {
            vote(kind, &mut best);
        }
    }
    best.map(|(_, kind)| kind)
}

/// Encode an independent probe while retaining reusable index/token storage.
/// The fresh encoder on the filtered arm deliberately keeps history out of
/// later probes. The plain arm does not need to retain its unused history.
fn encode_sampled_filter_probe(
    sample: &[u8],
    kind: Option<FilterKind>,
    options: EncodeOptions,
    scratch: &EncoderScratchPool,
) -> crate::codec::Result<Vec<u8>> {
    match kind {
        None => encode_lz_member_pooled(sample, &[], 0, options, None, scratch),
        Some(kind) => Unpack50Encoder::with_options(options).encode_member_with_filters_pooled(
            sample,
            0,
            &[Rar50FilterSpec::new(kind)],
            None,
            scratch,
        ),
    }
}

pub(super) fn encode_member_with_filter_policy_candidates_and_progress(
    data: &[u8],
    algorithm_version: u8,
    policy: FilterPolicy,
    candidates: &[EncodeOptions],
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    let mut candidates = candidates.iter().copied();
    let first = candidates.next().ok_or(Error::InvalidHeader(
        "RAR 5 compression level has no encoder options",
    ))?;
    let mut best = encode_member_with_filter_policy_and_progress(
        data,
        algorithm_version,
        policy,
        first,
        borrow_progress(&mut progress),
    )?;
    for options in candidates {
        let packed = encode_member_with_filter_policy_and_progress(
            data,
            algorithm_version,
            policy,
            options,
            borrow_progress(&mut progress),
        )?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    Ok(best)
}

pub(super) fn filter_policy_attempt_count(data: &[u8], policy: FilterPolicy) -> u64 {
    if policy != FilterPolicy::AutoSize
        || data.is_empty()
        || is_text_like_filter_skip_candidate(data)
    {
        return 1;
    }
    let delta_ranges = (1..=4)
        .filter(|&channels| auto_delta_filter_range(data, channels).is_some())
        .count();
    let e8 = auto_x86_filter_ranges(data, false);
    let e8e9 = auto_x86_filter_ranges(data, true);
    let e8_combined = usize::from(disjoint_filter_ranges(e8.clone()).len() > 1);
    let e8e9_combined = usize::from(disjoint_filter_ranges(e8e9.clone()).len() > 1);
    (8 + delta_ranges + e8.len() + e8_combined + e8e9.len() + e8e9_combined) as u64
}

#[cfg(test)]
pub(super) fn encode_member_with_filter_policy_candidates(
    data: &[u8],
    algorithm_version: u8,
    policy: FilterPolicy,
    candidates: &[EncodeOptions],
) -> Result<Vec<u8>> {
    let mut candidates = candidates.iter().copied();
    let first = candidates.next().ok_or(Error::InvalidHeader(
        "RAR 5 compression level has no encoder options",
    ))?;
    let mut best = encode_member_with_filter_policy(data, algorithm_version, policy, first)?;
    for options in candidates {
        let packed = encode_member_with_filter_policy(data, algorithm_version, policy, options)?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    Ok(best)
}

/// Members at least this long are sampled before the full encode.
pub(super) const INCOMPRESSIBLE_SAMPLE_MIN: usize = 16 << 20;
const INCOMPRESSIBLE_SAMPLE_MIN_LEN: usize = 256 << 10;
const INCOMPRESSIBLE_SAMPLE_COUNT: usize = 3;

/// How long each sample is: at least 256 KiB, and at least the dictionary
/// when the member can afford it (the three samples together stay under a
/// fifth of the member). A sample shorter than the dictionary cannot see
/// the redundancy the dictionary is FOR: a 1 MiB block repeated a thousand
/// times reads as random in any 256 KiB window, and the first cut of this
/// sampler stored such a member at a 32 MiB dictionary where rar packs it
/// to a thousandth (found by the 5 Sep 2026 public-position bench, `rep`
/// shape). At the 128 KiB dictionary the writer defaulted to until 8 Sep
/// 2026 the window stayed 256 KiB; at the 2 MiB default it is 2 MiB.
fn incompressible_sample_len(member_len: usize, dictionary: usize) -> usize {
    dictionary
        .max(INCOMPRESSIBLE_SAMPLE_MIN_LEN)
        .min(member_len / (INCOMPRESSIBLE_SAMPLE_COUNT * 5))
        .max(INCOMPRESSIBLE_SAMPLE_MIN_LEN)
}

/// Whether a large member reads as incompressible from three samples
/// (front, middle, back; see [`incompressible_sample_len`] for their
/// length), each raw-encoded on its own without history: a
/// sample that shrinks by more than half a percent votes for the full
/// encode. The writer used to compress the WHOLE member and then compare
/// the packed length against the input to decide on store, so a 1 GiB
/// video paid the full encode for nothing; the samples cost about 3 MiB of
/// encoding instead (768 KiB, since the literal price model made the 1 MiB
/// samples a fifth of a stored member's cost). A member with a compressible region that all three
/// samples miss is stored; that is the accepted trade, and it is the same
/// decision the compress-then-compare rule would have reached whenever the
/// compressible part is under half a percent of the member.
/// (nzbfast-local change, 5 Sep 2026; see VENDORING.md.)
pub(super) fn sampled_incompressible(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> bool {
    let Some(windows) = incompressible_sample_windows(data.len(), options) else {
        return false;
    };
    samples_read_incompressible(
        windows.iter().map(|window| &data[window.clone()]),
        algorithm_version,
        options,
    )
}

/// The windows [`sampled_incompressible`] samples of a member `member_len`
/// long, or `None` when the member is not sampled (too short, or a level
/// that stores everything). Split out so a writer that holds the member a
/// segment at a time can read the windows from its source and put them to
/// [`samples_read_incompressible`] for the same verdict (nzbfast-local
/// change, 6 Sep 2026; see VENDORING.md).
pub(super) fn incompressible_sample_windows(
    member_len: usize,
    options: EncodeOptions,
) -> Option<[std::ops::Range<usize>; INCOMPRESSIBLE_SAMPLE_COUNT]> {
    if member_len < INCOMPRESSIBLE_SAMPLE_MIN || options.max_match_candidates == 0 {
        return None;
    }
    let sample_len = incompressible_sample_len(member_len, options.max_match_distance);
    let last_start = member_len - sample_len;
    Some(std::array::from_fn(|index| {
        let start = last_start * index / (INCOMPRESSIBLE_SAMPLE_COUNT - 1);
        start..start + sample_len
    }))
}

/// [`sampled_incompressible`]'s verdict over samples already in hand, in
/// window order: the first sample that shrinks ends the sampling.
pub(super) fn samples_read_incompressible<'a>(
    samples: impl IntoIterator<Item = &'a [u8]>,
    algorithm_version: u8,
    options: EncodeOptions,
) -> bool {
    samples.into_iter().all(|sample| {
        match encode_lz_member_with_options(sample, algorithm_version, options) {
            Ok(packed) => packed.len() * 200 >= sample.len() * 199,
            Err(_) => false,
        }
    })
}

pub(super) fn should_store_compressed_payload(
    data: &[u8],
    packed: &[u8],
    solid: bool,
    policy: FilterPolicy,
) -> bool {
    !solid && !matches!(policy, FilterPolicy::Explicit(_)) && packed.len() >= data.len()
}

#[cfg(test)]
pub(super) fn encode_with_solid_reset_policy(
    encoder: &mut Unpack50Encoder,
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    index: usize,
) -> Result<(Vec<u8>, bool)> {
    encode_with_solid_reset_policy_and_progress(
        encoder,
        data,
        algorithm_version,
        options,
        index,
        None,
    )
}

/// The serial policy the pooled resolve replaced; kept as the reference
/// the tests compare against.
#[cfg(test)]
pub(super) fn encode_with_solid_reset_policy_and_progress(
    encoder: &mut Unpack50Encoder,
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    index: usize,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<(Vec<u8>, bool)> {
    if index == 0 {
        let packed = if let Some(progress) = progress.as_deref_mut() {
            encoder
                .encode_member_with_progress(data, algorithm_version, progress)
                .map_err(Error::from)?
        } else {
            encoder
                .encode_member(data, algorithm_version)
                .map_err(Error::from)?
        };
        return Ok((packed, false));
    }

    // The continued arm runs on the caller's encoder itself: it used to run
    // on a CLONE (a copy of up to the dictionary of history per member -
    // 12.8 GB of memcpy over a 400-member set at 32 MiB), where the only
    // outcome that needs the pre-member state is the fresh arm winning,
    // and that outcome replaces the encoder wholesale. An error aborts the
    // whole write either way. (nzbfast-local change, 6 Sep 2026; see
    // VENDORING.md.)
    let continued_packed = if let Some(progress) = progress.as_deref_mut() {
        encoder
            .encode_member_with_progress(data, algorithm_version, progress)
            .map_err(Error::from)?
    } else {
        encoder
            .encode_member(data, algorithm_version)
            .map_err(Error::from)?
    };
    let mut fresh = Unpack50Encoder::with_options(options);
    let fresh_packed = if let Some(progress) = progress {
        fresh
            .encode_member_with_progress(data, algorithm_version, progress)
            .map_err(Error::from)?
    } else {
        fresh
            .encode_member(data, algorithm_version)
            .map_err(Error::from)?
    };
    if fresh_packed.len() < continued_packed.len() {
        *encoder = fresh;
        Ok((fresh_packed, false))
    } else {
        Ok((continued_packed, true))
    }
}

/// The packed bytes and continuation flag of every member of a SOLID set:
/// the decision [`encode_with_solid_reset_policy_and_progress`] makes
/// member by member, with the encodes on the pool.
///
/// A solid set is a serial walk by nature - member `i` is encoded against
/// the history the members before it left - and the walk encoded every
/// member TWICE on one thread (continued against the history, fresh
/// without it, the smaller kept): 200 members of 2.7 MB took 203 s on an
/// 8-vCPU guest, against 20 s for the same members non-solid and 45 s for
/// rar. But the history a member sees is only the raw bytes of the
/// members before it since the last reset, never an earlier encode's
/// output, so both arms of every member can be encoded at once
/// SPECULATIVELY, assuming no reset within the dictionary behind it, and
/// the walk then only DECIDES: it takes the speculative continued arm
/// when the members since the last reset already fill the dictionary
/// (the two histories are then the same bytes), and re-encodes the
/// continued arm against the true history only for members within a
/// dictionary of a reset. The decision rule and the histories are the
/// serial walk's exactly, so the bytes and the flags are its bytes and
/// flags; a test holds them there over resets forced by a swapped rule.
/// (nzbfast-local change, 6 Sep 2026; see VENDORING.md.)
pub(super) fn resolve_solid_members(
    members: &[&[u8]],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: Option<&WorkTracker<'_>>,
) -> Result<Vec<(Vec<u8>, bool)>> {
    resolve_solid_members_with_rule(
        members,
        algorithm_version,
        options,
        progress,
        |fresh, continued| fresh + SOLID_RESET_MARGIN < continued,
    )
}

/// How many bytes smaller a member's FRESH arm must be before the walk
/// takes it and resets the solid history (nzbfast-local change, 7 Sep
/// 2026; see VENDORING.md).
///
/// A reset is priced locally - this member's two arms - and paid
/// globally: every later member of the set loses the dictionary behind
/// it, for as long as the run lasts. With the rule at "smaller wins",
/// a member whose two arms are within a few bytes of each other, which is
/// what a member the history does not help looks like, resets the stream
/// on the strength of that noise. Measured on 10,240 members of 10 KiB
/// cut from the mixed corpus at `-md32m` (7 Sep 2026): the rule reset 103
/// times over the set and produced 55,921,162 bytes, where rar 7.23 -s
/// never resets and produces 46,114,798. A margin of 64 bytes removes all
/// 103 resets and produces 45,527,586 - under rar's own, and the largest
/// single ratio finding of that round. The margin is not critical: 64,
/// 256 and "never reset" all produce that same archive here, and 0 is the
/// old behaviour. On the 400-member 1 GiB set the walk resets nowhere
/// under either rule, so nothing moves there.
///
/// The reach the tree match finder gives a solid set is worth 0.5 MB of
/// that 10.4 (46,024,193 bytes with the finder off and this margin on);
/// the resets were the rest.
const SOLID_RESET_MARGIN: usize = 64;

/// The last `dictionary` bytes of `members[run_start..index]`.
fn solid_history<'a>(
    members: &[&'a [u8]],
    run_start: usize,
    index: usize,
    dictionary: usize,
) -> std::borrow::Cow<'a, [u8]> {
    if index == run_start {
        return std::borrow::Cow::Borrowed(&[]);
    }
    let previous = members[index - 1];
    if previous.len() >= dictionary {
        return std::borrow::Cow::Borrowed(&previous[previous.len() - dictionary..]);
    }
    // Walk back until the members from `from` on hold the dictionary (or
    // the run begins), then take the tail of that span.
    let mut needed = dictionary;
    let mut from = index;
    while from > run_start && needed > 0 {
        from -= 1;
        needed = needed.saturating_sub(members[from].len());
    }
    let total: usize = members[from..index].iter().map(|m| m.len()).sum();
    let skip = total.saturating_sub(dictionary);
    let mut history = Vec::with_capacity(total - skip);
    history.extend_from_slice(&members[from][skip..]);
    for member in &members[from + 1..index] {
        history.extend_from_slice(member);
    }
    std::borrow::Cow::Owned(history)
}

/// A group of a solid set's members is resolved from one WINDOW: the
/// dictionary of history before the group, then the group's members
/// back to back, so every arm borrows its history from it. Groups run
/// in parallel, as many at once as the pool has threads, each group's
/// continued arms walking one live index in order and its fresh arms
/// beside them; a group holds at least this many member bytes, so the
/// working set is (threads) x (dictionary + this + one member).
#[cfg(not(test))]
const SOLID_GROUP_BYTES: usize = 16 << 20;
/// Tests use groups of a few members so the window's roll is exercised.
#[cfg(test)]
const SOLID_GROUP_BYTES: usize = 5_000;

fn resolve_solid_members_with_rule(
    members: &[&[u8]],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: Option<&WorkTracker<'_>>,
    prefer_fresh: impl Fn(usize, usize) -> bool,
) -> Result<Vec<(Vec<u8>, bool)>> {
    let dictionary = options.max_match_distance;
    let report_member = |member: &[u8]| -> Result<()> {
        if progress.is_some_and(|progress| !progress.advance(member.len() as u64)) {
            return Err(Error::Cancelled);
        }
        Ok(())
    };
    // The groups: consecutive members holding at least SOLID_GROUP_BYTES.
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut group_start = 0usize;
    while group_start < members.len() {
        let mut group_end = group_start;
        let mut group_bytes = 0usize;
        while group_end < members.len()
            && (group_bytes < SOLID_GROUP_BYTES || group_end == group_start)
        {
            group_bytes += members[group_end].len();
            group_end += 1;
        }
        groups.push((group_start, group_end));
        group_start = group_end;
    }
    // One group: its window, its fresh arms, and its continued arms on a
    // live index seeded once from the dictionary before it. Returns the
    // fresh and continued packed bytes of every member in the group (the
    // first member of the set has no continued arm).
    let resolve_group = |&(group_start, group_end): &(usize, usize)| -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>> {
        let scratch = EncoderScratchPool::new();
        let history = solid_history(members, 0, group_start, dictionary);
        let mut window: Vec<u8> = Vec::with_capacity(
            history.len() + members[group_start..group_end].iter().map(|m| m.len()).sum::<usize>(),
        );
        window.extend_from_slice(&history);
        drop(history);
        let mut offsets = Vec::with_capacity(group_end - group_start + 1);
        for member in &members[group_start..group_end] {
            offsets.push(window.len());
            window.extend_from_slice(member);
        }
        offsets.push(window.len());
        let mut live = LiveSpanEncoder::new();
        let mut out = Vec::with_capacity(group_end - group_start);
        for index in group_start..group_end {
            let member = members[index];
            let fresh =
                encode_lz_member_pooled(member, &[], algorithm_version, options, None, &scratch)?;
            report_member(member)?;
            let continued = if index == 0 {
                None
            } else {
                let start = offsets[index - group_start];
                let end = offsets[index - group_start + 1];
                let packed = live.encode_member(&window, start, end, algorithm_version, options)?;
                report_member(member)?;
                Some(packed)
            };
            out.push((fresh, continued));
        }
        Ok(out)
    };
    #[cfg(feature = "parallel")]
    let resolved_groups: Vec<Vec<(Vec<u8>, Option<Vec<u8>>)>> = {
        // As many groups at once as the pool has threads, for the memory
        // bound; the next chunk of groups starts when this one is done.
        let at_once = rayon::current_num_threads().max(1);
        let mut resolved = Vec::with_capacity(groups.len());
        for chunk in groups.chunks(at_once) {
            if chunk.len() > 1 {
                resolved.extend(crate::parallel::map_slice_collect(chunk, resolve_group)?);
            } else {
                resolved.push(resolve_group(&chunk[0])?);
            }
        }
        resolved
    };
    #[cfg(not(feature = "parallel"))]
    let resolved_groups: Vec<Vec<(Vec<u8>, Option<Vec<u8>>)>> =
        groups.iter().map(resolve_group).collect::<Result<Vec<_>>>()?;
    let mut fresh_arms: Vec<Option<Vec<u8>>> = Vec::with_capacity(members.len());
    let mut continued_arms: Vec<Option<Vec<u8>>> = Vec::with_capacity(members.len());
    for group in resolved_groups {
        for (fresh, continued) in group {
            fresh_arms.push(Some(fresh));
            continued_arms.push(continued);
        }
    }
    // The walk: decide, re-encoding the continued arm only where a reset
    // within the dictionary made the speculation wrong. The re-encodes
    // after a reset run on a live index of their own over the run's
    // members, appended one at a time (`rerun`): a first cut re-seeded
    // every one of them from the run's history, and with 10 KiB members
    // under a 32 MiB dictionary that was every member for thousands of
    // members after each reset - 24 s of a 26 s wall on the 10,240-member
    // set, serial.
    let max_member = members.iter().map(|m| m.len()).max().unwrap_or(0);
    let mut rerun: Option<(LiveSpanEncoder, Vec<u8>, usize)> = None;
    let mut resolved = Vec::with_capacity(members.len());
    let mut run_start = 0usize;
    for index in 0..members.len() {
        let fresh = fresh_arms[index].take().expect("fresh arm encoded");
        if index == 0 {
            resolved.push((fresh, false));
            continue;
        }
        let run_len: usize = members[run_start..index]
            .iter()
            .map(|member| member.len())
            .sum();
        let continued = if run_start == 0 || run_len >= dictionary {
            continued_arms[index]
                .take()
                .expect("continued arm encoded")
        } else {
            continued_arms[index] = None;
            let (live, span, _) = match rerun.take() {
                Some(state) if state.2 == run_start => state,
                _ => {
                    let mut span = Vec::with_capacity(dictionary + max_member);
                    for member in &members[run_start..index] {
                        span.extend_from_slice(member);
                    }
                    (
                        LiveSpanEncoder::with_capacity(dictionary + max_member),
                        span,
                        run_start,
                    )
                }
            };
            let mut live = live;
            let mut span = span;
            let start = span.len();
            span.extend_from_slice(members[index]);
            let packed = live.encode_member(&span, start, span.len(), algorithm_version, options)?;
            rerun = Some((live, span, run_start));
            packed
        };
        if prefer_fresh(fresh.len(), continued.len()) {
            run_start = index;
            resolved.push((fresh, false));
        } else {
            resolved.push((continued, true));
        }
    }
    Ok(resolved)
}

pub(super) fn encode_options_for_level(
    level: Option<u8>,
    dictionary_size: u64,
    optimal_parse: bool,
    adaptive_entropy_blocks: bool,
    tokenizer_horizon_choice: bool,
    working_memory: Option<usize>,
) -> Result<EncodeOptions> {
    let candidates = match level {
        None => MAX_MATCH_CANDIDATES_DEFAULT,
        Some(0) => 0,
        Some(1) => 8,
        Some(2) => 32,
        Some(3) => 64,
        Some(4) => 48,
        Some(5) => 64,
        Some(_) => {
            return Err(Error::InvalidHeader(
                "RAR 5 compression level must be in the range 0..5",
            ))
        }
    };
    // Research control: vary the ring's candidate budget ALONE. Changing
    // `level` to reach a different budget also flips `lazy_matching` below,
    // so a ladder built out of levels moves two things at once and cannot
    // price the search depth. Profiled 8 Sep 2026 at the SHIPPED 2 MiB
    // dictionary on the 1 GiB mixed corpus, where the tree never arms
    // (`TREE_MIN_DICTIONARY` is 4 MiB): `best_match_probe` and its two
    // callees are 86.8% of non-idle samples, and the budget this reads is
    // what bounds that walk. (nzbfast-local change, 8 Sep 2026; see
    // VENDORING.md.)
    #[cfg(feature = "ratio-lab")]
    let candidates = std::env::var("RARS_MATCH_CANDIDATES")
        .map(|s| {
            let n: usize = s.parse().expect("RARS_MATCH_CANDIDATES is a candidate count");
            assert!(n <= 4096, "RARS_MATCH_CANDIDATES is at most 4096");
            n
        })
        .unwrap_or(candidates);
    let max_match_distance = usize::try_from(dictionary_size).map_err(|_| {
        Error::InvalidHeader("RAR 5 dictionary size exceeds this platform's address space")
    })?;
    Ok(EncodeOptions::new(candidates)
        .with_lazy_matching(matches!(level, None | Some(4..=5)))
        .with_lazy_lookahead(1)
        .with_max_match_distance(max_match_distance)
        .with_optimal_parse(optimal_parse && candidates != 0)
        .with_adaptive_entropy_blocks(adaptive_entropy_blocks)
        .with_tokenizer_horizon_choice(tokenizer_horizon_choice && candidates != 0)
        .with_working_memory(working_memory))
}

pub(super) fn encode_option_candidates_for_level(
    level: Option<u8>,
    dictionary_size: u64,
    optimal_parse: bool,
    adaptive_entropy_blocks: bool,
    tokenizer_horizon_choice: bool,
    working_memory: Option<usize>,
) -> Result<Vec<EncodeOptions>> {
    let mut candidates = vec![encode_options_for_level(
        level,
        dictionary_size,
        optimal_parse,
        adaptive_entropy_blocks,
        tokenizer_horizon_choice,
        working_memory,
    )?];
    if matches!(level, Some(5)) {
        for fallback_level in (1..5).rev() {
            candidates.push(encode_options_for_level(
                Some(fallback_level),
                dictionary_size,
                optimal_parse,
                adaptive_entropy_blocks,
                tokenizer_horizon_choice,
                working_memory,
            )?);
        }
    }
    Ok(candidates)
}

pub(super) fn validate_compression_level(options: WriterOptions) -> Result<()> {
    compression_method_for_level(options.compression_level)?;
    let dictionary_size = dictionary_size_for_options(options)?;
    encode_options_for_level(
        options.compression_level,
        dictionary_size,
        options.optimal_parse,
        options.adaptive_entropy_blocks,
        options.tokenizer_horizon_choice,
        working_memory_for(options),
    )
    .map(|_| ())
}

pub(super) fn rar50_algorithm_version(options: WriterOptions) -> Result<u8> {
    match options.target {
        crate::ArchiveVersion::Rar50 => Ok(0),
        crate::ArchiveVersion::Rar70 => {
            let dictionary_size = dictionary_size_for_options(options)?;
            if dictionary_size_fields(0, dictionary_size).is_ok() {
                Ok(0)
            } else {
                Ok(1)
            }
        }
        _ => Err(Error::UnsupportedVersion(options.target)),
    }
}

pub(super) fn compression_method_for_level(level: Option<u8>) -> Result<u8> {
    match level {
        None => Ok(1),
        Some(level @ 0..=5) => Ok(level),
        Some(_) => Err(Error::InvalidHeader(
            "RAR 5 compression level must be in the range 0..5",
        )),
    }
}

pub(super) fn dictionary_size_for_options(options: WriterOptions) -> Result<u64> {
    let size = options
        .dictionary_size
        .unwrap_or(DEFAULT_RAR50_DICTIONARY_SIZE);
    validate_dictionary_size(options.target, size)?;
    Ok(size)
}

/// The dictionary a compressed set DECLARES, fitted to its payload the way
/// rar 7.23 fits it (measured 7 Sep 2026, `rar lt` on six member sizes
/// under `-md128m`): halve while the dictionary is strictly greater than
/// twice `largest_payload` - the largest member of a non-solid set, the
/// whole set of a solid one - never below the format's 128 KiB floor, and
/// never to a size the target cannot encode. Archive-wide, as rar's is:
/// every member of a set declares the same dictionary. A window the
/// members cannot reach into costs every extractor memory and the writer
/// its index for nothing; a member that reaches it keeps every byte of
/// the request. The encoder's match distance follows the declared size.
/// (nzbfast-local change, 7 Sep 2026; see VENDORING.md.)
pub(super) fn fitted_dictionary_size(
    target: crate::ArchiveVersion,
    requested: u64,
    largest_payload: u64,
) -> u64 {
    let mut size = requested;
    while size > RAR50_DICTIONARY_QUANTUM
        && size / 2 >= RAR50_DICTIONARY_QUANTUM
        && size > largest_payload.saturating_mul(2)
        && validate_dictionary_size(target, size / 2).is_ok()
    {
        size /= 2;
    }
    size
}

/// [`dictionary_size_for_options`] fitted to a compressed set's payload.
/// [`dictionary_size_for_options`] reduced to what a write policy's memory
/// allowance admits, halving on the format's own quantum so the result is
/// still a legal dictionary. Only ever REDUCES: a policy is an allowance,
/// never a request for a wider window than the caller asked for. Applied
/// BEFORE the payload fit, so the two reductions compose and the smaller
/// wins. (nzbfast-local change, 8 Sep 2026; see VENDORING.md.)
pub(super) fn admitted_dictionary_size(
    target: crate::ArchiveVersion,
    requested: u64,
    policy: Option<crate::Rar50WritePolicy>,
) -> u64 {
    let Some(policy) = policy else {
        return requested;
    };
    let mut size = requested;
    while size > RAR50_DICTIONARY_QUANTUM
        && size > policy.max_dictionary
        && size / 2 >= RAR50_DICTIONARY_QUANTUM
        && validate_dictionary_size(target, size / 2).is_ok()
    {
        size /= 2;
    }
    size
}

/// The encoder working-memory allowance a writer's policy sets, in bytes,
/// saturated to this target's `usize`. `None` keeps the host-sized
/// defaults. (nzbfast-local change, 8 Sep 2026; see VENDORING.md.)
pub(super) fn working_memory_for(options: WriterOptions) -> Option<usize> {
    options
        .write_policy
        .map(|policy| usize::try_from(policy.working_memory_limit).unwrap_or(usize::MAX))
}

/// [`dictionary_size_for_options`] fitted to a compressed set's payload.
pub(super) fn dictionary_size_for_payload(
    options: WriterOptions,
    largest_payload: u64,
) -> Result<u64> {
    let requested = admitted_dictionary_size(
        options.target,
        dictionary_size_for_options(options)?,
        options.write_policy,
    );
    Ok(fitted_dictionary_size(
        options.target,
        requested,
        largest_payload,
    ))
}

pub(super) fn validate_dictionary_size(target: crate::ArchiveVersion, size: u64) -> Result<()> {
    match target {
        crate::ArchiveVersion::Rar50 => dictionary_size_fields(0, size).map(|_| ()),
        crate::ArchiveVersion::Rar70 => dictionary_size_fields(0, size)
            .or_else(|_| dictionary_size_fields(1, size))
            .map(|_| ()),
        _ => Err(Error::UnsupportedVersion(target)),
    }
}

pub(super) fn dictionary_size_fields(algorithm_version: u8, size: u64) -> Result<(u8, u8)> {
    if size == 0 {
        return Err(Error::InvalidHeader(
            "RAR 5 dictionary size must be non-zero",
        ));
    }
    match algorithm_version {
        0 => {
            if size < RAR50_DICTIONARY_QUANTUM {
                return Err(Error::InvalidHeader(
                    "RAR 5 v0 dictionary size must be at least 128 KiB",
                ));
            }
            if !size.is_multiple_of(RAR50_DICTIONARY_QUANTUM) {
                return Err(Error::InvalidHeader(
                    "RAR 5 v0 dictionary size must be a power-of-two multiple of 128 KiB",
                ));
            }
            let multiple = size / RAR50_DICTIONARY_QUANTUM;
            if !multiple.is_power_of_two() {
                return Err(Error::InvalidHeader(
                    "RAR 5 v0 dictionary size must be a power-of-two multiple of 128 KiB",
                ));
            }
            let power = multiple.trailing_zeros();
            if power > 15 {
                return Err(Error::InvalidHeader(
                    "RAR 5 v0 dictionary size exceeds 4 GiB",
                ));
            }
            Ok((power as u8, 0))
        }
        1 => {
            if !size.is_multiple_of(4096) {
                return Err(Error::InvalidHeader(
                    "RAR 7 dictionary size must be a multiple of 4 KiB",
                ));
            }
            let mut units = size / 4096;
            let mut power = 0u8;
            while units > 63 {
                if !units.is_multiple_of(2) || power == 31 {
                    return Err(Error::InvalidHeader(
                        "RAR 7 dictionary size is not encodable",
                    ));
                }
                units /= 2;
                power += 1;
            }
            if units < 32 {
                return Err(Error::InvalidHeader(
                    "RAR 7 dictionary size must be at least 128 KiB",
                ));
            }
            Ok((power, (units - 32) as u8))
        }
        _ => Err(Error::InvalidHeader(
            "RAR 5 unknown compression algorithm version",
        )),
    }
}

pub(super) fn compression_info(
    algorithm_version: u8,
    method: u8,
    dictionary_size: u64,
    solid_continuation: bool,
) -> Result<u64> {
    let (dictionary_power, dictionary_fraction) =
        dictionary_size_fields(algorithm_version, dictionary_size)?;
    Ok(u64::from(algorithm_version)
        | (u64::from(method) << 7)
        | (u64::from(dictionary_power) << 10)
        | (u64::from(dictionary_fraction) << 15)
        | solid_compression_flag(solid_continuation))
}

pub(super) fn encode_safe_lz_member(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_lz_member_with_options(data, algorithm_version, options).map_err(Error::from)
}

pub(super) fn encode_safe_lz_member_with_progress(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: &mut dyn FnMut(usize) -> bool,
) -> Result<Vec<u8>> {
    encode_lz_member_with_options_and_progress(data, algorithm_version, options, progress)
        .map_err(Error::from)
}

/// [`encode_safe_lz_member_with_progress`] with the encoder scratch from
/// a pool the caller holds for a whole set of members.
pub(super) fn encode_safe_lz_member_pooled(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
    scratch: &EncoderScratchPool,
) -> Result<Vec<u8>> {
    encode_lz_member_pooled(data, &[], algorithm_version, options, progress, scratch)
        .map_err(Error::from)
}

#[cfg(test)]
pub(super) fn encode_member_with_auto_size_filter(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
) -> Result<Vec<u8>> {
    encode_member_with_auto_size_filter_progress(data, algorithm_version, options, None)
}

fn encode_member_with_auto_size_filter_progress(
    data: &[u8],
    algorithm_version: u8,
    options: EncodeOptions,
    mut progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<Vec<u8>> {
    if data.is_empty() {
        return encode_member_with_filter_policy_and_progress(
            data,
            algorithm_version,
            FilterPolicy::None,
            options,
            progress,
        );
    }
    let mut best = encode_member_with_filter_policy_and_progress(
        data,
        algorithm_version,
        FilterPolicy::None,
        options,
        borrow_progress(&mut progress),
    )?;
    if is_text_like_filter_skip_candidate(data) {
        return Ok(best);
    }
    let mut candidates = vec![FilterKind::E8, FilterKind::E8E9, FilterKind::Arm];
    for channels in 1..=4 {
        candidates.push(FilterKind::Delta { channels });
    }
    for filter in candidates {
        let packed = encode_member_with_filter_progress(
            data,
            algorithm_version,
            filter,
            options,
            borrow_progress(&mut progress),
        )
        .map_err(Error::from)?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    for channels in 1..=4 {
        if let Some(range) = auto_delta_filter_range(data, channels) {
            let packed = encode_member_with_filter_spec_progress(
                data,
                algorithm_version,
                Rar50FilterSpec::range(FilterKind::Delta { channels }, range),
                options,
                borrow_progress(&mut progress),
            )
            .map_err(Error::from)?;
            if packed.len() < best.len() {
                best = packed;
            }
        }
    }
    let e8_candidates = auto_x86_filter_ranges(data, false);
    for range in e8_candidates.iter().cloned() {
        let packed = encode_member_with_filter_spec_progress(
            data,
            algorithm_version,
            Rar50FilterSpec::range(FilterKind::E8, range),
            options,
            borrow_progress(&mut progress),
        )
        .map_err(Error::from)?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    let e8_ranges = disjoint_filter_ranges(e8_candidates);
    if e8_ranges.len() > 1 {
        let filters: Vec<_> = e8_ranges
            .into_iter()
            .map(|range| Rar50FilterSpec::range(FilterKind::E8, range))
            .collect();
        let packed = encode_member_with_filter_specs_progress(
            data,
            algorithm_version,
            &filters,
            options,
            borrow_progress(&mut progress),
        )
        .map_err(Error::from)?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    let e8e9_candidates = auto_x86_filter_ranges(data, true);
    for range in e8e9_candidates.iter().cloned() {
        let packed = encode_member_with_filter_spec_progress(
            data,
            algorithm_version,
            Rar50FilterSpec::range(FilterKind::E8E9, range),
            options,
            borrow_progress(&mut progress),
        )
        .map_err(Error::from)?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    let e8e9_ranges = disjoint_filter_ranges(e8e9_candidates);
    if e8e9_ranges.len() > 1 {
        let filters: Vec<_> = e8e9_ranges
            .into_iter()
            .map(|range| Rar50FilterSpec::range(FilterKind::E8E9, range))
            .collect();
        let packed = encode_member_with_filter_specs_progress(
            data,
            algorithm_version,
            &filters,
            options,
            borrow_progress(&mut progress),
        )
        .map_err(Error::from)?;
        if packed.len() < best.len() {
            best = packed;
        }
    }
    Ok(best)
}

fn is_text_like_filter_skip_candidate(data: &[u8]) -> bool {
    let sample_len = data.len().min(8192);
    if sample_len == 0 {
        return false;
    }
    let sample = &data[..sample_len];
    let text_bytes = sample
        .iter()
        .filter(|&&byte| matches!(byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
        .count();
    text_bytes * 100 / sample_len >= 95
}

pub(super) fn auto_delta_filter_range(
    data: &[u8],
    channels: usize,
) -> Option<std::ops::Range<usize>> {
    if channels == 0 || data.len() <= AUTO_DELTA_EDGE_SKIP * 2 + channels * 8 {
        return None;
    }
    let start = AUTO_DELTA_EDGE_SKIP;
    let end = data.len() - AUTO_DELTA_EDGE_SKIP;
    let aligned_start = start + ((channels - start % channels) % channels);
    let aligned_end = end - (end - aligned_start) % channels;
    (aligned_start + channels * 8 <= aligned_end).then_some(aligned_start..aligned_end)
}

pub(super) fn disjoint_filter_ranges(
    mut ranges: Vec<std::ops::Range<usize>>,
) -> Vec<std::ops::Range<usize>> {
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut disjoint: Vec<std::ops::Range<usize>> = Vec::new();
    for range in ranges {
        if let Some(last) = disjoint.last_mut() {
            if range.start <= last.end {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        disjoint.push(range);
    }
    disjoint
}

fn encode_member_with_filter_progress(
    data: &[u8],
    algorithm_version: u8,
    filter: FilterKind,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> crate::codec::Result<Vec<u8>> {
    let mut encoder = Unpack50Encoder::with_options(options);
    if let Some(progress) = progress {
        encoder.encode_member_with_filters_and_progress(
            data,
            algorithm_version,
            &[Rar50FilterSpec::new(filter)],
            progress,
        )
    } else {
        Unpack50Encoder::with_options(options).encode_member_with_filter(
            data,
            algorithm_version,
            Rar50FilterSpec::new(filter),
        )
    }
}

fn encode_member_with_filter_spec_progress(
    data: &[u8],
    algorithm_version: u8,
    filter: Rar50FilterSpec,
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> crate::codec::Result<Vec<u8>> {
    encode_member_with_filter_specs_progress(data, algorithm_version, &[filter], options, progress)
}

fn encode_member_with_filter_specs_progress(
    data: &[u8],
    algorithm_version: u8,
    filters: &[Rar50FilterSpec],
    options: EncodeOptions,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> crate::codec::Result<Vec<u8>> {
    let mut encoder = Unpack50Encoder::with_options(options);
    match progress {
        Some(progress) => encoder.encode_member_with_filters_and_progress(
            data,
            algorithm_version,
            filters,
            progress,
        ),
        None => encoder.encode_member_with_filters(data, algorithm_version, filters),
    }
}

#[cfg(test)]
pub(super) fn encode_member_with_filter_spec(
    data: &[u8],
    algorithm_version: u8,
    filter: Rar50FilterSpec,
    options: EncodeOptions,
) -> crate::codec::Result<Vec<u8>> {
    Unpack50Encoder::with_options(options).encode_member_with_filter(
        data,
        algorithm_version,
        filter,
    )
}

#[cfg(test)]
pub(super) fn encode_member_with_filter_specs(
    data: &[u8],
    algorithm_version: u8,
    filters: &[Rar50FilterSpec],
    options: EncodeOptions,
) -> crate::codec::Result<Vec<u8>> {
    Unpack50Encoder::with_options(options).encode_member_with_filters(
        data,
        algorithm_version,
        filters,
    )
}

pub(super) fn solid_compression_flag(solid_continuation: bool) -> u64 {
    if solid_continuation {
        0x40
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize, mut seed: u32) -> Vec<u8> {
        (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect()
    }

    fn decode(packed: &[u8], len: usize) -> Vec<u8> {
        crate::codec::rar50::Unpack50Decoder::new()
            .decode_member(packed, 0, len, false, crate::codec::rar50::DecodeMode::Lz)
            .unwrap()
    }

    #[test]
    fn sampled_filters_vote_per_region_skip_text_and_noise_and_round_trip() {
        let region = SAMPLED_FILTER_REGION;
        let mut data = Vec::with_capacity(region * 6);
        while data.len() < region * 2 {
            data.extend_from_slice(b"the quick brown fox jumps over the lazy dog, and again;\n");
        }
        data.truncate(region * 2);
        let mut counter: u32 = 0x1000_0000;
        while data.len() < region * 4 {
            data.extend_from_slice(&counter.to_le_bytes());
            counter = counter.wrapping_add(7919);
        }
        data.truncate(region * 4);
        data.extend(noise(region * 2, 11));
        let options = EncodeOptions::new(256)
            .with_lazy_matching(true)
            .with_max_match_distance(4 << 20);

        let specs = select_sampled_filters(&data, options);
        assert_eq!(
            specs.len(),
            2,
            "one vote per record region, none for text or noise: {specs:?}"
        );
        assert_eq!(specs[0].range, Some(region * 2..region * 3));
        assert_eq!(specs[1].range, Some(region * 3..region * 4));
        assert!(
            specs
                .iter()
                .all(|spec| matches!(spec.kind, FilterKind::Delta { .. })),
            "{specs:?}"
        );
        assert!(
            select_sampled_filters(&data, EncodeOptions::new(0)).is_empty(),
            "a storing level filters nothing"
        );

        let plain =
            encode_member_with_filter_policy(&data, 0, FilterPolicy::None, options).unwrap();
        let sampled =
            encode_member_with_filter_policy(&data, 0, FilterPolicy::Sampled, options).unwrap();
        assert!(
            sampled.len() < plain.len(),
            "{} vs {}",
            sampled.len(),
            plain.len()
        );
        assert_eq!(decode(&sampled, data.len()), data);

        // A member that votes nothing is `None`, byte for byte.
        let text = &data[..region * 2];
        assert!(select_sampled_filters(text, options).is_empty());
        assert_eq!(
            encode_member_with_filter_policy(text, 0, FilterPolicy::Sampled, options).unwrap(),
            encode_member_with_filter_policy(text, 0, FilterPolicy::None, options).unwrap()
        );
        // Short and empty members are legal input.
        for len in [0, 1, 7, 4096, region + 1] {
            let short = &data[region * 2..region * 2 + len];
            let packed =
                encode_member_with_filter_policy(short, 0, FilterPolicy::Sampled, options).unwrap();
            assert_eq!(decode(&packed, short.len()), short);
        }
    }

    #[test]
    fn sampled_filter_probe_reuse_preserves_bytes_across_kinds_and_shapes() {
        let options = EncodeOptions::new(8)
            .with_lazy_matching(true)
            .with_max_match_distance(SAMPLED_FILTER_PROBE_LEN);
        let scratch = EncoderScratchPool::new();
        // Large, tiny, empty, and regrown shapes deliberately share one pool.
        // Reusing the storage must never carry matches or filter history.
        for (turn, len) in [SAMPLED_FILTER_PROBE_LEN, 7, 0, 4096, SAMPLED_FILTER_PROBE_LEN]
            .into_iter()
            .enumerate()
        {
            let data: Vec<u8> = (0..len)
                .map(|i| ((i * 17 + i / (turn + 1) + turn * 71) % 251) as u8)
                .collect();
            for kind in std::iter::once(None).chain(
                SAMPLED_FILTER_KINDS
                    .into_iter()
                    .chain(SAMPLED_FILTER_DELTA_KINDS)
                    .map(Some),
            ) {
                let mut fresh = Unpack50Encoder::with_options(options);
                let expected = match kind {
                    None => fresh.encode_member(&data, 0),
                    Some(kind) => fresh.encode_member_with_filter(
                        &data, 0, Rar50FilterSpec::new(kind),
                    ),
                }
                .map_err(|error| format!("{error:?}"));
                assert_eq!(
                    encode_sampled_filter_probe(&data, kind, options, &scratch)
                        .map_err(|error| format!("{error:?}")),
                    expected,
                    "turn={turn}, len={len}, kind={kind:?}",
                );
            }
        }
    }

    /// Timing rig for the sampled selector, not a test: `RARS_FILTER_INPUT=<file>
    /// cargo test --release -p rars --features parallel --lib -- --ignored
    /// sampled_filter_timing --nocapture` prints the selector's own time
    /// and votes, then the member's encode time and bytes unfiltered and
    /// under the votes, both through the writer's 32 MiB optimal-parse
    /// options.
    #[test]
    #[ignore]
    fn sampled_filter_timing() {
        let Ok(path) = std::env::var("RARS_FILTER_INPUT") else {
            return;
        };
        let data = std::fs::read(path).unwrap();
        let options = encode_options_for_level(None, 32 << 20, true, true, false, None).unwrap();
        let started = std::time::Instant::now();
        let specs = select_sampled_filters(&data, options);
        let select = started.elapsed();
        let mut votes = std::collections::BTreeMap::new();
        for spec in &specs {
            *votes.entry(format!("{:?}", spec.kind)).or_insert(0usize) += 1;
        }
        let regions = data.len().div_ceil(SAMPLED_FILTER_REGION);
        eprintln!("select {select:?} over {regions} regions, votes {votes:?}");
        for (name, policy) in [
            ("none", FilterPolicy::None),
            ("sampled", FilterPolicy::Sampled),
        ] {
            let started = std::time::Instant::now();
            let packed = encode_member_with_filter_policy(&data, 0, policy, options).unwrap();
            eprintln!("{name}: {} bytes in {:?}", packed.len(), started.elapsed());
        }
        // The shape alone: the member delta-2-transformed by hand (channel
        // planes of byte differences, the RAR DELTA layout) and encoded
        // unfiltered, so the filtered encode's time has something to be
        // compared against that carries no filter records.
        let channels = 2usize;
        let mut planes = vec![0u8; data.len()];
        let plane_len = data.len() / channels;
        for channel in 0..channels {
            let mut previous = 0u8;
            for (index, slot) in planes[channel * plane_len..(channel + 1) * plane_len]
                .iter_mut()
                .enumerate()
            {
                let byte = data[index * channels + channel];
                *slot = byte.wrapping_sub(previous);
                previous = byte;
            }
        }
        let started = std::time::Instant::now();
        let packed =
            encode_member_with_filter_policy(&planes, 0, FilterPolicy::None, options).unwrap();
        eprintln!(
            "transformed, unfiltered: {} bytes in {:?}",
            packed.len(),
            started.elapsed()
        );
    }

    /// rar 7.23's payload-fit reduction, row for row from the 7 Sep 2026
    /// study (`-md128m` asked, `rar lt` read back), plus the floor, the
    /// "no reduction" side, and a solid set fitting its total.
    #[test]
    fn fitted_dictionary_follows_rar_row_for_row() {
        let mib = 1u64 << 20;
        let target = crate::ArchiveVersion::Rar50;
        for (largest, declared) in [
            (3 * mib, 4 * mib),
            (5 * mib, 8 * mib),
            (8 * mib, 16 * mib),
            (9 * mib, 16 * mib),
            (17 * mib, 32 * mib),
            (33 * mib, 64 * mib),
        ] {
            assert_eq!(
                fitted_dictionary_size(target, 128 * mib, largest),
                declared,
                "largest member {largest}"
            );
        }
        // Never below the format's floor, never above the request.
        assert_eq!(fitted_dictionary_size(target, 32 * mib, 1), 128 * 1024);
        assert_eq!(fitted_dictionary_size(target, 128 * 1024, 1), 128 * 1024);
        assert_eq!(
            fitted_dictionary_size(target, 32 * mib, 200 * mib),
            32 * mib
        );
        // Exactly twice the member is kept (strictly greater halves).
        assert_eq!(fitted_dictionary_size(target, 4 * mib, 2 * mib), 4 * mib);
        assert_eq!(
            fitted_dictionary_size(target, 4 * mib, 2 * mib - 1),
            2 * mib
        );
        // The writer's default, through the options.
        let options = WriterOptions::new(target, crate::FeatureSet::default());
        assert_eq!(
            dictionary_size_for_payload(options, 200 * 1024).unwrap(),
            256 * 1024
        );
        assert_eq!(
            dictionary_size_for_payload(options, 64 * mib).unwrap(),
            DEFAULT_RAR50_DICTIONARY_SIZE
        );
    }

    #[test]
    fn incompressible_sampling_stores_noise_and_keeps_encoding_anything_with_a_compressible_sample()
    {
        let options = EncodeOptions::new(8).with_max_match_distance(128 * 1024);
        let random = noise(INCOMPRESSIBLE_SAMPLE_MIN + 4096, 7);
        assert!(sampled_incompressible(&random, 0, options));
        assert!(
            !sampled_incompressible(&random[..INCOMPRESSIBLE_SAMPLE_MIN - 1], 0, options),
            "under the size floor the full encode decides, as before"
        );
        assert!(
            !sampled_incompressible(&random, 0, EncodeOptions::new(0)),
            "no matching means the encode is one literal run, no sample can say otherwise"
        );
        let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog "
            .iter()
            .copied()
            .cycle()
            .take(INCOMPRESSIBLE_SAMPLE_MIN + 4096)
            .collect();
        assert!(!sampled_incompressible(&text, 0, options));
        // A compressible region under any one of the three samples keeps
        // the full encode; one that all three miss is stored (the trade).
        let mut tail = random.clone();
        let n = tail.len();
        tail[n - (1 << 19)..].fill(b'z');
        assert!(!sampled_incompressible(&tail, 0, options));
        let mut hidden = random.clone();
        hidden[3 << 20..4 << 20].fill(b'z');
        assert!(sampled_incompressible(&hidden, 0, options));
        // A 1 MiB block repeated: random inside any 256 KiB window, a
        // thousand-to-one at a dictionary that reaches the previous copy.
        let block = noise(1 << 20, 11);
        let repeated: Vec<u8> = block.iter().copied().cycle().take(64 << 20).collect();
        assert!(
            sampled_incompressible(&repeated, 0, options),
            "a 128 KiB dictionary cannot reach the repeat, so storing is right"
        );
        assert!(
            !sampled_incompressible(&repeated, 0, options.with_max_match_distance(32 << 20)),
            "a 32 MiB dictionary reaches it, so the sample must be long enough to see it"
        );
        assert_eq!(incompressible_sample_len(64 << 20, 32 << 20), (64 << 20) / 15);
        assert_eq!(incompressible_sample_len(1 << 30, 32 << 20), 32 << 20);
        assert_eq!(incompressible_sample_len(1 << 30, 128 << 10), 256 << 10);
    }

    /// The pooled solid resolve is the serial walk, packed bytes and
    /// flags alike, under the real rule and under a swapped rule that
    /// forces resets - so the re-encode of a continued arm within a
    /// dictionary of a reset is exercised, with members shorter than the
    /// dictionary and one longer.
    #[test]
    fn pooled_solid_resolve_matches_the_serial_walk() {
        let text = |len: usize, seed: u64| -> Vec<u8> {
            let words = [
                "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
            ];
            let mut state = seed;
            let mut out = Vec::with_capacity(len + 8);
            while out.len() < len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                out.extend_from_slice(words[(state >> 61) as usize].as_bytes());
                out.push(b' ');
            }
            out.truncate(len);
            out
        };
        let members: Vec<Vec<u8>> = vec![
            text(3_000, 1),
            text(2_500, 2),
            text(9_000, 3),
            (0..4_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect(),
            text(2_000, 4),
            text(1_500, 5),
            text(6_000, 6),
        ];
        let slices: Vec<&[u8]> = members.iter().map(Vec::as_slice).collect();
        let options = EncodeOptions::new(16).with_max_match_distance(4_096);
        // A second set of many tiny members under a dictionary that spans
        // dozens of them: the live index runs member after member within a
        // group there.
        let tiny: Vec<Vec<u8>> = (0..60u64)
            .map(|i| {
                if i % 9 == 4 {
                    (0..700u32)
                        .map(|k| ((k + i as u32).wrapping_mul(2_654_435_761) >> 13) as u8)
                        .collect()
                } else {
                    text(300 + (i as usize * 37) % 1_700, 100 + i)
                }
            })
            .collect();
        let tiny_slices: Vec<&[u8]> = tiny.iter().map(Vec::as_slice).collect();
        let grown: Vec<Vec<u8>> = (0..24u64).map(|i| text(90_000 + (i as usize * 1_013) % 40_000, 500 + i)).collect();
        let grown_slices: Vec<&[u8]> = grown.iter().map(Vec::as_slice).collect();
        let rules: [(&str, fn(usize, usize) -> bool); 2] = [
            ("smaller wins", |fresh, continued| fresh < continued),
            ("fresh wins ties and more", |fresh, continued| fresh <= continued + 4),
        ];
        for (name, rule, slices, options) in [
            (rules[0].0, rules[0].1, &slices, options),
            (rules[1].0, rules[1].1, &slices, options),
            (
                "tiny members, smaller wins",
                rules[0].1,
                &tiny_slices,
                EncodeOptions::new(16).with_max_match_distance(32 << 10),
            ),
            (
                "tiny members, fresh wins ties and more",
                rules[1].1,
                &tiny_slices,
                EncodeOptions::new(16).with_max_match_distance(32 << 10),
            ),
            // A dictionary the history grows past member by member: the
            // index's shape changes early in the run and settles.
            (
                "growing history, smaller wins",
                rules[0].1,
                &grown_slices,
                EncodeOptions::new(16).with_max_match_distance(1 << 20),
            ),
        ] {
            // The serial walk, as the encoder-based policy runs it.
            let mut expected = Vec::new();
            let mut encoder = Unpack50Encoder::with_options(options);
            for (index, member) in slices.iter().enumerate() {
                if index == 0 {
                    expected.push((encoder.encode_member(member, 0).unwrap(), false));
                    continue;
                }
                let continued = encoder.encode_member(member, 0).unwrap();
                let mut fresh_encoder = Unpack50Encoder::with_options(options);
                let fresh = fresh_encoder.encode_member(member, 0).unwrap();
                if rule(fresh.len(), continued.len()) {
                    encoder = fresh_encoder;
                    expected.push((fresh, false));
                } else {
                    expected.push((continued, true));
                }
            }
            let resolved =
                resolve_solid_members_with_rule(slices, 0, options, None, rule).unwrap();
            assert_eq!(
                resolved.iter().map(|(_, flag)| *flag).collect::<Vec<_>>(),
                expected.iter().map(|(_, flag)| *flag).collect::<Vec<_>>(),
                "{name}: continuation flags"
            );
            assert_eq!(resolved, expected, "{name}: packed bytes");
            if name.contains("fresh wins") {
                assert!(
                    resolved.iter().skip(1).any(|(_, flag)| !flag),
                    "{name}: the swapped rule forced a reset"
                );
            }
        }
    }

}
