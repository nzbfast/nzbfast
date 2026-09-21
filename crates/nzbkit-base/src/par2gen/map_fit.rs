//! Which payload reads go through a mapping, and whether a mapping of the
//! whole corpus can stay resident while the transform walks it.
//!
//! Cut out of `par2gen` on 16 Sep 2026 when the headroom term took the file
//! past the 4,000-line ceiling: the seam is the mapping ADMISSION policy -
//! the `NZBFAST_PAR2GEN_MAP` mode, the fit gate and the create's own working
//! set - which nothing else in the parent reads into.

use super::ntt_range;

/// Which payload reads go through a mapping. `NZBFAST_PAR2GEN_MAP=0`:
/// none, every read on the copied paths. Unset: the TRANSFORM reads its
/// corpus mapped (unix since 2 Sep 2026, Windows since 5 Sep) and the
/// scan and the direct fold keep their reads. `all`: the scan and the
/// direct fold read the mapping too.
///
/// `all` is the measured negative that shaped the default (the
/// mapped-inputs handoff, rounds L-M, i5-10600KF and M3 Ultra, 5 Sep
/// 2026): on the 1 MiB create it takes 0.5-1.0 s of kernel time OUT of
/// the process and still costs 0.05-0.10 s of WALL, on both boxes, with
/// or without the populate hint - soft faults taken inside twelve scan
/// lanes and six fold workers serialise where a read's copy did not.
/// The transform's stripe-wise walk does not pay that: 64 KiB create
/// 3.47-3.69 s mapped against 3.53-3.71 copied on the i5, 0.3 s less
/// kernel time.
pub(super) fn map_inputs_enabled() -> bool {
    !ntt_range::map_off_pinned() && map_mode() != MapMode::Off
}

/// Whether the scan and the direct fold read mapped members (see
/// [`map_inputs_enabled`]): only under `NZBFAST_PAR2GEN_MAP=all`.
pub(super) fn map_scan_and_fold_enabled() -> bool {
    map_mode() == MapMode::All
}

/// Whether a mapping of `payload` bytes can stay RESIDENT while the
/// transform walks it, which is the only condition under which reading
/// the corpus through a mapping is the fast route (TODO 345).
///
/// The transform's walk is stripe-wise: every one of its ~1,440 stripes
/// touches every source slice. A mapping that fits is read once and then
/// served from the page cache; one that does not is faulted back in from
/// disk over and over. Measured 15 Sep 2026 on a Core Ultra 9 laptop
/// (32 GB, Windows, 32,768 slices, 5%): a 45 GiB member created in 532 s
/// mapped, reading 320 GB off the disk and taking 5.6 M hard page reads,
/// against 102 s on the copied windows over the same bytes; skipping only
/// the whole-mapping PREFETCH changed nothing (544 s). A 12 GiB member on
/// the same box stays mapped: the copied windows cost it 22% of wall there.
///
/// **The line is the payload against AVAILABLE memory, and nothing else.**
/// Measured the same day on a Ryzen 7 9800X3D (61.6 GB) with physical RAM
/// pinned away to set what the cache could hold, one 24 GiB (25.8 GB)
/// member at 5%: mapped 27.4 s with 26.6 GB available (no faults to speak
/// of), 116.9 s with 20.4 GB and 164.8 s with 14.3 GB; the copied windows
/// 34.6-36.1 s at every one of those. The process budget is not a term: the
/// same member at `-m8192` unlocked mapped in 27.4 s, and 26.6 GB held
/// the mapping with only ~0.8 GB to spare. The copied windows' ~26% cost
/// while a mapping fits is why the gate is not simply "never map".
///
/// **A CGROUP LIMIT IS A TERM, AND IT IS NOT THE PROCESS BUDGET.** The
/// paragraph above rules out `-m` and is right to: `-m` does not bound the
/// page cache. A cgroup limit is a different object and DOES bound it, and
/// until 16 Sep 2026 this gate could not see one - `mem::available_ram()`
/// reads `/proc/meminfo`, which is not namespaced, so inside a container it
/// answers for the HOST. Measured that day on an 8-core 31 GB Linux box, one
/// 2 GiB member at 5%, `MemAvailable` reading 30.9 GB inside every container:
/// at a 1 GiB limit the gate admitted the mapping and the create took 147 s
/// with 1.04 M major faults and 34.4 GB read for a 2 GiB member, against
/// 4.0-4.3 s and 2.0 GB at 3 and 4 GiB. The gate now takes the tighter of the
/// machine and the cgroup (`mem::cgroup_available_ram`).
///
/// NOTE WHAT THE SAME ROUND FOUND BELOW THAT BAND, because it bounds how much
/// this gate can ever be worth in a container: at 512 MiB and 768 MiB the
/// create never reaches the transform at all. `create_ntt_window` needs
/// NTT_WINDOW_MIN slices of `MemBudget` budget, and that budget is already
/// cgroup-aware, so it routes to the direct fold first and all three arms
/// land within 1.3 s of each other. The gate is reachable only in the band
/// where the budget admits the transform and the WHOLE payload still exceeds
/// what the cgroup can hold - on this shape, 1 GiB to 2 GiB.
///
/// AND THE CGROUP READING TAKES A HEADROOM TERM, SINCE 16 SEP 2026, BECAUSE
/// THE HOST READING AND THE CGROUP READING ARE NOT THE SAME QUANTITY. The
/// round above left a band it measured and did not close, and a finer ladder
/// on the same box, fixture and binary the same day made it worse than it
/// had looked: the old composition admitted from 2,161 MiB of limit for a
/// 2 GiB payload (`payload + 113 MiB`, the create's anon charge when the gate
/// is asked), and the mapped route does not overtake the copied windows until
/// about 2,290. Three reps per rung, medians, the `def` arm on the shipped
/// binary, cgroup `memory.stat` counters:
///
/// | limit | wall | cgroup major faults |
/// |---|---|---|
/// | 2,160 MiB | 5.5 s - REFUSED, the copied windows | 0 |
/// | 2,180 MiB | 18.5 s mapped | 85-99 k |
/// | 2,220 MiB | 19.4 s mapped | 72-75 k |
/// | 2,260 MiB | 9.7 s mapped | 34-37 k |
/// | 2,300 MiB | 4.5 s mapped | 2.5-2.7 k |
/// | 2,350 MiB | 4.4 s mapped | 2.5-2.8 k |
///
/// So the residual band cost up to **3.4x**, not the 1.3x the coarse ladder
/// read off two rungs. What was missing is this create's OWN working set,
/// which is allocated AFTER this question is asked: [`create_map_headroom`].
/// With it, the same rungs read 5.5 / 5.9 / 6.0 / 5.4 / 5.4 / 5.4 s - the
/// copied windows' flat wall - so the term buys 3.1x at 2,180, 3.2x at 2,220
/// and 1.8x at 2,260 and pays about 20% at 2,300 and 2,350, where the mapping
/// was right and the term refuses it anyway. That overshoot is stated rather
/// than tuned away: the term is a DERIVED upper bound on what the create adds
/// and the crossover that would tune it exactly (~131 MiB on this shape) is
/// an INTERPOLATION between two rungs on one box, which is not a thing to set
/// a constant from.
///
/// **AND THE ACCUMULATOR ALONE IS NOT THE BETTER TERM - asked, bracketed and
/// answered on the same box the next day (section 9 of the round's
/// write-up).** The accumulator is 107.3 MiB here against the full term's
/// 255.7, so it would have put the boundary within 22 MiB of the crossover
/// where the full term is 127 MiB past it, which is a better residual on one
/// ladder and no reason at all to drop a term. The arena half is separable
/// from the accumulator by exactly one knob - `NZBFAST_NTT_THREADS`, because
/// [`ntt_range::worker_arenas`] is per-worker scratch TIMES the pool while
/// `count * bs` never sees the pool, where `-b` and `-r` move both halves
/// together through the row count - and at a 16-worker pin the mapped route's
/// knee MOVED with it. The binary printed its own term at both pins rather
/// than the round computing one (`headroom 268099584 B` on eight workers,
/// `428851200 B` on sixteen: 153.3 MiB more arena and not one byte of
/// accumulator), and over 102 legs on one fixture and one recovery set the
/// wall reaches its floor at a 2,280 MiB limit on eight workers and at 2,400
/// on sixteen, with the cgroup's major-fault contours shifting +90 to
/// +160 MiB. Accumulator-alone predicts zero shift on every one of those
/// lines. Both halves stay.
///
/// **THAT ROUND'S RESIDUAL IS NOW MEASURED, AND IT WAS THE READING - 18 Sep
/// 2026, section 10.** It recorded the overshoot as likeliest being the
/// reading rather than the arenas, and was right: `limit - (usage - cache)`
/// had already deducted the accumulator at the moment the gate was asked, and
/// the gross term added it a second time. Read at the decision point on the
/// same box, shape and fixture, with the binary printing its own figures - a
/// 107,347,968 B accumulator against a 112,021,504 B anon RSS and a
/// 114,008,064 B unreclaimable charge, so the accumulator is 96% of
/// everything this create has resident when it asks. Both halves separate
/// cleanly: `NZBFAST_NTT_THREADS=16` DOUBLES the arenas to 321,503,232 B and
/// moves the charge by 8 KB, while `-r10` doubles the accumulator to
/// 214,761,472 B and the charge follows it to 221,761,536 B. So the charge is
/// the accumulator and never the gross term - at `-r10` the gross is
/// 496,353,280 B and the charge 219,512,832 B - and the ~4.7 MB by which anon
/// exceeds the accumulator is constant across all three legs and is this
/// create's genuine other anon. [`headroom_net`] is the arithmetic that
/// stopped paying for it twice. The arena half's own smaller over-count
/// stands, RECORDED and not tuned.
///
/// **The term is applied to the cgroup reading ONLY, and that asymmetry is
/// measured rather than cautious.** [`crate::mem::cgroup_available_ram`] is
/// `limit - (usage - cache)`: a HARD limit less the charge that cannot be
/// reclaimed, taken at a moment when this create has allocated its
/// accumulators and - measured 18 Sep 2026, contrary to what this paragraph
/// claimed until then - already TOUCHED every page of them, which is what
/// [`headroom_net`] credits back. The bytes it has NOT yet touched, the
/// arenas, are charged to the same limit the mapping is, so they are
/// genuinely
/// not in that reading and subtracting them is the arithmetic the reading
/// already implies. [`crate::mem::available_ram`] is a different object -
/// `MemAvailable`, Windows' `ullAvailPhys`, macOS's free-plus-purgeable - an
/// ESTIMATE of what an allocation can take without paging, with the kernel's
/// own reserve already deducted, and not a wall. Subtract a working set from
/// it and you count that reserve twice. The 15 Sep Ryzen 7 9800X3D leg says
/// so directly: a 24 GiB member at 5% (1,638 rows of 768 KiB) mapped in
/// 27.2 s against the copied windows' 34.5 with 26.6 GB available, ~0.8 GB
/// clear of the payload - while this create's working set on that shape is
/// ~1.5 GiB, so by the term's own arithmetic that leg had NEGATIVE spare and
/// was still right by 26%. A host-side term would have refused it. The host
/// decision is therefore unchanged BY CONSTRUCTION, not by a tuned constant:
/// where no cgroup reading exists - every Mac, every Windows box, every
/// uncontained Linux - this function asks exactly what it asked before.
///
/// `NZBFAST_PAR2GEN_MAP_FIT=off` maps whatever fits the address space, as
/// every create did before this gate - the A/B arm. Where the OS reports no
/// available-memory figure the gate stays open, so that route is unchanged
/// there.
///
/// macOS reports one since 16 Sep 2026, and the same knee is there: a
/// 48 GiB member on a 32 GiB MacBook Air mapped in 316 s and 353 s against
/// 124 s on the copied windows, ~245 GB paged in for a 51.5 GB member,
/// while the gated legs refused and walled with the copied windows; a
/// 13 GiB control on that box never refused (TODO 345 D,
/// `mem::available_ram`, section 6.5). The rounds, their harness and the
/// per-leg counters are in research/PARFAST-OVER-RAM-CREATE-2026-09-15.md.
pub(super) fn mapped_payload_fits_memory(payload: u64, headroom: u64) -> bool {
    if matches!(
        std::env::var("NZBFAST_PAR2GEN_MAP_FIT").ok().as_deref(),
        Some("off") | Some("0")
    ) {
        return true;
    }
    let host = crate::mem::available_ram();
    let cgroup = crate::mem::cgroup_available_ram();
    let fits = mapped_payload_fits(payload, headroom, host, cgroup);
    if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
        // THE COMPOSITION, on BOTH the admit and the refuse path, because the
        // question "is this create's own charge counted twice" is answered by
        // the parts and not by the verdict - and an admitted leg is exactly
        // the leg whose parts say whether the refusal next door was right.
        // A shell reading /sys/fs/cgroup around the create reads a different
        // instant: the accumulators are allocated before this call and touched
        // after it, so the charge moves by more than the difference under test.
        for line in crate::mem::cgroup_probe_lines() {
            tracing::info!(target: "repair-timing", "create map gate: {line}");
        }
        if let Some(rss) = crate::mem::self_rss_probe() {
            tracing::info!(target: "repair-timing", "create map gate: {rss}");
        }
    }
    if !fits && std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
        // WHICH reading bound it, because on Linux they can differ by an
        // order and a reader of the refusal cannot otherwise tell a small
        // machine from a small cgroup - and the headroom term applies to only
        // one of them, so a refusal that names one figure explains nothing.
        tracing::info!(
            target: "repair-timing",
            "create map refused: payload {payload} B + headroom {headroom} B against host {} B, cgroup {} B (the headroom binds the cgroup reading only) - the copied windows take it",
            host.map_or_else(|| "none".to_string(), |v| v.to_string()),
            cgroup.map_or_else(|| "none".to_string(), |v| v.to_string()),
        );
    }
    fits
}

/// Pure half of [`mapped_payload_fits_memory`]. Both readings must admit,
/// and only the cgroup one is asked to hold the create's own working set -
/// see that function's docstring for why the two are not interchangeable.
fn mapped_payload_fits(
    payload: u64,
    headroom: u64,
    host: Option<u64>,
    cgroup: Option<u64>,
) -> bool {
    host.is_none_or(|host| payload <= host)
        && cgroup.is_none_or(|cgroup| payload.saturating_add(headroom) <= cgroup)
}

/// What this create is about to make resident BESIDES the corpus, for
/// [`mapped_payload_fits_memory`]'s cgroup arm: the recovery accumulators it
/// has allocated but not yet touched, plus the transform's per-worker arenas.
///
/// **Derived from the shape, never a constant.** Both terms move with the
/// block size, the row count and the worker pool, and a figure fitted to one
/// of those is wrong at the next one - the two shapes this gate has been
/// measured on differ by 14x in it (256 MiB on a 2 GiB member at 64 KiB
/// blocks on 8 threads, ~1.5 GiB on a 24 GiB member at 768 KiB blocks on 16).
///
/// - `count * bs` is `recovery_slices`' accumulator, `vec![vec![0u16; words];
///   count]`, allocated BEFORE this gate is asked and **fully resident by the
///   time it is**. This bullet claimed the opposite until 18 Sep 2026 - that a
///   zeroed `Vec` is lazy pages the cgroup has not been billed for, and that
///   the anon charge at the gate was therefore ~50 MiB on a shape whose
///   accumulator is 102 MiB. Both halves were wrong. The INNER `vec![0u16;
///   words]` is lazy, because `u16` is `IsZero` and that specialisation
///   reaches `alloc_zeroed`; the OUTER `vec![inner; count]` is not, because
///   `Vec<u16>` is not `IsZero`, so `from_elem` CLONES the inner vector
///   `count - 1` times and every clone memcpys into every destination page.
///   It is the same line the 17 Sep hit-wall round priced at 3.3 ms per row
///   (`research/HIT-WALL-LINEAR-TERM-2026-09-17.md`), which is a measurement
///   of those writes. Measured directly at the gate on 18 Sep: 107,347,968 B
///   of accumulator against a 112,021,504 B anon RSS. [`headroom_net`]
///   credits it back for that reason, and would stop crediting it on its own
///   if that allocation were ever made lazy. (`NZBFAST_CREATE_WS_LOCK=1`
///   claims to touch them up front; note it is `#[cfg(windows)]` - a
///   `VirtualLock` loop - so it is a NO-OP on the only platform where a
///   cgroup reading exists at all, and cannot be used as a control arm here.)
/// - [`ntt_range::worker_arenas`] is what `create_ntt_window` already
///   subtracts from the transform's budget for exactly this reason, so the
///   crate has one name for "what the transform needs besides the corpus"
///   and this reuses it rather than deriving a second estimate that could
///   drift. It prices the REPAIR's stripe width, which differs from the
///   create's only on x86 nibble arms at 1 MiB and up (512 words against
///   1,024), so it understates those by a factor of two in a term that is
///   itself the smaller half - and understating is the safe direction here,
///   since it can only leave the old admission.
///
/// Not counted: the short-tail pad arena, which is bounded by the mapped
/// path's own `pad_cap` and is a few MiB next to either term above.
pub(super) fn create_map_headroom(bs: usize, first: usize, count: usize) -> u64 {
    let arenas = ntt_range::worker_arenas(bs, first, count);
    let gross = headroom_from(bs, count, arenas);
    let accumulator = (count as u64).saturating_mul(bs as u64);
    let own = if own_charge_credit_enabled() {
        crate::mem::self_anon_rss()
    } else {
        None
    };
    let net = headroom_net(accumulator, arenas as u64, own);
    if std::env::var_os("NZBFAST_REPAIR_TIMING").is_some() {
        // The halves NAMED, and the credit beside them: the two halves are
        // separable only by the worker pin, so a reader of one total cannot
        // tell which moved, and the credit is the term a reader of a moved
        // boundary would otherwise attribute to the wrong half.
        tracing::info!(
            target: "repair-timing",
            "create map headroom: net {net} B = accumulator {accumulator} B \
             ({count} rows x {bs} B) + arenas {arenas} B - own-anon credit {} B \
             (gross {gross}, own anon {})",
            gross.saturating_sub(net),
            own.map_or_else(|| "none".to_string(), |v| v.to_string()),
        );
    }
    net
}

/// Whether the own-charge credit [`headroom_net`] applies is read once and is
/// off only under `NZBFAST_PAR2GEN_MAP_OWN_CHARGE=0` - the A/B door the
/// bracketing round drove, kept because it is the only way to walk one
/// binary's boundary both ways on one fixture, which is what a composition
/// change has to be shown by.
fn own_charge_credit_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("NZBFAST_PAR2GEN_MAP_OWN_CHARGE")
                .ok()
                .as_deref(),
            Some("0") | Some("off")
        )
    })
}

/// The headroom term LESS the part of it this create has already made
/// resident, which [`crate::mem::cgroup_available_ram`] has already deducted.
///
/// **This is the double count the 16 Sep round recorded and the 18 Sep round
/// measured.** The reading is `limit - (usage - cache)`, and `usage - cache`
/// is the cgroup's unreclaimable charge AT THE INSTANT THE GATE IS ASKED. The
/// gross term is what the create will hold BESIDES the corpus. Those two
/// overlap by whatever of the term is resident already, and adding the whole
/// term to a reading that has already deducted it charges the overlap twice -
/// worth 102 MiB of a ~140 MiB overshoot on the measured shape, paid as a
/// refused mapping on every containerised create in the band.
///
/// **The overlap is the ACCUMULATOR and not the arenas, which is why the
/// credit is capped at the accumulator rather than taken whole.** The
/// accumulator is `vec![vec![0u16; words]; count]` in `recovery_slices`,
/// allocated before this gate is asked - and `Vec<u16>` is not `IsZero`, so
/// `from_elem` CLONES the inner vector `count - 1` times and every clone
/// writes every destination page. It is therefore fully resident and fully
/// charged by the time the gate runs, whatever the older reasoning here said
/// about a zeroed `Vec` being lazy pages. The arenas do not exist yet:
/// `create_ntt_window` allocates them inside the attempt this gate admits, so
/// their bytes are genuinely absent from the reading and genuinely have to be
/// found.
///
/// So the credit is `min(own resident anon, accumulator)`, and both bounds
/// are load-bearing:
///
/// - capping at the ACCUMULATOR keeps a co-tenant honest. A create inside a
///   daemon's container shares the process with an index, a queue and every
///   other allocation, and crediting its whole `RssAnon` would cancel the
///   arena half too - which would readmit the 3.4x collapse this term was
///   added to prevent.
/// - capping at OWN ANON keeps the credit self-correcting. Make that
///   allocation lazy - it costs 3.3 ms per row, so somebody will - and the
///   accumulator stops being resident at the gate, `RssAnon` falls, and the
///   term comes back without a line changing here.
///
/// `None` (every non-Linux platform, and a Linux that will not report it)
/// takes no credit at all, so the host decision this term never reached is
/// unreachable still.
fn headroom_net(accumulator: u64, arenas: u64, own_anon: Option<u64>) -> u64 {
    let gross = accumulator.saturating_add(arenas);
    gross.saturating_sub(own_anon.unwrap_or(0).min(accumulator))
}

/// Pure half of [`create_map_headroom`]. Split out because the arena half is
/// a function of THIS box's worker pool, so a test that asked
/// `create_map_headroom` for a measured shape's figure would assert the dev
/// machine's core count and read as a measurement of the round's box.
fn headroom_from(bs: usize, count: usize, arenas: usize) -> u64 {
    (count as u64)
        .saturating_mul(bs as u64)
        .saturating_add(arenas as u64)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MapMode {
    Off,
    Transform,
    All,
}

fn map_mode() -> MapMode {
    static MODE: std::sync::OnceLock<MapMode> = std::sync::OnceLock::new();
    *MODE.get_or_init(
        || match std::env::var("NZBFAST_PAR2GEN_MAP").ok().as_deref() {
            Some("0") => MapMode::Off,
            Some("all") => MapMode::All,
            _ => MapMode::Transform,
        },
    )
}

#[cfg(test)]
mod map_fit_tests {
    use super::{create_map_headroom, headroom_from, headroom_net, mapped_payload_fits};

    const GIB: u64 = 1 << 30;

    /// The HOST arm, which the headroom term deliberately does not reach:
    /// every assertion here is the pre-16-Sep behaviour and must stay so,
    /// headroom or no headroom.
    #[test]
    fn a_payload_maps_only_when_it_fits_available_memory() {
        // The 32 GB laptop: 12 GiB mapped fast, 45 GiB collapsed, ~26 GiB available.
        assert!(mapped_payload_fits(12 * GIB, 0, Some(26 * GIB), None));
        assert!(!mapped_payload_fits(45 * GIB, 0, Some(26 * GIB), None));
        // The RAM-pinned desktop sweep: 25.8 GB held by 26.6 GB available, not by 20.4 GB.
        let member = 24 * GIB;
        assert!(mapped_payload_fits(member, 0, Some(26_600_000_000), None));
        assert!(!mapped_payload_fits(member, 0, Some(20_400_000_000), None));
        // The boundary is inclusive.
        assert!(mapped_payload_fits(member, 0, Some(member), None));
        assert!(!mapped_payload_fits(member + 1, 0, Some(member), None));
    }

    #[test]
    fn no_available_memory_figure_keeps_the_mapping() {
        assert!(mapped_payload_fits(u64::MAX, u64::MAX, None, None));
    }

    /// THE REGRESSION THIS TERM EXISTS NOT TO CAUSE. The 15 Sep Ryzen leg
    /// mapped a 24 GiB member correctly in 27.2 s against the copied windows'
    /// 34.5 with 26.6 GB available - ~0.8 GB clear of the payload, against a
    /// working set of ~1.5 GiB on that shape (1,638 accumulator rows of
    /// 768 KiB, plus ~299 MiB of arenas on sixteen threads at a 512-word
    /// stripe). A host-side headroom term would refuse it; this composition
    /// must not, at ANY headroom.
    #[test]
    fn the_host_reading_never_takes_the_headroom_term() {
        let member = 24 * GIB;
        let ryzen = headroom_from(768 << 10, 1_638, 299 << 20);
        let spare = 26_600_000_000 - member;
        assert!(
            ryzen > spare,
            "{ryzen} B should exceed the leg's {spare} B of spare"
        );
        assert!(mapped_payload_fits(
            member,
            ryzen,
            Some(26_600_000_000),
            None
        ));
        assert!(mapped_payload_fits(
            member,
            u64::MAX,
            Some(26_600_000_000),
            None
        ));
        // And a host that genuinely cannot hold the payload still refuses,
        // which is the half of the old behaviour the term must not soften.
        assert!(!mapped_payload_fits(member, 0, Some(14_300_000_000), None));
    }

    /// The residual band the 16 Sep cgroup round measured and did not close:
    /// one 2 GiB member at 5%, 32,768 slices of 64 KiB, 1,638 rows, 8 threads
    /// - a 107 MiB accumulator and ~149 MiB of arenas. The old composition
    /// admitted from `payload + ~50 MiB` of LIMIT; the mapped route only
    /// started winning between the 2200 MiB rung (22.1 s mapped against 17.2
    /// copied) and the 2400 MiB one (4.3 against 7.2).
    #[test]
    fn the_cgroup_reading_admits_only_past_the_creates_own_working_set() {
        let payload = 2 * GIB;
        // `cgroup_available_ram` is `limit - (usage - cache)`, and a create
        // that has allocated its accumulators lazily has touched ~50 MiB.
        let anon = 50 << 20;
        let avail = |limit_mib: u64| Some((limit_mib << 20) - anon);
        let head = headroom_from(64 << 10, 1_638, 149 << 20);
        // Without the term, 2200 MiB admitted - the losing rung.
        assert!(mapped_payload_fits(payload, 0, None, avail(2200)));
        // With it, the losing rung refuses and the winning one still maps.
        assert!(!mapped_payload_fits(payload, head, None, avail(2200)));
        assert!(mapped_payload_fits(payload, head, None, avail(2400)));
        // And the far cells the round already banked do not move: 1 and 2 GiB
        // refuse (147 s and 39 s measured), 3 GiB maps (4.3 s).
        assert!(!mapped_payload_fits(payload, head, None, avail(1024)));
        assert!(!mapped_payload_fits(payload, head, None, avail(2048)));
        assert!(mapped_payload_fits(payload, head, None, avail(3072)));
    }

    /// THE ARENA HALF IS LOAD-BEARING, and this is the shape of the round
    /// that proved it rather than a restatement of the arithmetic. The
    /// accumulator alone was the standing alternative until 16 Sep 2026: on
    /// the measured cgroup shape it lands the boundary nearer the crossover
    /// than the full term does, which is a better residual on one ladder and
    /// not a reason to drop a term. `NZBFAST_NTT_THREADS` is the only knob
    /// that separates the two - the arenas are per-worker scratch times the
    /// pool, the accumulator never sees the pool - and a 16-worker pin on
    /// that shape adds 153.3 MiB of arena and NO accumulator. The mapped
    /// route's knee moved with it (2,280 MiB of limit on eight workers,
    /// 2,400 on sixteen), where accumulator-alone predicts no move at all.
    ///
    /// So the property to hold is that the pool is visible in the term at
    /// all, and that it is visible by about the arena delta - which is what
    /// a later tidy-up dropping the arenas would break silently, since every
    /// other assertion in this module passes without them.
    #[test]
    fn the_arena_half_moves_with_the_worker_pool_and_the_accumulator_does_not() {
        // The measured shape: 1,638 rows of 64 KiB, one worker's arena
        // 20,093,952 B, the binary's own printed term 268,099,584 B at the
        // eight workers this box had.
        let (bs, rows, per_worker) = (64 << 10, 1_638, 20_093_952);
        let accumulator = (rows as u64) * (bs as u64);
        let eight = headroom_from(bs, rows, per_worker * 8);
        let sixteen = headroom_from(bs, rows, per_worker * 16);
        assert_eq!(eight, 268_099_584, "the figure the round's binary printed");
        // Doubling the pool adds arena and nothing else, and what it adds is
        // the 153.3 MiB the second shape's ladder moved by.
        assert_eq!(sixteen - eight, per_worker as u64 * 8);
        assert_eq!(sixteen - eight, 160_751_616);
        // And the accumulator is the SMALLER half here, so a term that kept
        // only it would be under the pinned shape's by more than a factor of
        // three - the gap the ladders measured.
        assert_eq!(accumulator, 107_347_968);
        assert!(sixteen > accumulator * 3, "{sixteen} vs {accumulator}");
    }

    /// THE DOUBLE COUNT, which is what the 18 Sep round measured and the
    /// 16 Sep round had only recorded as a likely mechanism.
    ///
    /// The measured shape, one 2 GiB member at 5% on eight workers: a
    /// 107,347,968 B accumulator, 160,751,616 B of arenas, and a cgroup
    /// unreclaimable charge of ~113 MiB at the instant the gate is asked -
    /// which is the accumulator, because `vec![vec![0u16; words]; count]`
    /// clones and every clone writes every page. The gross term adds that
    /// accumulator to a reading that has already deducted it.
    #[test]
    fn the_headroom_term_credits_what_the_reading_has_already_deducted() {
        let (accumulator, arenas) = (107_347_968u64, 160_751_616u64);
        let gross = accumulator + arenas;
        // No figure to credit against - every non-Linux platform - is the old
        // term exactly. This is the property that keeps the host decision,
        // every Mac and every Windows box unchanged.
        assert_eq!(headroom_net(accumulator, arenas, None), gross);
        // The measured charge credits the accumulator and NOT the arenas,
        // which do not exist yet at the gate.
        let own = 118_259_712; // 112.8 MiB, read off the 2,150 MiB cell.
        assert_eq!(headroom_net(accumulator, arenas, Some(own)), arenas);
        // CAPPED AT THE ACCUMULATOR: a co-tenant's anon must not cancel the
        // arena half. A daemon holding an index in the same container can read
        // an arbitrarily large RssAnon and still owes the arenas in full.
        assert_eq!(headroom_net(accumulator, arenas, Some(8 << 30)), arenas);
        assert_eq!(headroom_net(accumulator, arenas, Some(u64::MAX)), arenas);
        // CAPPED AT OWN ANON, so the credit is self-correcting: make that
        // allocation lazy and the term comes back on its own.
        assert_eq!(headroom_net(accumulator, arenas, Some(0)), gross);
        assert_eq!(
            headroom_net(accumulator, arenas, Some(accumulator / 2)),
            gross - accumulator / 2
        );
        // And the credit can never take the term below the arena half, at any
        // shape, which is the one invariant a later tidy-up must not lose.
        for own in [0, 1 << 20, 50 << 20, accumulator, 1 << 40, u64::MAX] {
            assert!(
                headroom_net(accumulator, arenas, Some(own)) >= arenas,
                "own {own}"
            );
        }
    }

    /// What the credit BUYS, in the quantity the round measures: where the
    /// admission boundary sits for the measured shape.
    ///
    /// 16 Sep bracketed the mapped route's crossover at (2,270, 2,280) MiB of
    /// cgroup limit and measured the gross term putting the boundary at
    /// ~2,417 - about 140 MiB past it, paid as 20-23% of wall at 2,300 and
    /// 2,350 where the mapping was right. The credit moves the boundary down
    /// by the accumulator.
    #[test]
    fn the_credit_moves_the_boundary_onto_the_measured_crossover() {
        const MIB: u64 = 1 << 20;
        let payload = 2 * 1024 * MIB;
        let (accumulator, arenas) = (107_347_968u64, 160_751_616u64);
        let own = 118_259_712;
        // The reading at a given limit, as `cgroup_available_from` composes
        // it: the limit less this create's own unreclaimable charge.
        let avail = |limit_mib: u64| Some(limit_mib * MIB - own);
        let gross = headroom_net(accumulator, arenas, None);
        let net = headroom_net(accumulator, arenas, Some(own));
        // GROSS: 2,300 and 2,350 refuse, which is the 20-23% the round paid.
        assert!(!mapped_payload_fits(payload, gross, None, avail(2300)));
        assert!(!mapped_payload_fits(payload, gross, None, avail(2350)));
        // NET: the boundary lands at 2,314 MiB - `payload + arenas + own` -
        // so 2,350 recovers and 2,300 does NOT. The credit is worth the
        // accumulator, 102.4 MiB of a 140 MiB overshoot, and the residual it
        // leaves is the ARENA half over-counting, which is the term the
        // worker-pin contrast already attributes and this change does not
        // touch. Reported rather than tuned: the crossover is an
        // interpolation between two rungs on one box.
        assert!(mapped_payload_fits(payload, net, None, avail(2350)));
        assert!(mapped_payload_fits(payload, net, None, avail(2320)));
        assert!(!mapped_payload_fits(payload, net, None, avail(2310)));
        // The boundary moved by exactly the accumulator and no more.
        let boundary = |h: u64| payload + h + own;
        assert_eq!(boundary(gross) - boundary(net), accumulator);
        assert!(boundary(net) / MIB == 2314, "{} MiB", boundary(net) / MIB);
        // And the losing rungs below the crossover still refuse - 2,180 and
        // 2,220 measured 18.5 s and 19.4 s mapped against the copied
        // windows' 5.4.
        assert!(!mapped_payload_fits(payload, net, None, avail(2180)));
        assert!(!mapped_payload_fits(payload, net, None, avail(2220)));
        // And the far cells the first round banked do not move: 1 and 2 GiB
        // refuse (147 s and 39 s mapped), 3 GiB admits (4.3 s).
        assert!(!mapped_payload_fits(payload, net, None, avail(1024)));
        assert!(!mapped_payload_fits(payload, net, None, avail(2048)));
        assert!(mapped_payload_fits(payload, net, None, avail(3072)));
    }

    /// The term is made of the accumulator and the arenas, and BOTH move with
    /// the shape - a constant fitted to either measured shape is wrong at the
    /// other by an order.
    #[test]
    fn the_headroom_term_is_derived_from_the_shape() {
        // The accumulator alone is 107 MiB on one measured shape and 1.2 GiB
        // on the other, at the same row count.
        let small = headroom_from(64 << 10, 1_638, 149 << 20);
        let large = headroom_from(768 << 10, 1_638, 299 << 20);
        assert!(large > small * 4, "{large} vs {small}");
        // The arenas are the other half: at one row the accumulator is
        // negligible and the term is still a real figure.
        assert!(headroom_from(64 << 10, 1, 149 << 20) > 100 << 20);
        // On THIS box only shape properties are assertable, because the arena
        // half prices the local worker pool. An index-only set asks for no
        // rows, so the accumulator cannot be what refuses a mapping.
        assert_eq!(
            create_map_headroom(64 << 10, 0, 0),
            create_map_headroom(64 << 10, 0, 0)
        );
        // ...and the arena half is asserted through `headroom_net` with the
        // credit PINNED, not through `create_map_headroom`, which passes it
        // `mem::self_anon_rss()` - this process's own anonymous RSS, live, at
        // call time. `net >= accumulator` on that answer reduces to
        // `arenas >= min(own_anon, accumulator)`, which is a property of how
        // big THIS process happens to be and not a property of the shape, so
        // it holds in a small process and fails in a large one. It did:
        // `one-process-loaded` went red in 11 of 11 runs on a6b911c3
        // (20 Sep 2026) with 1,656 tests' worth of RSS already grown, while
        // `one-process-light` and `one-process-heavy` passed on that same sha.
        // Pinning the credit to `None` keeps the real `worker_arenas` in the
        // assertion - which is the half this test is about - and removes the
        // only term the box could move. NZBFAST_PAR2GEN_MAP_OWN_CHARGE=0 is
        // NOT the fix: `own_charge_credit_enabled()` latches in a `OnceLock`,
        // so in a one-process run whichever test calls first decides for the
        // whole binary.
        //
        // MEASURED on the dev Mac (18 cores, so `worker_arenas` is 621 MiB
        // for both shapes here), which names the failing line exactly:
        //   bs=64 KiB   accumulator 102 MiB, arenas 621 MiB -> even a FULL
        //               credit leaves 621 MiB, so that line held whatever
        //               the RSS was and never was the red;
        //   bs=768 KiB  accumulator 1228 MiB, arenas 621 MiB -> a full
        //               credit leaves 621 MiB, under the accumulator, so
        //               this line fails once own-anon RSS passes
        //               1228 - 621 = 607 MiB.
        // A 4 vCPU CI runner has SMALLER arenas, so its threshold is lower
        // than 607 MiB again - which is why the loaded job failed 11 of 11
        // rather than intermittently.
        let arenas_only = |bs: usize| {
            let arenas = super::ntt_range::worker_arenas(bs, 0, 1_638) as u64;
            headroom_net(1_638u64 * bs as u64, arenas, None)
        };
        assert!(arenas_only(64 << 10) >= 1_638 * (64 << 10));
        assert!(arenas_only(768 << 10) >= 1_638 * (768 << 10));
    }
}
