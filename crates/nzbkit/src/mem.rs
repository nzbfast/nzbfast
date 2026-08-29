//! M15: one global memory budget for every cache tier in the pipeline.
//!
//! The engine treats RAM as a cache, never a requirement: every consumer
//! (extractor holds, verifier partial blocks, the body-buffer pool) has a
//! graceful spill path - materialize to disk, defer to settle read-back,
//! allocate-and-free. The budget just decides *when* each tier spills, so
//! a 190 GB job on an 8 GB NAS degrades to more disk I/O instead of
//! swapping the machine to death.
//!
//! Sizing: by default a quarter of physical RAM, clamped to
//! [256 MB, 16 GB] - small boxes never swap, big boxes never waste. Inside
//! a container the cgroup memory limit (not host RAM) is the OOM-kill
//! line, so the budget is further capped at half of it. The `--mem-limit`
//! flag overrides.

/// Physical RAM in bytes (unix: sysconf pages × page size; Windows:
/// GlobalMemoryStatusEx).
///
/// The Windows arm is not cosmetic. This returning None is what
/// [`MemBudget::auto_total`] falls back to, and its fallback is a flat
/// 1 GB - so for as long as this was unix-only, EVERY Windows install ran
/// the whole pipeline on a 1 GB budget no matter how much RAM the machine
/// had, where a 32 GB box should get 8. The budget only decides when each
/// tier spills to disk, so nothing broke; Windows just did far more disk
/// I/O than it needed to, silently, and `concurrency_caps_for` could not
/// see a small box either. `ullTotalPhys` is the right analogue of
/// `_SC_PHYS_PAGES`: both report USABLE physical memory rather than what is
/// physically installed.
pub fn physical_ram() -> Option<u64> {
    #[cfg(unix)]
    // SAFETY: sysconf is a plain FFI call taking only an integer constant;
    // it reads no pointers and has no preconditions.
    unsafe {
        let pages = libc::sysconf(libc::_SC_PHYS_PAGES);
        let page = libc::sysconf(libc::_SC_PAGE_SIZE);
        if pages > 0 && page > 0 {
            return Some(pages as u64 * page as u64);
        }
    }
    #[cfg(windows)]
    // SAFETY: MemoryStatusEx is #[repr(C)] matching the documented
    // MEMORYSTATUSEX layout (comment below), every field is a plain integer
    // so zeroed() is a valid value, `length` is set to the struct size
    // before the call as the API requires, and the pointer is a valid &mut.
    unsafe {
        // MEMORYSTATUSEX (sysinfoapi.h): two DWORD then seven DWORDLONG.
        // `dwLength` must be the struct's own size before the call.
        #[repr(C)]
        struct MemoryStatusEx {
            length: u32,
            memory_load: u32,
            total_phys: u64,
            avail_phys: u64,
            total_page_file: u64,
            avail_page_file: u64,
            total_virtual: u64,
            avail_virtual: u64,
            avail_extended_virtual: u64,
        }
        #[link(name = "kernel32")]
        // SAFETY: signature matches the documented kernel32 export
        // GlobalMemoryStatusEx (sysinfoapi.h), per the layout comment above.
        unsafe extern "system" {
            fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
        }
        let mut st: MemoryStatusEx = std::mem::zeroed();
        st.length = std::mem::size_of::<MemoryStatusEx>() as u32;
        if GlobalMemoryStatusEx(&mut st) != 0 && st.total_phys > 0 {
            return Some(st.total_phys);
        }
    }
    None
}

/// This process's memory counters from kernel32, in bytes: (peak working
/// set, current working set).
///
/// The Windows stand-in for `getrusage`'s `ru_maxrss` and `/proc/self/statm`.
/// `K32GetProcessMemoryInfo` is the kernel32 export of psapi's
/// `GetProcessMemoryInfo`, used so this needs no extra import library -
/// same reasoning as [`opt_out_of_power_throttling`] linking kernel32
/// directly.
#[cfg(windows)]
fn process_memory_counters() -> Option<(u64, u64)> {
    // PROCESS_MEMORY_COUNTERS (psapi.h): two DWORD then eight SIZE_T.
    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    #[link(name = "kernel32")]
    // SAFETY: signatures match the documented kernel32 exports
    // (GetCurrentProcess; K32GetProcessMemoryInfo, the kernel32 export of
    // psapi's GetProcessMemoryInfo, per the doc comment above).
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(
            process: isize,
            counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
    }
    // SAFETY: ProcessMemoryCounters is #[repr(C)] matching the documented
    // PROCESS_MEMORY_COUNTERS layout (comment above), every field is a plain
    // integer so zeroed() is a valid value, cb is set to the struct size
    // before the call, and both arguments passed are valid.
    unsafe {
        let mut c: ProcessMemoryCounters = std::mem::zeroed();
        c.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
        if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0 {
            return Some((c.peak_working_set_size as u64, c.working_set_size as u64));
        }
    }
    None
}

/// Cgroup memory limit on our own cgroup (Linux): tightest `memory.max`
/// (v2) or `memory.limit_in_bytes` (v1 memory controller) walking from
/// this process's cgroup up to the mount root, so both private-cgroupns
/// containers (path `/`) and nested host paths (systemd slices, docker
/// with host cgroupns) resolve. "max" / v1's page-rounded i64::MAX
/// sentinel read as no limit.
// `pub`, matching the `cfg(not(linux))` twin below: examples/memprobe.rs
// consumes it from OUTSIDE the crate, so a `pub(crate)` here is E0603 on
// Linux and invisible everywhere else (see the §103.6 note below).
#[cfg(target_os = "linux")]
pub fn cgroup_mem_limit() -> Option<u64> {
    use std::path::Path;
    fn read_limit(p: &Path) -> Option<u64> {
        let v: u64 = std::fs::read_to_string(p).ok()?.trim().parse().ok()?;
        (v < 1 << 48).then_some(v)
    }
    fn tightest(base: &Path, rel: &str, file: &str) -> Option<u64> {
        let mut dir = base.join(rel.trim_start_matches('/'));
        let mut best: Option<u64> = None;
        loop {
            if let Some(v) = read_limit(&dir.join(file)) {
                best = Some(best.map_or(v, |b| b.min(v)));
            }
            if dir == *base || !dir.pop() {
                return best;
            }
        }
    }
    let cg = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let mut best: Option<u64> = None;
    for line in cg.lines() {
        let mut it = line.splitn(3, ':');
        let (Some(_), Some(ctrls), Some(rel)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let found = if ctrls.is_empty() {
            tightest(Path::new("/sys/fs/cgroup"), rel, "memory.max")
        } else if ctrls.split(',').any(|c| c == "memory") {
            tightest(
                Path::new("/sys/fs/cgroup/memory"),
                rel,
                "memory.limit_in_bytes",
            )
        } else {
            None
        };
        if let Some(v) = found {
            best = Some(best.map_or(v, |b| b.min(v)));
        }
    }
    best
}

#[cfg(not(target_os = "linux"))]
pub fn cgroup_mem_limit() -> Option<u64> {
    None
}

/// `123`, `700M`, `2400M`, `2G` - DECIMAL suffixes, the same units
/// `--mem-limit` takes (`serve::parse_size`: M = 1e6, not 1 MiB). Local
/// rather than shared with that parser because nzbkit does not depend on
/// the nzbfast crate, and the only caller is a bench override.
fn parse_decimal_size(v: &str) -> Option<usize> {
    let (digits, mult) = match v.as_bytes().last()? {
        b'k' | b'K' => (&v[..v.len() - 1], 1_000u64),
        b'm' | b'M' => (&v[..v.len() - 1], 1_000_000),
        b'g' | b'G' => (&v[..v.len() - 1], 1_000_000_000),
        _ => (v, 1),
    };
    let n: u64 = digits.trim().parse().ok()?;
    usize::try_from(n.checked_mul(mult)?).ok()
}

/// How many CPU-bound workers this machine should run at once.
///
/// The one place `available_parallelism` is read for a WORKER POOL, so
/// that the answer can be capped from outside the process. Sites that
/// want the machine's real core count for something else - a benchmark
/// measuring the box, a diagnostic reporting it - go on asking the
/// standard library directly and say so.
///
/// `NZBFAST_CPU_WORKERS` overrides it, and the caller that exists is a
/// PHONE (TODO 281 AN4). On a big.LITTLE SoC `available_parallelism`
/// counts the little cores as if they were big, and every one of these
/// pools is a work-stealing queue sharing one thermal envelope: past the
/// big cluster the extra threads are paid for twice, once in power and
/// again in the frequency the throttle takes off every other thread. The
/// Android launcher reads the topology out of `cpuinfo_max_freq` and
/// passes the count - see `DeviceProfile.cpuWorkers` in
/// packaging/android/compose-app.
///
/// This is a CEILING on the pool width and nothing else. Every call site
/// still applies its own clamps (`.min(work.len())`, the physical-core
/// rule on hybrid x86, `NZBFAST_NTT_THREADS`), so a smaller answer here
/// can only ever narrow a pool, never widen one.
///
/// Read once. The value cannot change while the process runs, and these
/// sites sit inside repair and decode loops where a `getenv` per call
/// would be a syscall in a hot path.
pub fn cpu_workers() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        let machine = std::thread::available_parallelism().map_or(4, |n| n.get());
        match std::env::var("NZBFAST_CPU_WORKERS") {
            Ok(v) => cpu_workers_override(&v).unwrap_or(machine),
            Err(_) => machine,
        }
    })
}

/// What `NZBFAST_CPU_WORKERS` is allowed to mean, split out so it can be
/// tested: the reading of the variable itself cannot be, because
/// [`cpu_workers`] latches its answer in a `OnceLock` and the whole
/// process shares one.
///
/// `None` for anything that is not a positive number, so a typo falls
/// back to the machine rather than to zero workers, which is a hang. The
/// ceiling is not a guess about hardware: this value arrives from a
/// launcher, and a pool a thousand threads wide is a way to take the
/// process down that no caller asked for. 1024 is far past any real
/// machine and far short of thread exhaustion.
pub(crate) fn cpu_workers_override(raw: &str) -> Option<usize> {
    raw.trim()
        .parse::<usize>()
        .ok()
        .filter(|n| *n > 0)
        .map(|n| n.min(1024))
}

#[derive(Clone, Copy, Debug)]
pub struct MemBudget {
    pub total: u64,
}

impl MemBudget {
    pub const MIN: u64 = 64 << 20; // even --mem-limit can't go below 64 MB
    const AUTO_FLOOR: u64 = 256 << 20;
    // 16 GB (was 4): the 4 GB ceiling forced the verify-partials spill on
    // big-RAM boxes - measured on the 190 GB Kill Bill set: 540 s at
    // 4.29 GB vs 499 s at 16 GB vs 435 s at 64 GB. RAM/4
    // keeps small machines safe; --mem-limit / the mem_limit setting
    // still overrides in either direction.
    const AUTO_CEIL: u64 = 16 << 30;
    /// Hard ceiling on 32-bit hosts (armv7 Raspberry Pi OS). Two
    /// independent reasons, either one sufficient:
    ///   - The consumers below are `usize`-sized. A total whose 45%/30%
    ///     slice exceeds 4 GiB used to `as usize` straight off the end -
    ///     `--mem-limit 10G` handed the extractor a 512 MB cap while the
    ///     log and the settings page both said 10 GB. Wrapping only ever
    ///     under-promised, so nothing corrupted; it just made the knob
    ///     lie, silently, on the one platform where memory is scarce.
    ///   - A 32-bit process has ~3 GiB of user address space TOTAL, and
    ///     these tiers are ~90% of the budget between them before any
    ///     untracked allocation. A budget the address space cannot hold
    ///     is not a budget, it is a deferred OOM.
    /// 1 GiB leaves every tier spendable with room for fragmentation.
    /// The auto default never reaches it (RAM/4 on a 1 GB Pi is the
    /// 256 MB floor), so this only ever binds an explicit --mem-limit.
    #[cfg(target_pointer_width = "32")]
    const ADDRESS_SPACE_CEIL: u64 = 1 << 30;

    /// Quarter of physical RAM, clamped - the no-configuration default.
    /// In a container, additionally capped at half the cgroup memory
    /// limit: the RAM/4 rule shares a host with other apps and the page
    /// cache, but a cgroup limit is this process's hard OOM-kill line, so
    /// half is spent on cache and half stays free for everything the
    /// budget doesn't track (decode scratch, repair matrices, stacks).
    pub fn auto() -> MemBudget {
        MemBudget {
            total: Self::auto_total(physical_ram(), cgroup_mem_limit()),
        }
    }

    fn auto_total(ram: Option<u64>, cgroup_limit: Option<u64>) -> u64 {
        let host = ram
            .map(|r| (r / 4).clamp(Self::AUTO_FLOOR, Self::AUTO_CEIL))
            .unwrap_or(1 << 30);
        let total = match cgroup_limit {
            Some(lim) => host.min((lim / 2).max(Self::MIN)),
            None => host,
        };
        Self::fit_address_space(total)
    }

    pub fn with_total(total: u64) -> MemBudget {
        MemBudget {
            total: Self::fit_address_space(total.max(Self::MIN)),
        }
    }

    /// No-op on 64-bit; clamps to [`Self::ADDRESS_SPACE_CEIL`] on 32-bit.
    fn fit_address_space(total: u64) -> u64 {
        #[cfg(target_pointer_width = "32")]
        {
            total.min(Self::ADDRESS_SPACE_CEIL)
        }
        #[cfg(not(target_pointer_width = "32"))]
        {
            total
        }
    }

    /// Extractor held-span ceiling (spill: materialize volumes to disk).
    pub fn holds_cap(&self) -> usize {
        // `as usize` here truncated on 32-bit rather than saturating.
        // `fit_address_space` already keeps the total in range, so this
        // is the belt: a cap that saturates is merely generous, a cap
        // that wraps is arbitrary.
        let natural = usize::try_from(self.total / 100 * 45).unwrap_or(usize::MAX);
        // Bench override only (TODO 219 follow-up, 23 Aug 2026), and
        // REDUCE-only so every budget invariant above still holds. The
        // A/B that prices the in-stream chase against the disk route
        // needs the holds cap on one side of the chain and the other,
        // with NOTHING else moved: `--mem-limit` also moves
        // `bufpool_bufs`, `channel_depth`, `inflight_cap`,
        // `partials_cap`, `repair_cap` and the rars execution policy,
        // so a ladder rung is five confounds wide. This is the same
        // reduction the holds LEDGER applies to a successor pipeline
        // (`set_holds_cap`), reachable from a single-job `get` leg.
        // Parsed like `--mem-limit`: decimal K/M/G suffixes.
        static OVERRIDE: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
        match OVERRIDE.get_or_init(|| {
            std::env::var("NZBFAST_HOLDS_CAP")
                .ok()
                .and_then(|v| parse_decimal_size(v.trim()))
        }) {
            Some(cap) => (*cap).min(natural),
            None => natural,
        }
    }

    /// Verifier partial-block ceiling, GLOBAL across all slots (spill:
    /// leave blocks Pending → settle read-back hashes them from disk).
    pub fn partials_cap(&self) -> usize {
        usize::try_from(self.total / 100 * 30).unwrap_or(usize::MAX)
    }

    /// Body-buffer pool retention count (~800 KB each; spill: plain
    /// allocate/free, the allocator absorbs the churn).
    pub fn bufpool_bufs(&self) -> usize {
        // Bench override only (memfloor levers, 22 Aug 2026): 0 disables
        // retention entirely (plain allocate/free per article).
        static OVERRIDE: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
        if let Some(d) = OVERRIDE.get_or_init(|| {
            std::env::var("NZBFAST_BUFPOOL_BUFS")
                .ok()
                .and_then(|v| v.trim().parse::<usize>().ok())
                .map(|d| d.min(8192))
        }) {
            return *d;
        }
        ((self.total / 100 * 15) / (800 * 1024)).clamp(32, 512) as usize
    }

    /// fetch→decode channel depth (raw articles in flight between the
    /// pool and the decode threads, ~800 KB each). Historically a fixed
    /// 256 - up to ~200 MB of budget-EXEMPT bytes, which on a 256 MB-
    /// budget box could exceed the entire budget by itself (B2). A
    /// budget/16 slice keeps the pipeline deep on big metal (256 at
    /// 3.3 GB+) without drowning small boxes (20 at the 256 MB floor);
    /// backpressure semantics are unchanged, the channel just fills
    /// sooner and the TCP windows close - the systemic response the
    /// slow-disk throttle test already pins.
    pub fn channel_depth(&self) -> usize {
        // Line-rate A/B (6 Aug 2026): a page-cache flush burst reaches
        // the sockets through exactly this channel, so the decoupling
        // candidate is "make it deeper". Bench override only - the
        // budget-derived depth stays the shipped behaviour.
        static OVERRIDE: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
        if let Some(d) = OVERRIDE.get_or_init(|| {
            std::env::var("NZBFAST_CHANNEL_DEPTH")
                .ok()
                .and_then(|v| v.trim().parse::<usize>().ok())
                .map(|d| d.clamp(8, 8192))
        }) {
            return *d;
        }
        ((self.total / 16) / (800 * 1024)).clamp(8, 256) as usize
    }

    /// Wire-side in-flight body byte cap, GLOBAL across every server
    /// pool (B3). Pipelined BODY responses are budget-EXEMPT bytes:
    /// window × connections × ~800 KB pooled bodies - 48 connections at
    /// window 3 is 115 MB+ before the first article even reaches the
    /// fetch→decode channel. Workers stop topping up their pipeline past
    /// one request per connection while the pool's charged estimate
    /// exceeds this; the one-in-flight floor keeps every connection busy
    /// (no deadlock - throughput degrades to window 1 at worst). A
    /// budget/4 slice leaves deep pipelines untouched on big metal
    /// (256 MB+ at the 1 GB auto default) while a 256 MB-budget box is
    /// held to 64 MB of wire bodies.
    pub fn inflight_cap(&self) -> u64 {
        (self.total / 4).clamp(32 << 20, 2 << 30)
    }

    /// Working-buffer ceiling for RAR recovery repair (embedded recovery
    /// records and `.rev` reconstruction).
    ///
    /// These run after the download pipeline has drained, so the cache tiers
    /// above are releasing rather than filling and a quarter of the budget
    /// is comfortably available. The slice exists to keep the repair of a
    /// 20 GB volume bounded at all - before it, recovery read whole volumes
    /// and cloned them, entirely outside this budget.
    pub fn repair_cap(&self) -> u64 {
        (self.total / 4).clamp(8 << 20, 512 << 20)
    }

    /// RAR extraction's execution policy: how much working memory the rars
    /// decode pipelines may plan with (flat buffers vs the bounded ring,
    /// worker counts). A quarter of the budget, floored so ordinary archives
    /// keep their fast paths on small hosts and capped because flat buffers
    /// beyond a few GB stop paying. Extraction overlaps the download
    /// pipeline (chase extraction decodes while later volumes arrive), so
    /// this deliberately shares the budget rather than assuming the cache
    /// tiers have drained.
    pub fn rar_execution_policy(&self) -> rars::Rar50ExecutionPolicy {
        rars::Rar50ExecutionPolicy::from_working_memory((self.total / 4).clamp(96 << 20, 6 << 30))
    }
}

/// Read options for a production RAR extraction: the caller's password plus
/// the process budget's execution policy. Every nzbfast/nzbkit extraction
/// entry point goes through this so a memory-constrained host never selects
/// a flat plan it cannot afford and a big host may exceed rars' built-in
/// flat cap.
///
/// It also picks the split-member BLAKE2sp seeding. The in-stream chase
/// decodes a split member through a growing chain, so it has to decide
/// whether to hash before it has read the finish fragment that says whether
/// any digest was ever recorded - and the safe answer, hashing regardless,
/// costs a whole-payload BLAKE2sp that is then thrown away on every set
/// written with `rar`'s DEFAULT switches (`Pack-CRC32`, no hash line), which
/// is what a posted set normally is. Measured on an Apple M3 at +4.22 G
/// instructions per GB unpacked and +5.83 G paced, against ~42 G for the
/// decode itself; it is the whole of the gap between the chase and the
/// volumes-on-disk route, which holds the finish fragment and so never
/// hashes an unstamped set. `FirstFragment` takes the first fragment's
/// header as the set's answer, which is exact for every WinRAR 7.21 and
/// rar 7.23 set measured (both stamp EVERY fragment of a `-htb` set and
/// none without it) and inexact only for the rars writer's own split sets,
/// which stamp the finish fragment alone - those keep their CRC32 check and
/// lose the BLAKE2sp one. Posted archives do not come from the rars writer.
pub fn rar_read_options(password: Option<&[u8]>) -> rars::ArchiveReadOptions<'_> {
    rars::ArchiveReadOptions::with_optional_password(password)
        .with_rar50_execution_policy(process_budget().rar_execution_policy())
        .with_rar50_split_hash_seeding(rars::Rar50SplitHashSeeding::FirstFragment)
}

/// The budget this process resolved at startup, in bytes; 0 until set.
static PROCESS_BUDGET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Publishes the resolved budget process-wide.
///
/// Every entry point resolves a budget from `--mem-limit`, the `mem_limit`
/// setting, or [`MemBudget::auto`], then threads it into the pipeline. The
/// repair paths sit several layers below any of those call sites (extraction
/// failure -> recovery-record repair -> per-volume repair), and threading a
/// budget down that chain would touch every caller for one leaf consumer.
pub fn set_process_budget(budget: MemBudget) {
    PROCESS_BUDGET.store(budget.total, std::sync::atomic::Ordering::Relaxed);
}

/// The published budget, or [`MemBudget::auto`] when nothing set one (a
/// library user, or a test calling a repair helper directly).
pub fn process_budget() -> MemBudget {
    match PROCESS_BUDGET.load(std::sync::atomic::Ordering::Relaxed) {
        0 => MemBudget::auto(),
        total => MemBudget { total },
    }
}

/// The budget an entry point actually PUBLISHED, or `None` when none has.
///
/// [`process_budget`] substitutes [`MemBudget::auto`] for the unpublished
/// case, which is right for a leaf consumer that must pick SOME figure.
/// This is for the one consumer that must tell the two apart: a default
/// that reads `auto` is host-derived, so the same code would demote on a
/// 4 GB CI runner and not on a 128 GB dev box - see the extractor's
/// `default_holds_cap` (TODO 260) for why that distinction is load-bearing.
pub fn published_budget() -> Option<MemBudget> {
    match PROCESS_BUDGET.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        total => Some(MemBudget { total }),
    }
}

/// Outstanding LZMA decode-window bytes, process-wide. An LZMA (zip
/// method 14) decoder allocates its whole dictionary window in one
/// `try_reserve_exact` - up to `LZMA_DICT_MAX` (256 MiB) per legitimate
/// `-mx=9` entry - and that allocation lives inside the decoder, entirely
/// outside `MemBudget`. A one-pass NESTED chase decodes each level on its
/// own thread while feeding the level below, so N method-14 levels hold N
/// windows LIVE AT ONCE: measured 22 Aug 2026 as EXACTLY 5 x 256 MiB =
/// 1.25 GiB against a pinned 256 MiB budget, with zero refusals
/// (`research/NOTE-2026-08-22-lzma-dict-window-rss.md`, the tracking-
/// allocator rig `tests/lzma_dict_window_rss.rs`, TODO 209 items 2 & 3).
/// This gauge makes those windows visible and bounds their sum.
static LZMA_DICT_OUTSTANDING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// High-water mark of [`LZMA_DICT_OUTSTANDING`], for observability - the
/// peak simultaneous dictionary-window bytes this process has held. The
/// pre-fix rig peaked here at 5 x 256 MiB; the budget now holds it to one
/// window under a floor-sized budget (TODO 209).
static LZMA_DICT_PEAK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Live LZMA dictionary-window bytes charged against the process budget.
/// The window is otherwise invisible to `MemBudget`; this is the answer to
/// TODO 209 item 3 ("should the window be visible to `MemBudget`?").
pub fn lzma_dict_outstanding() -> u64 {
    LZMA_DICT_OUTSTANDING.load(std::sync::atomic::Ordering::Relaxed)
}

/// Peak simultaneous LZMA dictionary-window bytes since process start.
pub fn lzma_dict_peak() -> u64 {
    LZMA_DICT_PEAK.load(std::sync::atomic::Ordering::Relaxed)
}

/// A reserved slice of the LZMA dictionary budget; releases on drop.
#[derive(Debug)]
pub struct LzmaDictCharge(u64);

impl Drop for LzmaDictCharge {
    fn drop(&mut self) {
        LZMA_DICT_OUTSTANDING.fetch_sub(self.0, std::sync::atomic::Ordering::Relaxed);
        // Take the wakeup lock before notifying. A waiter re-tests
        // admission while holding it, so a release can never land in the
        // gap between that failed test and the wait that follows.
        {
            use crate::sync::MutexExt;
            drop(LZMA_DICT_FREED.0.lock_ok());
        }
        LZMA_DICT_FREED.1.notify_all();
    }
}

/// Wakeup for [`charge_lzma_dict_waiting`], signalled when a charge is
/// released. The mutex guards nothing - the gauge is atomic - it exists
/// only so a waiter cannot miss a notification.
static LZMA_DICT_FREED: (std::sync::Mutex<()>, std::sync::Condvar) =
    (std::sync::Mutex::new(()), std::sync::Condvar::new());

/// How long a materialized disk decode waits for the window before it
/// charges anyway. The wait exists so a valid archive is not filed as a
/// gap because some other decode held the budget at that instant; the
/// deadline exists so a stream of speculative chase windows can never
/// starve that disk pass outright. One extra window is strictly cheaper
/// than failing an extraction that would otherwise succeed.
const LZMA_DICT_WAIT_MAX: std::time::Duration = std::time::Duration::from_secs(600);

/// Reserve `need` bytes of window for a decode that has NO lower rung,
/// waiting for the budget rather than refusing.
///
/// This is the disk reader's admission mode. The chase can demote a
/// refusal to the sequential disk pass; the disk pass has nowhere to
/// demote to, and `rarfix`'s entry pool (up to four workers) plus the
/// queue hand-over (an older job's post-processing overlaps the newer
/// job's chase) both put a second window against the gauge while it
/// decodes. Refusing there turns a structurally valid method-14 zip into
/// a `ZipGap`, which is what this waits to avoid.
///
/// Never called from a decode that already holds a charge - each disk
/// level is materialized before the next is opened - so the wait cannot
/// be on itself; the deadline bounds it regardless.
pub fn charge_lzma_dict_waiting(need: u64) -> LzmaDictCharge {
    use crate::sync::MutexExt;
    if let Some(c) = charge_lzma_dict(need) {
        return c;
    }
    let deadline = std::time::Instant::now() + LZMA_DICT_WAIT_MAX;
    let mut g = LZMA_DICT_FREED.0.lock_ok();
    loop {
        if let Some(c) = charge_lzma_dict(need) {
            return c;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        g = LZMA_DICT_FREED
            .1
            .wait_timeout(g, deadline - now)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
    drop(g);
    tracing::warn!(
        target: "unpack",
        "lzma dictionary budget still held after {}s - decoding anyway rather \
         than failing a valid archive",
        LZMA_DICT_WAIT_MAX.as_secs()
    );
    force_lzma_dict(need)
}

/// Charge `need` past the admission rule, for the deadline arm above.
fn force_lzma_dict(need: u64) -> LzmaDictCharge {
    use std::sync::atomic::Ordering::Relaxed;
    let cur = LZMA_DICT_OUTSTANDING
        .fetch_add(need, Relaxed)
        .saturating_add(need);
    LZMA_DICT_PEAK.fetch_max(cur, Relaxed);
    LzmaDictCharge(need)
}

/// Reserve `need` bytes of LZMA dictionary window against the process
/// budget, or return `None` when it will not fit.
///
/// The FIRST outstanding window is always admitted: a single `-mx=9`
/// entry needs its full 256 MiB and cannot decode in less, so refusing it
/// would fail a legitimate archive. Only an ADDITIONAL, concurrent window
/// - the nested one-pass chase's stacking - is refused once the sum would
/// exceed the budget; that caller demotes the container to the sequential
/// disk pass, which produces identical output.
///
/// This is the TRY-ONCE mode, and it is for callers that HAVE that lower
/// rung. The gauge is process-global, not per-job, so the disk pass does
/// NOT observe a zero gauge: `rarfix` runs an archive's entries on a pool
/// of up to four workers, and the queue hand-over overlaps an older job's
/// post-processing with the newer job's chase. A caller with nowhere to
/// demote to takes [`charge_lzma_dict_waiting`] instead.
pub fn charge_lzma_dict(need: u64) -> Option<LzmaDictCharge> {
    use std::sync::atomic::Ordering::Relaxed;
    let cap = process_budget().total;
    let mut cur = LZMA_DICT_OUTSTANDING.load(Relaxed);
    loop {
        if !dict_charge_admits(cur, need, cap) {
            return None;
        }
        match LZMA_DICT_OUTSTANDING.compare_exchange_weak(
            cur,
            cur.saturating_add(need),
            Relaxed,
            Relaxed,
        ) {
            Ok(_) => {
                LZMA_DICT_PEAK.fetch_max(cur.saturating_add(need), Relaxed);
                return Some(LzmaDictCharge(need));
            }
            Err(observed) => cur = observed,
        }
    }
}

/// Admission predicate for [`charge_lzma_dict`], factored out so the rule
/// is testable without the process-global gauge. `cur == 0` always admits
/// - a single window must decode on any box, and it is what keeps
/// [`charge_lzma_dict_waiting`] from waiting forever - while an additional
/// window is admitted only while the running sum stays within `cap`.
fn dict_charge_admits(cur: u64, need: u64, cap: u64) -> bool {
    cur == 0 || cur.saturating_add(need) <= cap
}

/// B4: RAM-tiered caps on job concurrency (connections per server,
/// pipeline window, decode threads). MemBudget protects correctness on
/// small boxes; these protect throughput consistency - 8 connections on
/// a 512 MB NAS just fill the budget faster and spill-churn the HDD,
/// which measures slower than simply running fewer connections. Applied
/// as a clamp on the effective values at job start, never by rewriting
/// user config - the config stays portable, and the same settings are
/// honoured in full the moment they run on bigger hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConcurrencyCaps {
    pub(crate) connections: usize,
    pub(crate) window: usize,
    pub decoders: usize,
}

impl ConcurrencyCaps {
    /// Clamp the requested values to these caps.
    pub fn apply(
        &self,
        connections: usize,
        window: usize,
        decoders: usize,
    ) -> (usize, usize, usize) {
        (
            connections.min(self.connections),
            window.min(self.window),
            decoders.min(self.decoders),
        )
    }
}

/// Caps for this machine, or None above 1 GB - big-box behavior stays
/// byte-identical. Same RAM sources as MemBudget::auto: inside a
/// container the cgroup limit, not host RAM, is what we can actually
/// spend, so the tighter of the two picks the tier.
pub fn concurrency_caps() -> Option<ConcurrencyCaps> {
    concurrency_caps_for(physical_ram(), cgroup_mem_limit())
}

fn concurrency_caps_for(ram: Option<u64>, cgroup_limit: Option<u64>) -> Option<ConcurrencyCaps> {
    // Unknown RAM reads as "not small": clamping is an optimization for
    // boxes we can SEE are tiny, never a penalty for a failed probe.
    let eff = match (ram, cgroup_limit) {
        (Some(r), Some(l)) => r.min(l),
        (Some(r), None) => r,
        (None, Some(l)) => l,
        (None, None) => return None,
    };
    if eff <= 512 << 20 {
        Some(ConcurrencyCaps {
            connections: 4,
            window: 2,
            decoders: 2,
        })
    } else if eff <= 1 << 30 {
        Some(ConcurrencyCaps {
            connections: 6,
            window: 3,
            decoders: 2,
        })
    } else {
        None
    }
}

/// Peak resident set size of this process in bytes (getrusage; Windows:
/// peak working set). The number benchmarks quote.
///
/// `ru_maxrss` is the one getrusage field whose UNIT is per-platform:
/// Apple's kernels report bytes, and every other unix we build for -
/// Linux, Android, the BSDs including FreeBSD - reports kilobytes. The
/// scaling test below is therefore "is this an Apple platform", not "is
/// this Linux": written the other way round it silently under-reports by
/// 1024x on Android and FreeBSD, which reads as a suspiciously tiny
/// process rather than as an obvious failure.
pub fn peak_rss() -> Option<u64> {
    #[cfg(unix)]
    // SAFETY: libc::rusage is plain data (integer fields only) so zeroed()
    // is a valid value, and getrusage writes through a valid &mut pointer.
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut ru) == 0 {
            let raw = ru.ru_maxrss as u64;
            return Some(if cfg!(any(target_os = "macos", target_os = "ios")) {
                raw
            } else {
                raw * 1024
            });
        }
    }
    #[cfg(windows)]
    {
        process_memory_counters().map(|(peak, _)| peak)
    }
    #[cfg(not(windows))]
    None
}

// The one true `task_info` declaration. It used to be declared twice,
// locally in `current_rss` and `dashboard_rss`, each with its own
// info-struct pointer type - two conflicting extern signatures for one
// symbol, which the language rules call undefined behaviour even when
// both are pointer-sized. Declared once with the real Mach signature
// (`task_info_t` is `integer_t*`); callers cast their struct pointer.
#[cfg(any(target_os = "macos", target_os = "ios"))]
// SAFETY: declared once, with the real Mach signature (`task_info_t` is
// `integer_t*`) per the comment above, so there are no conflicting extern
// declarations for the symbol; callers cast their #[repr(C)] info-struct
// pointer at the call site.
unsafe extern "C" {
    static mach_task_self_: u32;
    #[link_name = "task_info"]
    fn mach_task_info(task: u32, flavor: u32, info: *mut i32, count: *mut u32) -> i32;
}

/// CURRENT resident set size in bytes - the live number the dashboard's
/// resource chart tracks (peak_rss only ever goes up). macOS: mach
/// task_info; Linux: /proc/self/statm; Windows: current working set;
/// elsewhere falls back to the peak.
pub fn current_rss() -> Option<u64> {
    #[cfg(windows)]
    {
        // Not `peak_rss()`'s fallback: the chart is a LIVE reading, and the
        // peak never comes back down.
        if let Some((_, cur)) = process_memory_counters() {
            return Some(cur);
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    // SAFETY: TaskBasicInfo is #[repr(C)] matching the documented
    // mach_task_basic_info layout (comment below), every field is a plain
    // integer so zeroed() is a valid value, `count` is initialized to the
    // struct size in integer_t units as task_info requires, and the
    // out-pointers are valid; mach_task_self_ is a plain u32 read.
    unsafe {
        // struct mach_task_basic_info (mach/task_info.h): three
        // mach_vm_size_t, two time_value_t, policy_t, integer_t.
        #[repr(C)]
        struct TaskBasicInfo {
            virtual_size: u64,
            resident_size: u64,
            resident_size_max: u64,
            user_time: [i32; 2],
            system_time: [i32; 2],
            policy: i32,
            suspend_count: i32,
        }
        const MACH_TASK_BASIC_INFO: u32 = 20;
        let mut info: TaskBasicInfo = std::mem::zeroed();
        let mut count = (std::mem::size_of::<TaskBasicInfo>() / 4) as u32;
        if mach_task_info(
            mach_task_self_,
            MACH_TASK_BASIC_INFO,
            (&raw mut info).cast(),
            &mut count,
        ) == 0
        {
            return Some(info.resident_size);
        }
    }
    #[cfg(target_os = "linux")]
    {
        // statm field 2 = resident pages.
        if let Some(pages) = std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| {
                s.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
            })
        {
            // SAFETY: sysconf is a plain FFI call taking only an integer
            // constant; it reads no pointers and has no preconditions.
            let page = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
            if page > 0 {
                return Some(pages * page as u64);
            }
        }
    }
    peak_rss()
}

/// The kernel's honest memory charge for this process - macOS
/// phys_footprint (what Activity Monitor's Memory column and the memory-
/// pressure system use). Unlike resident_size it EXCLUDES pages the
/// allocator has already offered back via madvise-reusable, so it falls
/// after an idle trim where naive RSS stays pinned. Elsewhere it equals
/// current_rss.
pub fn dashboard_rss() -> Option<u64> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    // SAFETY: TaskVmInfo is #[repr(C)] matching the documented task_vm_info
    // layout (comment below), every field is a plain integer so Default's
    // zero value is valid, `count` is initialized to the struct size in
    // integer_t units as task_info requires, and the out-pointers are
    // valid; mach_task_self_ is a plain u32 read.
    unsafe {
        // struct task_vm_info (mach/task_info.h), flavor 22.
        #[repr(C)]
        #[derive(Default, Clone, Copy)]
        struct TaskVmInfo {
            virtual_size: u64,
            region_count: i32,
            page_size: i32,
            resident_size: u64,
            resident_size_peak: u64,
            device: u64,
            device_peak: u64,
            internal: u64,
            internal_peak: u64,
            external: u64,
            external_peak: u64,
            reusable: u64,
            reusable_peak: u64,
            purgeable_volatile_pmap: u64,
            purgeable_volatile_resident: u64,
            purgeable_volatile_virtual: u64,
            compressed: u64,
            compressed_peak: u64,
            compressed_lifetime: u64,
            phys_footprint: u64,
            min_address: u64,
            max_address: u64,
        }
        const TASK_VM_INFO: u32 = 22;
        let mut info = TaskVmInfo::default();
        let mut count = (std::mem::size_of::<TaskVmInfo>() / 4) as u32;
        if mach_task_info(
            mach_task_self_,
            TASK_VM_INFO,
            (&raw mut info).cast(),
            &mut count,
        ) == 0
            && info.phys_footprint > 0
        {
            return Some(info.phys_footprint);
        }
    }
    current_rss()
}

/// Hand freed-but-retained allocator pages back to the OS. When a job
/// ends the pipeline frees its buffers, but malloc keeps the pages
/// resident for reuse - harmless, yet it reads as a leak on the
/// dashboard's RAM line and starves nothing proactively. macOS reports
/// bytes released; glibc's malloc_trim only reports whether anything was
/// released (surfaced as 0 here); other platforms are a no-op.
// Not #[expect]: the tail is genuinely unreachable only on macOS.
// Linux and Windows fall through to it and the expectation goes
// unfulfilled.
#[allow(unreachable_code)]
pub fn trim() -> u64 {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        // SAFETY: signature matches the documented declaration in
        // malloc/malloc.h (comment below).
        unsafe extern "C" {
            // malloc/malloc.h: zone == NULL means every zone, goal == 0
            // means "release as much as possible".
            fn malloc_zone_pressure_relief(
                zone: *mut libc::c_void,
                goal: libc::size_t,
            ) -> libc::size_t;
        }
        // SAFETY: NULL zone and goal 0 are documented valid arguments (see
        // the comment on the declaration above).
        return unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) as u64 };
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: malloc_trim is a plain FFI call taking only an integer; it
    // reads no pointers and has no preconditions.
    unsafe {
        libc::malloc_trim(0);
    }
    0
}

/// Total CPU time (user + system) this process has consumed, in seconds.
/// Deltas between samples over wall time give the process CPU%.
pub fn cpu_time_secs() -> Option<f64> {
    cpu_user_sys_secs().map(|(user, sys)| user + sys)
}

/// The same charge, split into (user, system) seconds.
///
/// The split is not decoration: a measurement rig timing a loopback
/// path pays most of its system time inside the mock server and the
/// kernel, which swings run to run, so `tests/delivery_cost.rs` takes
/// its median on USER time alone. That rig used to call `getrusage`
/// itself, which does not exist on Windows and (with `--all-targets`)
/// held `windows-clippy` red; both halves are already here on both
/// platforms, so it can ask for them instead.
pub fn cpu_user_sys_secs() -> Option<(f64, f64)> {
    #[cfg(unix)]
    // SAFETY: libc::rusage is plain data (integer fields only) so zeroed()
    // is a valid value, and getrusage writes through a valid &mut pointer.
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut ru) == 0 {
            return Some((
                ru.ru_utime.tv_sec as f64 + ru.ru_utime.tv_usec as f64 / 1e6,
                ru.ru_stime.tv_sec as f64 + ru.ru_stime.tv_usec as f64 / 1e6,
            ));
        }
    }
    #[cfg(windows)]
    // SAFETY: FileTime is #[repr(C)] matching the documented FILETIME
    // layout (comment below), and all four out-pointers passed to
    // GetProcessTimes are valid &muts to initialized values.
    unsafe {
        // FILETIME pairs, 100-nanosecond units. Creation and exit times are
        // wall clock and not what this wants; kernel + user is the charge.
        #[repr(C)]
        #[derive(Default)]
        struct FileTime {
            low: u32,
            high: u32,
        }
        impl FileTime {
            fn secs(&self) -> f64 {
                (((self.high as u64) << 32) | self.low as u64) as f64 / 1e7
            }
        }
        #[link(name = "kernel32")]
        // SAFETY: signatures match the documented kernel32 exports
        // (GetCurrentProcess, GetProcessTimes; FILETIME layout per the
        // comment above).
        unsafe extern "system" {
            fn GetCurrentProcess() -> isize;
            fn GetProcessTimes(
                process: isize,
                creation: *mut FileTime,
                exit: *mut FileTime,
                kernel: *mut FileTime,
                user: *mut FileTime,
            ) -> i32;
        }
        let (mut c, mut e, mut k, mut u) = (
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
            FileTime::default(),
        );
        if GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) != 0 {
            return Some((u.secs(), k.secs()));
        }
    }
    None
}

/// Opt this process out of Windows 11 power throttling (EcoQoS).
///
/// Windows demotes sustained "background" CPU work - anything without a
/// foreground window, which is exactly a daemon or an ssh-launched
/// process - onto efficiency cores at reduced QoS a few seconds in.
/// Measured on the i7-1280P: the GF(2^16) repair fold ran at 111 GB/s
/// for ~3 s and then 13 GB/s for the rest of a heavy repair (the whole
/// machine sat 66% idle). This opts out of execution-speed throttling
/// while leaving priority CLASS alone, so we schedule normally instead
/// of being parked, without starving anyone the way a raised priority
/// would. No-op off Windows and on Windows versions without the API.
// `pub`, matching the `cfg(not(windows))` twin below - and NOT optional:
// nzbfast's lib and main both call this at startup from outside the
// crate, so demoting it makes the function unreachable, then dead code,
// then a `-D warnings` error in the windows-gated clippy job. A
// visibility change under a `#[cfg]` can only be validated on the gated
// platform: a macOS `--all-targets` run compiles the OTHER arm and reads
// clean either way (§103.6, 12 Aug).
#[cfg(windows)]
pub fn opt_out_of_power_throttling() {
    #[repr(C)]
    struct PowerThrottlingState {
        version: u32,
        control_mask: u32,
        state_mask: u32,
    }
    const VERSION: u32 = 1; // PROCESS_POWER_THROTTLING_CURRENT_VERSION
    const EXECUTION_SPEED: u32 = 0x1; // PROCESS_POWER_THROTTLING_EXECUTION_SPEED
    const PROCESS_POWER_THROTTLING: i32 = 4; // PROCESS_INFORMATION_CLASS
    #[link(name = "kernel32")]
    // SAFETY: signatures match the documented kernel32 exports
    // (GetCurrentProcess, SetProcessInformation).
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn SetProcessInformation(
            process: isize,
            class: i32,
            info: *const core::ffi::c_void,
            size: u32,
        ) -> i32;
    }
    let state = PowerThrottlingState {
        version: VERSION,
        control_mask: EXECUTION_SPEED,
        state_mask: 0, // control it, and set it OFF
    };
    // Failure (older Windows) just leaves the OS default in place.
    // SAFETY: `state` is a live #[repr(C)] struct matching the documented
    // PROCESS_POWER_THROTTLING_STATE layout (the named constants above),
    // and the pointer and size passed describe exactly that struct.
    unsafe {
        SetProcessInformation(
            GetCurrentProcess(),
            PROCESS_POWER_THROTTLING,
            &state as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<PowerThrottlingState>() as u32,
        );
    }
}

#[cfg(not(windows))]
pub fn opt_out_of_power_throttling() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The budget a host of THIS pointer width can actually hold.
    /// `MemBudget` clamps to [`MemBudget::ADDRESS_SPACE_CEIL`] on 32-bit
    /// (armv7), so an expectation written as a flat 16 GiB is not wrong
    /// there so much as unreachable - a 32-bit process has ~3 GiB of
    /// address space in total. Capping the EXPECTATION keeps one set of
    /// assertions instead of two, and keeps them honest: the clamp is
    /// pinned on its own in `a_32_bit_budget_is_held_to_the_address_space`.
    fn fits(bytes: u64) -> u64 {
        #[cfg(target_pointer_width = "32")]
        {
            bytes.min(MemBudget::ADDRESS_SPACE_CEIL)
        }
        #[cfg(not(target_pointer_width = "32"))]
        {
            bytes
        }
    }

    /// A 32-bit host holds the budget to something it can address, and
    /// every cap below it stays consistent with the total it reports.
    /// The failure this guards is not a crash: `(total / 100 * 45) as
    /// usize` used to WRAP, so `--mem-limit 10G` printed 10 GB and gave
    /// the extractor 512 MB, with nothing anywhere saying so.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn a_32_bit_budget_is_held_to_the_address_space() {
        let b = MemBudget::with_total(10 << 30);
        assert_eq!(b.total, MemBudget::ADDRESS_SPACE_CEIL);
        // Every slice fits inside the whole - the property a wrap breaks.
        assert!(b.holds_cap() as u64 <= b.total);
        assert!(b.partials_cap() as u64 <= b.total);
        assert!(b.holds_cap() + b.partials_cap() < b.total as usize);
        // And a budget UNDER the ceiling is untouched.
        assert_eq!(MemBudget::with_total(512 << 20).total, 512 << 20);
    }

    /// The `NZBFAST_HOLDS_CAP` bench override takes `--mem-limit`'s
    /// DECIMAL units, and the override itself is reduce-only (asserted
    /// at the call site by `min(natural)`) so no budget invariant moves.
    /// Parsing is tested rather than the env read: the override latches
    /// in a process-wide `OnceLock`, so a test that set the variable
    /// would decide the value for every other test in the binary.
    #[test]
    fn holds_cap_override_parses_decimal_sizes() {
        assert_eq!(parse_decimal_size("400M"), Some(400_000_000));
        assert_eq!(parse_decimal_size("2400m"), Some(2_400_000_000));
        assert_eq!(parse_decimal_size("2G"), Some(2_000_000_000));
        assert_eq!(parse_decimal_size("512K"), Some(512_000));
        assert_eq!(parse_decimal_size("1024"), Some(1024));
        assert_eq!(parse_decimal_size(""), None);
        assert_eq!(parse_decimal_size("M"), None);
        assert_eq!(parse_decimal_size("1.5G"), None);
        assert_eq!(parse_decimal_size("18446744073709551615G"), None);
        // Reduce-only: an override ABOVE the natural slice is ignored,
        // which is what keeps `holds_cap + partials_cap < total`.
        let b = MemBudget::with_total(1 << 30);
        assert_eq!(b.holds_cap(), (1u64 << 30) as usize / 100 * 45);
    }

    /// TODO 281 AN4: what a launcher is allowed to say with
    /// `NZBFAST_CPU_WORKERS`.
    ///
    /// The reading of the variable is not tested here and cannot be:
    /// [`cpu_workers`] latches its answer in a process-wide `OnceLock`,
    /// so a test that set the variable would be testing whichever test
    /// ran first. What IS testable is the rule the value is judged by,
    /// which is where every way of getting this wrong lives.
    #[test]
    fn cpu_workers_override_is_bounded_and_refuses_nonsense() {
        assert_eq!(cpu_workers_override("6"), Some(6));
        assert_eq!(cpu_workers_override("  6\n"), Some(6));
        // Zero workers is a hang, not a setting, and neither is a typo:
        // both fall back to the machine rather than to nothing.
        assert_eq!(cpu_workers_override("0"), None);
        assert_eq!(cpu_workers_override(""), None);
        assert_eq!(cpu_workers_override("many"), None);
        assert_eq!(cpu_workers_override("-4"), None);
        assert_eq!(cpu_workers_override("4.5"), None);
        // Clamped rather than trusted: this arrives from a launcher.
        assert_eq!(cpu_workers_override("100000"), Some(1024));
        assert_eq!(cpu_workers_override("1024"), Some(1024));
        // And with nothing set at all the answer is still a usable pool
        // width - never zero, never past the ceiling.
        let n = cpu_workers();
        assert!((1..=1024).contains(&n), "cpu_workers() = {n}");
    }

    #[test]
    fn budget_slices_and_clamps() {
        let b = MemBudget::with_total(1 << 30);
        assert_eq!(b.holds_cap(), (1u64 << 30) as usize / 100 * 45);
        assert_eq!(b.partials_cap(), (1u64 << 30) as usize / 100 * 30);
        assert!(b.bufpool_bufs() >= 32 && b.bufpool_bufs() <= 512);
        // B2: channel depth scales with the budget and stays clamped.
        assert_eq!(
            b.channel_depth(),
            ((1u64 << 30) / 16 / (800 * 1024)) as usize
        );
        assert_eq!(MemBudget::with_total(256 << 20).channel_depth(), 20);
        assert_eq!(MemBudget::with_total(64 << 20).channel_depth(), 8); // floor
        // B3: wire-side in-flight cap scales with the budget, clamped.
        assert_eq!(b.inflight_cap(), (1u64 << 30) / 4);
        assert_eq!(MemBudget::with_total(256 << 20).inflight_cap(), 64 << 20);
        assert_eq!(MemBudget::with_total(64 << 20).inflight_cap(), 32 << 20); // floor
        // The UPPER clamps need a budget large enough to reach them, and
        // a 32-bit host cannot hold one (see `fits`). There the budget
        // stops at the address-space ceiling first, so these would pin
        // the ceiling's arithmetic rather than the clamp they name.
        #[cfg(not(target_pointer_width = "32"))]
        {
            assert_eq!(MemBudget::with_total(16 << 30).channel_depth(), 256); // cap
            assert_eq!(MemBudget::with_total(16 << 30).inflight_cap(), 2 << 30); // cap
        }
        // Slices always fit inside the whole.
        assert!(b.holds_cap() + b.partials_cap() < b.total as usize);
        // Floor: even absurd --mem-limit values keep the engine viable.
        assert_eq!(MemBudget::with_total(1).total, MemBudget::MIN);
        // Auto is clamped sane on any machine (a tight cgroup limit may
        // pull it below the 256 MB auto floor, never below MIN).
        let a = MemBudget::auto();
        assert!(a.total >= MemBudget::MIN && a.total <= 16 << 30);
    }

    #[test]
    fn auto_respects_cgroup_limit() {
        let gb = 1u64 << 30;
        // Uncontained: quarter of RAM, clamped.
        assert_eq!(MemBudget::auto_total(Some(64 * gb), None), fits(16 * gb));
        assert_eq!(MemBudget::auto_total(Some(512 << 20), None), 256 << 20);
        // docker --memory 1g on a big host: half the limit, not RAM/4.
        assert_eq!(MemBudget::auto_total(Some(25 * gb), Some(gb)), gb / 2);
        // Roomy limit doesn't inflate the host-derived figure.
        assert_eq!(
            MemBudget::auto_total(Some(8 * gb), Some(32 * gb)),
            fits(2 * gb)
        );
        // Tiny limit floors at MIN, not at the 256 MB auto floor.
        assert_eq!(
            MemBudget::auto_total(Some(25 * gb), Some(96 << 20)),
            MemBudget::MIN
        );
    }

    #[test]
    fn concurrency_caps_tiers() {
        let mb = |n: u64| Some(n << 20);
        // Tiny tier: <=512 MB.
        assert_eq!(
            concurrency_caps_for(mb(256), None),
            Some(ConcurrencyCaps {
                connections: 4,
                window: 2,
                decoders: 2
            })
        );
        assert_eq!(
            concurrency_caps_for(mb(512), None),
            Some(ConcurrencyCaps {
                connections: 4,
                window: 2,
                decoders: 2
            })
        );
        // Small tier: <=1 GB.
        assert_eq!(
            concurrency_caps_for(mb(513), None),
            Some(ConcurrencyCaps {
                connections: 6,
                window: 3,
                decoders: 2
            })
        );
        assert_eq!(
            concurrency_caps_for(mb(1024), None),
            Some(ConcurrencyCaps {
                connections: 6,
                window: 3,
                decoders: 2
            })
        );
        // Above 1 GB: no caps - big-box behavior byte-identical.
        assert_eq!(concurrency_caps_for(mb(1025), None), None);
        assert_eq!(concurrency_caps_for(Some(64 << 30), None), None);
        // The tighter of host RAM and cgroup limit picks the tier.
        assert_eq!(
            concurrency_caps_for(Some(64 << 30), mb(512)),
            Some(ConcurrencyCaps {
                connections: 4,
                window: 2,
                decoders: 2
            })
        );
        assert_eq!(
            concurrency_caps_for(mb(512), Some(64 << 30))
                .unwrap()
                .connections,
            4
        );
        // Unknown RAM never clamps - a failed probe is not a small box.
        assert_eq!(concurrency_caps_for(None, None), None);
        assert_eq!(concurrency_caps_for(None, mb(256)).unwrap().connections, 4);
    }

    #[test]
    fn concurrency_caps_apply_clamps_only_downward() {
        let caps = ConcurrencyCaps {
            connections: 6,
            window: 3,
            decoders: 2,
        };
        // Above the caps: clamped, per axis.
        assert_eq!(caps.apply(8, 4, 4), (6, 3, 2));
        // At or below: untouched - a deliberate low setting stays.
        assert_eq!(caps.apply(2, 1, 1), (2, 1, 1));
        assert_eq!(caps.apply(6, 3, 2), (6, 3, 2));
        // Mixed: only the offending axis moves.
        assert_eq!(caps.apply(4, 4, 1), (4, 3, 1));
    }

    #[test]
    fn rss_and_ram_readable() {
        // Smoke: both syscall paths work on the platforms we test on.
        assert!(physical_ram().unwrap_or(0) > 1 << 30);
        assert!(peak_rss().unwrap_or(0) > 1 << 20);
        // Current RSS is live and can never exceed the getrusage peak.
        let cur = current_rss().unwrap_or(0);
        assert!(cur > 1 << 20);
        assert!(cur <= peak_rss().unwrap_or(u64::MAX));
        // CPU clock is readable and monotone.
        let a = cpu_time_secs().unwrap();
        let b = cpu_time_secs().unwrap();
        assert!(a >= 0.0 && b >= a);
    }

    /// Qualitative pins for the RAR execution policy, not exact numbers: a
    /// small host must stay on bounded modes, a big one must be allowed
    /// past rars' built-in 256 MiB flat cap, and more budget never yields a
    /// strictly smaller allowance.
    #[test]
    fn rar_execution_policy_scales_with_budget() {
        // A 256 MiB total budget must not admit a ~245 MiB flat plan: the
        // flat cap lands well under the plan.
        let small = MemBudget::with_total(256 << 20).rar_execution_policy();
        assert!(small.flat_output_limit < 200 << 20, "{small:?}");
        assert!(small.max_workers <= 2, "{small:?}");

        // A 16 GB budget clears the built-in 256 MiB chain cap - on a host
        // that can hold a 16 GB budget. A 32-bit one cannot, so there the
        // answer is correctly "stays on the bounded modes", which the
        // `small` block above already pins.
        #[cfg(not(target_pointer_width = "32"))]
        {
            let large = MemBudget::with_total(16 << 30).rar_execution_policy();
            assert!(large.flat_output_limit > 256 << 20, "{large:?}");
            assert!(large.max_workers >= 8, "{large:?}");
        }

        // Monotone: more budget never shrinks the allowances.
        let mut previous = MemBudget::with_total(MemBudget::MIN).rar_execution_policy();
        for shift in 27..36 {
            let policy = MemBudget::with_total(1u64 << shift).rar_execution_policy();
            assert!(policy.working_memory_limit >= previous.working_memory_limit);
            assert!(policy.flat_output_limit >= previous.flat_output_limit);
            assert!(policy.max_workers >= previous.max_workers);
            previous = policy;
        }
    }

    #[test]
    fn trim_links_and_survives() {
        // Smoke: the platform symbol resolves and a burst of freed
        // allocations doesn't make trim misbehave. No RSS assertion -
        // how much the OS takes back is its business.
        let bufs: Vec<Vec<u8>> = (0..64).map(|_| vec![7u8; 1 << 20]).collect();
        drop(bufs);
        trim();
        trim(); // idempotent on an already-trimmed heap
    }
}

#[cfg(test)]
mod lzma_dict_budget_tests {
    use super::*;

    #[test]
    fn the_first_window_always_admits_even_over_budget() {
        // A single -mx=9 window (256 MiB) must decode under any budget,
        // including a 64 MiB --mem-limit, or a legitimate archive fails.
        assert!(dict_charge_admits(0, 256 << 20, 64 << 20));
        assert!(dict_charge_admits(0, u64::MAX, 1));
    }

    #[test]
    fn a_concurrent_window_is_bounded_by_the_budget() {
        let cap = 256 << 20;
        // One 256 MiB window is live; a second would make 512 MiB > cap.
        assert!(!dict_charge_admits(256 << 20, 256 << 20, cap));
        // A second window that still fits is admitted.
        assert!(dict_charge_admits(64 << 20, 64 << 20, 256 << 20));
        // Exactly at the cap admits (<=), one byte over does not.
        assert!(dict_charge_admits(128 << 20, 128 << 20, 256 << 20));
        assert!(!dict_charge_admits(128 << 20, (128 << 20) + 1, 256 << 20));
    }

    #[test]
    fn overflow_saturates_rather_than_wraps() {
        // Without saturation `(MAX-1) + 2` would wrap to 1 and slip under
        // a small cap; saturating_add pins it at MAX so it is refused.
        assert!(!dict_charge_admits(u64::MAX - 1, 2, 100));
    }
}
