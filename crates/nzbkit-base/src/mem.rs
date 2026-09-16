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
    {
        if let Some((total, _)) = global_memory_status() {
            return Some(total);
        }
    }
    None
}

/// Physical memory the OS could hand out right now, in bytes: free pages
/// plus the file cache it would reclaim first (Windows `ullAvailPhys`,
/// which counts the standby list; Linux `MemAvailable`; macOS free,
/// file-backed and purgeable pages, and only when opted in - see that arm).
/// `None` where the OS offers no such figure (or macOS has not opted in),
/// so a caller gating on it keeps its old behaviour there.
///
/// It moves from one call to the next, which is the point for its caller:
/// whether a MAPPING of a large payload can stay resident
/// (`par2gen::mapped_payload_fits_memory`, TODO 345) is a question about
/// the cache at this moment, not about the machine.
#[cfg(windows)]
pub fn available_ram() -> Option<u64> {
    global_memory_status().map(|(_, avail)| avail)
}

/// See the Windows arm.
#[cfg(target_os = "linux")]
pub fn available_ram() -> Option<u64> {
    meminfo_available(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

/// See the Windows arm: [`vm_available_ram`], always.
///
/// THE DEFAULT SINCE 16 SEP 2026, when the knee was measured on a Mac whose
/// RAM is smaller than the member, which is the only box that can show it
/// (TODO 345 D, research/PARFAST-OVER-RAM-CREATE-2026-09-15.md section
/// 6.5). A 48 GiB member on a 32 GiB MacBook Air, no pin anywhere: the
/// mapped route took 316 s and 353 s against 124 s on the copied windows,
/// with 8.5 M hard faults a leg and ~245 GB paged in for a 51.5 GB member,
/// while all three legs over this reading refused at the figure it returned
/// and walled with the copied windows. A 13 GiB control on the same box
/// never refused and walled with the mapped route, so the reading does not
/// cost a member that fits. One set digest per member, both rounds.
///
/// It was OPT-IN until then, behind `NZBFAST_MACOS_AVAILABLE_RAM=1`,
/// because this function's one caller REFUSES a mapping on the strength of
/// it and the collapse was unmeasured on a Mac: the 512 GiB M3 Ultra could
/// not be pinned down to a small machine's memory without starving every
/// other program on it (sections 6.2 and 6.3). That variable is GONE - the
/// override that maps regardless is `NZBFAST_PAR2GEN_MAP_FIT=off`, on every
/// platform, and it is what an A/B arm should set now.
#[cfg(target_os = "macos")]
pub fn available_ram() -> Option<u64> {
    vm_available_ram()
}

/// macOS memory the OS could hand out now: `host_statistics64(HOST_VM_INFO64)`,
/// summed as [`vm_available_bytes`] says. For `examples/memprobe.rs` and
/// the knee round; the gate reads [`available_ram`], which since 16 Sep
/// 2026 is this same reading.
#[cfg(target_os = "macos")]
pub fn vm_available_ram() -> Option<u64> {
    // vm_statistics64 (mach/vm_statistics.h) through
    // `total_uncompressed_pages_in_compressor`, the HOST_VM_INFO64 layout
    // every supported macOS returns in full; newer kernels append fields
    // and copy only as many as `count` asks for. Four natural_t then nine
    // u64 then two natural_t then four u64 then four natural_t then one
    // u64: no padding under the header's `pack(4)` or under repr(C).
    #[repr(C)]
    struct VmStatistics64 {
        free_count: u32,
        _active_count: u32,
        _inactive_count: u32,
        _wire_count: u32,
        _counters: [u64; 9],
        purgeable_count: u32,
        speculative_count: u32,
        _compressor_counters: [u64; 4],
        _compressor_page_count: u32,
        _throttled_count: u32,
        external_page_count: u32,
        _internal_page_count: u32,
        _total_uncompressed_pages_in_compressor: u64,
    }
    const HOST_VM_INFO64: i32 = 4;
    // SAFETY: signatures match mach/mach_host.h and mach/mach_port.h
    // (`host_t`, `mach_port_t` and `ipc_space_t` are u32 ports,
    // `host_info64_t` is `integer_t*`, `vm_size_t` is pointer-sized).
    unsafe extern "C" {
        fn mach_host_self() -> u32;
        fn host_statistics64(host: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
        fn host_page_size(host: u32, size: *mut usize) -> i32;
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
    }
    // SAFETY: VmStatistics64 is #[repr(C)] matching the layout above,
    // every field is a plain integer so zeroed() is a valid value, `count`
    // is the struct size in integer_t units as host_statistics64 requires,
    // and every out-pointer is a valid &mut. `mach_host_self` hands back a
    // send right with a user reference added, which is released before
    // returning so a long-lived process does not accumulate them.
    unsafe {
        let host = mach_host_self();
        let mut stats: VmStatistics64 = std::mem::zeroed();
        let mut count = (std::mem::size_of::<VmStatistics64>() / 4) as u32;
        let mut page: usize = 0;
        let ok = host_statistics64(host, HOST_VM_INFO64, (&raw mut stats).cast(), &mut count) == 0
            && host_page_size(host, &mut page) == 0;
        mach_port_deallocate(mach_task_self_, host);
        if !ok {
            return None;
        }
        vm_available_bytes(
            stats.free_count,
            stats.speculative_count,
            stats.external_page_count,
            stats.purgeable_count,
            page as u64,
        )
    }
}

/// See the Windows arm: no figure here, so callers keep their old route.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn available_ram() -> Option<u64> {
    None
}

/// macOS available memory from HOST_VM_INFO64 counts, in bytes: free
/// pages that are not speculative, plus every file-backed page, plus
/// purgeable pages. `None` for a zero page size.
///
/// Each term, and each page count left out, is argued from this Mac's own
/// counters (TODO 345 D, research/PARFAST-OVER-RAM-CREATE-2026-09-15.md
/// section 6):
/// - `free_count` INCLUDES the speculative pages (`vm_stat` prints
///   `free_count - speculative_count` as "Pages free"), and speculative
///   pages are file read-ahead, already inside `external_page_count`:
///   measured 15 Sep 2026 on an M3 Ultra, file-backed plus anonymous
///   pages (6,177,925 + 7,919,264) equal active plus inactive plus
///   speculative (6,956,479 + 6,811,680 + 329,030) exactly. Adding
///   speculative again would count read-ahead twice.
/// - `external_page_count` is the file cache, active and inactive alike:
///   the pageout daemon evicts either without writing anything, the same
///   pages Linux counts in `MemAvailable`.
/// - `purgeable_count` is volatile memory the kernel drops on demand.
/// - `inactive_count` is NOT a term, although a sum of free + inactive +
///   speculative + purgeable is the common reading: inactive holds
///   anonymous pages too, which the kernel can only reclaim by
///   compressing or swapping them, and Windows' `ullAvailPhys` leaves the
///   same class (the modified list) out.
#[cfg(any(target_os = "macos", test))]
fn vm_available_bytes(
    free_count: u32,
    speculative_count: u32,
    external_page_count: u32,
    purgeable_count: u32,
    page_size: u64,
) -> Option<u64> {
    let pages = u64::from(free_count.saturating_sub(speculative_count))
        + u64::from(external_page_count)
        + u64::from(purgeable_count);
    (page_size > 0).then(|| pages.saturating_mul(page_size))
}

/// `MemAvailable` out of a `/proc/meminfo` text, in bytes.
#[cfg(any(target_os = "linux", test))]
fn meminfo_available(meminfo: &str) -> Option<u64> {
    meminfo.lines().find_map(|line| {
        let kb = line.strip_prefix("MemAvailable:")?.trim();
        kb.strip_suffix("kB")?
            .trim()
            .parse::<u64>()
            .ok()?
            .checked_mul(1024)
    })
}

/// `(ullTotalPhys, ullAvailPhys)` from GlobalMemoryStatusEx - the one FFI
/// site both [`physical_ram`] and [`available_ram`] read.
#[cfg(windows)]
fn global_memory_status() -> Option<(u64, u64)> {
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
            return Some((st.total_phys, st.avail_phys));
        }
    }
    None
}

#[cfg(test)]
mod available_ram_tests {
    #[test]
    fn meminfo_available_reads_the_kilobyte_line_and_nothing_else() {
        let text = "MemTotal:       32768000 kB\nMemFree:  100 kB\nMemAvailable:   20480000 kB\nBuffers: 5 kB\n";
        assert_eq!(super::meminfo_available(text), Some(20_480_000 * 1024));
        assert_eq!(super::meminfo_available("MemTotal: 1 kB\n"), None);
        assert_eq!(super::meminfo_available("MemAvailable: lots\n"), None);
    }

    /// The M3 Ultra's own counters from 15 Sep 2026 (vm_stat, 16 KiB
    /// pages): speculative is inside `free_count` and inside the
    /// file-backed count, so it is taken out once, and inactive is not a
    /// term.
    #[test]
    fn vm_available_bytes_counts_speculative_once_and_leaves_inactive_out() {
        let (free_shown, spec, file, purgeable) =
            (18_468_700u32, 329_030u32, 6_177_925u32, 1_064_322u32);
        let free_count = free_shown + spec;
        assert_eq!(
            super::vm_available_bytes(free_count, spec, file, purgeable, 16_384),
            Some((18_468_700u64 + 6_177_925 + 1_064_322) * 16_384)
        );
        // A speculative count above free (a torn read between the two
        // counters) must not wrap.
        assert_eq!(
            super::vm_available_bytes(5, 9, 10, 0, 4096),
            Some(10 * 4096)
        );
        assert_eq!(super::vm_available_bytes(1, 0, 1, 1, 0), None);
    }
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

/// Every cgroup directory this process is charged to, with the ancestors
/// each line walks up to its mount root, paired with whether that line is
/// the v2 unified hierarchy. Both [`cgroup_mem_limit`] and
/// [`cgroup_available_ram`] fold over this, so the "which directories count"
/// rule has one copy: private-cgroupns containers (path `/`) and nested host
/// paths (systemd slices, docker with host cgroupns) resolve the same way for
/// both readings, and a reader who has checked one has checked the other.
#[cfg(target_os = "linux")]
fn cgroup_dirs() -> Vec<(std::path::PathBuf, bool)> {
    use std::path::Path;
    let cg = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let mut out = Vec::new();
    for line in cg.lines() {
        let mut it = line.splitn(3, ':');
        let (Some(_), Some(ctrls), Some(rel)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let (base, v2) = if ctrls.is_empty() {
            (Path::new("/sys/fs/cgroup"), true)
        } else if ctrls.split(',').any(|c| c == "memory") {
            (Path::new("/sys/fs/cgroup/memory"), false)
        } else {
            continue;
        };
        let mut dir = base.join(rel.trim_start_matches('/'));
        loop {
            out.push((dir.clone(), v2));
            if dir == *base || !dir.pop() {
                break;
            }
        }
    }
    out
}

/// A cgroup byte counter, with v1's page-rounded `i64::MAX` and v2's "max"
/// sentinel both read as absent.
#[cfg(target_os = "linux")]
fn cgroup_u64(p: &std::path::Path) -> Option<u64> {
    let v: u64 = std::fs::read_to_string(p).ok()?.trim().parse().ok()?;
    (v < 1 << 48).then_some(v)
}

/// One field out of a cgroup `memory.stat`.
#[cfg(target_os = "linux")]
fn cgroup_stat_field(p: &std::path::Path, key: &str) -> Option<u64> {
    let text = std::fs::read_to_string(p).ok()?;
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == key).then(|| it.next()?.parse().ok())?
    })
}

/// Cgroup memory limit on our own cgroup (Linux): tightest `memory.max`
/// (v2) or `memory.limit_in_bytes` (v1 memory controller) over
/// [`cgroup_dirs`]. "max" / v1's page-rounded i64::MAX sentinel read as no
/// limit.
// `pub`, matching the `cfg(not(linux))` twin below: examples/memprobe.rs
// consumes it from OUTSIDE the crate, so a `pub(crate)` here is E0603 on
// Linux and invisible everywhere else (see the §103.6 note below).
#[cfg(target_os = "linux")]
pub fn cgroup_mem_limit() -> Option<u64> {
    cgroup_dirs()
        .iter()
        .filter_map(|(dir, v2)| {
            cgroup_u64(&dir.join(if *v2 {
                "memory.max"
            } else {
                "memory.limit_in_bytes"
            }))
        })
        .min()
}

#[cfg(not(target_os = "linux"))]
pub fn cgroup_mem_limit() -> Option<u64> {
    None
}

/// How much memory this process's cgroup could still hold, in bytes, or
/// `None` outside a limited cgroup - the CONTAINER analogue of
/// [`available_ram`], and the reading that function cannot give.
///
/// **`/proc/meminfo` is not namespaced.** Inside a memory-limited container
/// `MemAvailable` reports the HOST's figure, so [`available_ram`]'s Linux
/// arm answers for the machine and not for the cgroup the process actually
/// lives in. Cgroup v2 charges page cache to the cgroup, so a mapping
/// admitted on the host's figure is charged, reclaimed under the limit and
/// refaulted - which is exactly the collapse
/// `par2gen::mapped_payload_fits_memory` exists to prevent.
///
/// Measured 16 Sep 2026 on an 8-core 31 GB Linux box, one 2 GiB member at 5%
/// (`-b32768`), every container reading `MemAvailable: 30926756 kB` whatever
/// its limit, mapped against copied windows: at a 1 GiB limit the gate
/// admitted the mapping and the create took 147-152 s with ~1.0 M major
/// faults and 34.2-34.5 GB read off disk for a 2 GiB member, where the copied
/// windows took 30.7-42.4 s; at 2 GiB, 38.7-50.8 s against 11.0-13.7. At
/// 3 GiB the mapping FITS and wins as it is meant to, 4.1-4.2 s against
/// 4.5-6.1, which is why the reading has to be a figure and not "refuse in a
/// container". This composition refuses at 1 and 2 GiB and admits at 3.
/// Round and per-leg counters:
/// `research/PAR2GEN-GATE-CGROUP-BLIND-2026-09-16.md`, harness
/// `research/harness/cgmap.py`.
///
/// **Its caller does not compare a payload against this figure directly**,
/// and a reader of that gate should not expect it to: since 16 Sep 2026
/// `par2gen::map_fit::mapped_payload_fits_memory` subtracts the create's own
/// working set from THIS reading and not from [`available_ram`]'s, because
/// `limit - (usage - cache)` is a hard limit less an unreclaimable charge
/// while `MemAvailable` is an estimate with the kernel's reserve already
/// deducted. That asymmetry is measured; the arms are in section 8 of the
/// round below.
///
/// The composition is [`cgroup_available_from`]: a cgroup LIMIT is not an
/// AVAILABLE figure and cannot be dropped in as one, because `memory.current`
/// already holds whatever cache this cgroup has charged. It is NOT
/// [`MemBudget::auto_total`]'s half-the-limit either - that is a budget
/// heuristic for when a tier spills, and this is a question about what the
/// page cache can hold.
#[cfg(target_os = "linux")]
pub fn cgroup_available_ram() -> Option<u64> {
    cgroup_dirs()
        .iter()
        .filter_map(|(dir, v2)| {
            let (limit, usage, cache) = if *v2 {
                ("memory.max", "memory.current", "file")
            } else {
                (
                    "memory.limit_in_bytes",
                    "memory.usage_in_bytes",
                    "total_cache",
                )
            };
            Some(cgroup_available_from(
                cgroup_u64(&dir.join(limit))?,
                cgroup_u64(&dir.join(usage))?,
                cgroup_stat_field(&dir.join("memory.stat"), cache)?,
            ))
        })
        .min()
}

#[cfg(not(target_os = "linux"))]
pub fn cgroup_available_ram() -> Option<u64> {
    None
}

/// Pure half of [`cgroup_available_ram`]: the limit less the charge that
/// cannot be reclaimed to make room.
///
/// `usage` (v2 `memory.current`) counts this cgroup's whole charge, page
/// cache included, so `limit - usage` UNDERSTATES what a mapping could have
/// by every cached byte - on a cgroup that has just read its member that is
/// most of the limit, and the gate would refuse a payload that fits. The
/// cache is reclaimable to make room for the mapping, so the term that binds
/// is `usage - cache`: anonymous memory, kernel memory and socket buffers,
/// the charge the kernel can only move by swapping or OOM-killing.
///
/// `cache` is v2's `file` (v1's `total_cache`) whole, not `file` less
/// `file_dirty`/`file_writeback`: dirty pages are reclaimable after a
/// writeback this create is not waiting on, and both are transient next to a
/// payload measured in GiB. Over-counting them by a few MiB moves no
/// admission this round could see.
#[cfg(any(target_os = "linux", test))]
fn cgroup_available_from(limit: u64, usage: u64, cache: u64) -> u64 {
    limit.saturating_sub(usage.saturating_sub(cache))
}

/// The tighter of two optional readings, either of which may be absent -
/// [`available_ram`] (the machine) against [`cgroup_available_ram`] (the
/// container). `None` only when neither OS offers a figure, which is what
/// keeps a caller's old route on a platform that reports nothing.
pub fn tightest_available(host: Option<u64>, cgroup: Option<u64>) -> Option<u64> {
    match (host, cgroup) {
        (Some(h), Some(c)) => Some(h.min(c)),
        (h, c) => h.or(c),
    }
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
/// The environment is read once. The value cannot change while the
/// process runs, and these sites sit inside repair and decode loops
/// where a `getenv` per call would be a syscall in a hot path.
/// [`set_cpu_workers`] is checked ahead of that cache, so an entry point
/// that publishes a width still binds every site even if something read
/// the default first.
pub fn cpu_workers() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    match CPU_WORKERS_PUBLISHED.load(std::sync::atomic::Ordering::Relaxed) {
        0 => *N.get_or_init(|| {
            let machine = std::thread::available_parallelism().map_or(4, |n| n.get());
            match std::env::var("NZBFAST_CPU_WORKERS") {
                Ok(v) => cpu_workers_override(&v).unwrap_or(machine),
                Err(_) => machine,
            }
        }),
        n => n,
    }
}

/// The width an ENTRY POINT published, or 0 when none has - the pool
/// twin of `PROCESS_BUDGET`, and set the same way, once, before any
/// command runs.
static CPU_WORKERS_PUBLISHED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Publish the pool width for this process: `parfast -t<n>`, which is
/// par2cmdline's "number of threads used for main processing".
///
/// It beats `NZBFAST_CPU_WORKERS` on purpose. That variable is a
/// launcher's ceiling for a process it starts (the Android
/// `DeviceProfile.cpuWorkers` path); `-t` is the person at the keyboard
/// naming a width for THIS run, and the more specific instruction wins.
/// Clamped to the same 1..=1024 band the variable is, so a `-t0` is a
/// serial run and not a hang, and so no caller has to re-apply `.max(1)`
/// to a number that came from here.
///
/// Publishing rather than threading the count through every signature is
/// the only shape that reaches the sites that matter: the fold, the
/// solve, the packet scan and the catalog build all size themselves from
/// [`cpu_workers`], and none of them takes a width from the CLI. See
/// `set_process_budget` for the same decision about `-m`.
pub fn set_cpu_workers(n: usize) {
    CPU_WORKERS_PUBLISHED.store(n.clamp(1, 1024), std::sync::atomic::Ordering::Relaxed);
}

thread_local! {
    /// A ceiling on the WINDOW FOLD's worker count, published by a create
    /// that has measured its fold outrunning its whole-file MD5 chain, or 0
    /// when none is in force. Read by `linalg::fold_parallel` under
    /// [`cpu_workers`]; never above it.
    ///
    /// Why a create would ask for FEWER fold workers: a single-file (or
    /// few-file) create is bound by the whole-file MD5 chain - one serial
    /// thread - and the fold overlaps it. On a box with cores to spare the
    /// fold's workers cost the chain nothing; on an 8-vCPU box every fold
    /// worker past what the fold needs to keep pace is a thread the OS
    /// schedules fairly AGAINST the one thread whose length is the wall.
    /// Measured 13 Sep 2026 on a Zen 4 VM, 8.86 GB one file at 5%: eight
    /// fold workers 13.26 s, seven 12.90, six 12.34, four 11.91 - the same
    /// binary, `-t` the only change (research/PARFAST-SINGLE-FILE-MD5-
    /// HEADROOM-2026-09-13.md). `par2gen::fold_windows` paces the width
    /// from what it measures window by window and clears it on exit.
    ///
    /// PER THREAD since 15 Sep 2026, and it was process-global until then.
    /// The global was right while "the parfast queue runs one create at a
    /// time" held, and the queue now admits a second large single-file
    /// create beside the first (apps/parfast `parfast-session`'s
    /// `pairing`): two creates writing one atomic is last-writer-wins, and
    /// the first to finish zeroed it under the other, which then folded at
    /// full width for the rest of its run. The fold reads its width on the
    /// thread that calls `linalg::fold_parallel`, and the fused window loop
    /// calls it on the same driver thread that holds the cap, so each
    /// create's ceiling now binds its own fold and nobody else's - a repair
    /// on another thread included.
    static FOLD_WIDTH_CAP: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Live [`FoldWidthCap`]s in this process, and the sum of their current
/// widths - what [`paced_folds`] reports. Two atomics read without a
/// lock, so every writer orders its two stores to err towards REFUSING
/// a reader's admission (a count that is low only alongside a width sum
/// that is high), never towards admitting one.
static PACED_FOLDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PACED_WIDTH_SUM: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The width the window fold may use right now: [`cpu_workers`] unless a
/// create on THIS thread has published a lower ceiling through
/// [`FoldWidthCap`].
pub fn fold_workers() -> usize {
    let cores = cpu_workers().max(1);
    match FOLD_WIDTH_CAP.with(std::cell::Cell::get) {
        0 => cores,
        cap => cap.clamp(1, cores),
    }
}

/// What the paced creates live in this process are running at right now:
/// how many hold a [`FoldWidthCap`], and their fold widths summed. Each of
/// those creates also runs one whole-file MD5 chain thread beside its
/// fold, which a caller budgeting cores adds itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PacedFolds {
    pub creates: usize,
    pub fold_workers: usize,
}

/// See [`PacedFolds`]. A scheduler's reading, not a reservation: a pacer
/// moves its width window by window, so the answer is as old as the last
/// window of each create.
pub fn paced_folds() -> PacedFolds {
    PacedFolds {
        creates: PACED_FOLDS.load(std::sync::atomic::Ordering::Acquire),
        fold_workers: PACED_WIDTH_SUM.load(std::sync::atomic::Ordering::Acquire),
    }
}

/// The published fold-width ceiling, held for exactly as long as the
/// create that measured it: `Drop` clears it, so a create that returns
/// early (an error, a cancel) cannot leave its thread's next fold
/// narrowed. Bound to the thread that published it (it is `!Send`), which
/// is the thread whose fold it narrows - see `FOLD_WIDTH_CAP` for why it
/// is not process-global any more. One cap per thread: a second publish
/// on a thread that already holds one would overwrite it, and nothing
/// nests creates that way.
pub struct FoldWidthCap {
    width: std::cell::Cell<usize>,
    _thread_bound: std::marker::PhantomData<*const ()>,
}

impl FoldWidthCap {
    /// Publish `width` (clamped to `1..=cpu_workers()`) and hold it.
    pub fn publish(width: usize) -> FoldWidthCap {
        let cap = FoldWidthCap {
            width: std::cell::Cell::new(0),
            _thread_bound: std::marker::PhantomData,
        };
        cap.set(width);
        // Width first, count second: a reader between the two sees a width
        // sum with no create to own it, which reads as busier, not freer.
        PACED_FOLDS.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        cap
    }

    /// Move the ceiling while held.
    pub fn set(&self, width: usize) {
        let cores = cpu_workers().max(1);
        let width = width.clamp(1, cores);
        let old = self.width.replace(width);
        // Add the new width before taking the old one away, for the same
        // reason as `publish`.
        PACED_WIDTH_SUM.fetch_add(width, std::sync::atomic::Ordering::AcqRel);
        PACED_WIDTH_SUM.fetch_sub(old, std::sync::atomic::Ordering::AcqRel);
        FOLD_WIDTH_CAP.with(|c| c.set(width));
    }
}

impl Drop for FoldWidthCap {
    fn drop(&mut self) {
        FOLD_WIDTH_CAP.with(|c| c.set(0));
        // Count first, width second: the mirror of `publish`.
        PACED_FOLDS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        PACED_WIDTH_SUM.fetch_sub(self.width.get(), std::sync::atomic::Ordering::AcqRel);
    }
}

/// The FILE-level width an entry point published, or 0 when none has.
/// Separate from [`CPU_WORKERS_PUBLISHED`] because the two axes are
/// separate switches on the reference CLI and multiply rather than
/// replace each other - see [`set_file_workers`].
static FILE_WORKERS_PUBLISHED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// How many FILES to hash at once, when an entry point has named a
/// number: `parfast -T<n>`, which is par2cmdline's "number of files
/// hashed in parallel".
///
/// `None` - nothing published - means "derive it", which is what every
/// caller did before this existed and still does by default. It is
/// deliberately not folded into [`cpu_workers`]: `-t` and `-T` are two
/// switches on the reference and a caller splits one budget across the
/// other axis, so a site that read a single number could not tell a
/// pinned file width from a pinned total.
///
/// A published 0 is not reachable - [`set_file_workers`] clamps to
/// 1..=1024 exactly as [`set_cpu_workers`] does - so 0 unambiguously
/// means unset.
pub fn file_workers() -> Option<usize> {
    match FILE_WORKERS_PUBLISHED.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        n => Some(n),
    }
}

/// Publish the file-hash width for this process: `parfast -T<n>`.
///
/// The twin of [`set_cpu_workers`], set the same way - once, before any
/// command runs - and clamped to the same 1..=1024 band, so `-T0` is a
/// one-file-at-a-time run and not a hang.
///
/// It must NOT re-scale what `-t` published. A verify pass splits one
/// budget across two axes (files in flight, and lanes inside a file);
/// pinning the file axis leaves `cpu_workers` meaning what it meant, and
/// the intra-file share takes the remainder. The two multiply, which is
/// the same rule `parfast`'s own `verify::survey` applies to the same
/// pair of switches. How much that remainder is worth is a separate
/// question with a poor answer today - see TODO 339.
pub fn set_file_workers(n: usize) {
    FILE_WORKERS_PUBLISHED.store(n.clamp(1, 1024), std::sync::atomic::Ordering::Relaxed);
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

    /// What [`Self::with_total`] would DO to a figure a PERSON supplied:
    /// `None` when it is taken as asked, `Some(actual)` when a clamp
    /// moved it.
    ///
    /// Split out from the warning below so the arithmetic is pinnable
    /// without capturing a log, and it answers BOTH clamps in one place:
    /// the [`Self::MIN`] floor, and the 32-bit [`Self::ADDRESS_SPACE_CEIL`]
    /// whose own comment already calls the silence a defect - "it just
    /// made the knob lie, silently, on the one platform where memory is
    /// scarce".
    pub fn limit_clamp(requested: u64) -> Option<u64> {
        let actual = Self::with_total(requested).total;
        (actual != requested).then_some(actual)
    }

    /// The budget a number a PERSON supplied becomes, with the clamp
    /// said out loud.
    ///
    /// USE THIS AT EVERY BOUNDARY WHERE A HUMAN FIGURE ARRIVES, and
    /// `with_total` only where the caller chose the number itself.
    /// There are three such boundaries - `--mem-limit`, the `mem_limit`
    /// setting, and an embedded host's `mem_limit_bytes` - and until
    /// 31 Aug 2026 every one of them clamped in SILENCE.
    ///
    /// What the silence cost, measured rather than argued: `--mem-limit`
    /// parses DECIMAL (`sizes::parse_size`, 1e6 per `M`), so `8M`, `32M`
    /// and `64M` are 8,000,000 / 32,000,000 / 64,000,000 - all three
    /// BELOW the 67,108,864-byte floor and therefore all three the
    /// identical budget. `e2e_chaserepair`'s paged leg was written `8M`
    /// meaning something tight, got the floor, and sat exactly on the
    /// backpressure park mark; it was FLAKY for two days and was found
    /// by a person noticing, not by a job. Note that even `64M` floors -
    /// it is 64 million, not 64 MiB - so spelling the sites `64M` would
    /// NOT have made the number honest, which is why the fix is here and
    /// not in the fixtures.
    ///
    /// `source` names the knob, because this is one function serving
    /// three of them and "your memory limit" is not something a person
    /// can act on.
    pub fn from_user_limit(requested: u64, source: &str) -> MemBudget {
        let budget = Self::with_total(requested);
        // The provenance [`published_user_limit`] reads: this is the one
        // funnel every figure a person supplied passes through.
        USER_LIMIT.store(budget.total, std::sync::atomic::Ordering::Relaxed);
        if let Some(actual) = Self::limit_clamp(requested) {
            let mib = |b: u64| b as f64 / (1u64 << 20) as f64;
            // Both clamps get their own sentence. "Below the floor" is
            // wrong for the 32-bit ceiling, and a message that names the
            // wrong end sends the reader to raise a number that is
            // already too big.
            let why = if requested < Self::MIN {
                format!(
                    "that is under the {} byte ({:.0} MiB) floor, so anything smaller changes nothing",
                    Self::MIN,
                    mib(Self::MIN),
                )
            } else {
                "that is more than a 32-bit process can address".to_string()
            };
            tracing::warn!(
                target: "mem",
                "{source} asked for {requested} bytes ({:.1} MiB) - {why}. Running with {actual} bytes ({:.1} MiB).",
                mib(requested),
                mib(actual),
            );
        }
        budget
    }

    /// The largest total this target can hold, whatever is asked for:
    /// [`Self::ADDRESS_SPACE_CEIL`] on 32-bit, `u64::MAX` on 64-bit
    /// (where [`Self::with_total`] clamps nothing at the top).
    ///
    /// EXPOSED BECAUSE THE CEILING IS OTHERWISE INVISIBLE TO ANYTHING
    /// THAT DOES NOT RUN ON 32-BIT, and that invisibility cost ten days
    /// of red nightly. `armv7-cross` failed every night from 28 Aug
    /// 2026 on one assertion - a test picking `with_total(4 GiB)` and
    /// asserting its `holds_cap` clears a 1 GB threshold, which is true
    /// on every box this fleet owns and false by ARITHMETIC on armv7:
    /// the clamp here makes the budget 1 GiB, so 45% of it is
    /// 483,183,810 bytes and the threshold is unreachable. The product
    /// was right and the test could not have known, because the number
    /// it needed was a private const behind a `cfg` nobody compiles.
    /// A caller that has to hold to a budget TIER on every target asks
    /// this, and gets an answer on the target it is compiled for.
    ///
    /// Not a statement about physical RAM, and never a floor: it is the
    /// ceiling the clamp applies, so the real budget is at or under it.
    pub const fn max_total() -> u64 {
        #[cfg(target_pointer_width = "32")]
        {
            Self::ADDRESS_SPACE_CEIL
        }
        #[cfg(not(target_pointer_width = "32"))]
        {
            u64::MAX
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
    /// pool AND every concurrent pipeline that shares this budget (B3).
    ///
    /// The second half of that was a claim rather than a behaviour
    /// until 2 Sep 2026 (TODO 313 item 1): the counter it is compared
    /// against lived on one pool's `Shared`, so the two pipelines that
    /// exist at every queue boundary - the hand-over successor dialling
    /// while its predecessor drains, and the prefetch sidecar beside
    /// the active job - each admitted a full cap's worth and the wire
    /// held twice this. It is now one shared ledger
    /// (`pool::WireCharge`), handed to every fleet the daemon builds;
    /// a caller that hands a pool no ledger gets a private one, which
    /// for a lone pipeline is the same number.
    ///
    /// Pipelined BODY responses are budget-EXEMPT bytes:
    /// window × connections × ~800 KB pooled bodies - 48 connections at
    /// window 3 is 115 MB+ before the first article even reaches the
    /// fetch→decode channel. Workers stop topping up their pipeline past
    /// one request per connection while the SHARED charged estimate
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
        let mut policy = rars::Rar50ExecutionPolicy::from_working_memory(
            (self.total / 4).clamp(96 << 20, 6 << 30),
        );
        policy.max_tape_workers = policy.max_workers.min(rar_worker_cap());
        policy
    }

    /// RAR 5 WRITING's memory allowance - the counterpart of
    /// [`Self::rar_execution_policy`], and a quarter of the budget for the
    /// same reason: posting encodes while the rest of the pipeline is live,
    /// so the writer shares rather than assuming it has the host to itself.
    ///
    /// It exists because nothing admitted the writer's memory at all. The
    /// encoder's own defaults are host-sized - 128 MiB of block wave per
    /// pool thread FLOORED AT A GIBIBYTE, a flat 512 MiB of parse hints,
    /// and a match-finder tree of ten bytes per dictionary byte - so a
    /// 32-bit target, whose whole [`Self::max_total`] is 1 GiB, was
    /// outspent by the floor alone before a byte of payload arrived
    /// (measured 8 Sep 2026: 1.4 to 2.1 GiB of live heap beyond the
    /// caller's input, at every dictionary from 128 KiB to 32 MiB).
    ///
    /// The floor is deliberately low rather than absent: the encoder
    /// narrows to a single block in flight rather than failing, so a small
    /// allowance costs wall time and no bytes. The ceiling is where the
    /// stock defaults already sat, so a large budget changes nothing.
    pub fn rar_write_policy(&self) -> rars::Rar50WritePolicy {
        rars::Rar50WritePolicy::from_working_memory((self.total / 4).clamp(64 << 20, 4 << 30))
    }
}

/// How many RAR 5 tape workers this host should run: two fewer than its
/// PHYSICAL cores (the apply and scan threads want one each), between 2
/// and rars' own ceiling of 8. Physical, not logical: on an i5-10600KF
/// (6 cores, 12 threads) eight workers plus apply, scan, writer and
/// digester oversubscribed the six cores and read 6% slower than four
/// (2.20-2.33 s vs 2.08-2.11 on a 1 GiB -m3 member), while the 20-core
/// M1 Ultra was fastest at eight
/// (research/RAR-PERF-AUDIT-2026-09-02.md, round 5). `cpu_workers()`
/// still bounds it, so a phone's launcher-supplied count is honoured.
pub fn rar_worker_cap() -> usize {
    let logical = cpu_workers();
    let physical = physical_cores().unwrap_or(logical).min(logical);
    physical.saturating_sub(2).clamp(2, 8)
}

/// Physical core count where the host can tell us: Windows through the
/// kernel's processor-core records (the PAR2 fold already reads them),
/// Linux from `/proc/cpuinfo` (distinct physical id + core id pairs).
/// `None` elsewhere - Apple silicon has no SMT, so the logical count IS
/// the physical one there.
#[cfg(all(target_arch = "x86_64", windows))]
fn physical_cores() -> Option<usize> {
    crate::par2repair::linalg::physical_cores()
}

#[cfg(not(any(all(target_arch = "x86_64", windows), target_os = "linux")))]
fn physical_cores() -> Option<usize> {
    None
}

#[cfg(target_os = "linux")]
fn physical_cores() -> Option<usize> {
    {
        let info = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        let mut cores = std::collections::BTreeSet::new();
        let (mut phys, mut core) = (None, None);
        for line in info.lines() {
            let mut kv = line.splitn(2, ':');
            let key = kv.next().unwrap_or("").trim();
            let val = kv.next().unwrap_or("").trim();
            match key {
                "physical id" => phys = val.parse::<u32>().ok(),
                "core id" => core = val.parse::<u32>().ok(),
                "" => {
                    if let (Some(p), Some(c)) = (phys, core) {
                        cores.insert((p, c));
                    }
                    phys = None;
                    core = None;
                }
                _ => {}
            }
        }
        if let (Some(p), Some(c)) = (phys, core) {
            cores.insert((p, c));
        }
        (!cores.is_empty()).then_some(cores.len())
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
///
/// And it defers a STORED split member's per-fragment PACKED digests. For a
/// stored member those bytes are the member's own bytes, so the fragment
/// records and the whole-member record digest every byte twice - once on
/// the thread doing the reading, in series with it. On a `-htb` set the
/// second pass is a whole BLAKE2sp: 13.96 G instructions per GiB against
/// 7.73, 1.55 s of user CPU against 0.80, on an M3 Ultra (audit round 25).
/// Damaged DATA still names its volume, because a failed member digest
/// re-reads the packed bytes to find it. What this gives up is a set whose
/// fragment digest RECORD is damaged while its payload is sound: that now
/// extracts, and it extracts a file the member's own digest proved correct.
/// A downloader that would send such a set to PAR2 repair on the strength
/// of a header byte, having already produced the right output, is doing
/// the user no favours - see [`rars::Rar50SplitFragmentDigests`].
/// Ceiling on the RAR 5 streaming decoder's WINDOW, derived from the
/// process budget.
///
/// `StreamingOutput::new` reserves the ring at the declared dictionary's
/// size up front whenever that dictionary is over 64 MiB and the
/// declared output covers it - deliberately, because a member that
/// reaches past a smaller initial cap would otherwise hold two rings
/// resident across the growth copy. The number it reserves is a HEADER
/// FIELD, though, and nothing here overrode the crate's own 1 GiB
/// default, so a parseable archive drove a multi-hundred-megabyte
/// allocation that `MemBudget` never saw - the same blind spot
/// `LZMA_DICT_OUTSTANDING` was added for on the zip method-14 window.
///
/// A quarter of the budget, like [`MemBudget::rar_execution_policy`] and
/// for the same reason (extraction runs while the rest of the pipeline
/// is live), and capped at the crate's own default so no host that could
/// already decode an archive stops being able to: only a host whose
/// whole budget is smaller than 4 GiB is held tighter than today, which
/// is exactly the host that cannot afford the reserve. Past it the
/// decode fails with an error that names this knob rather than aborting
/// the process on a failed allocation.
fn rar_window_limit() -> u64 {
    (process_budget().total / 4).clamp(64 << 20, 1 << 30)
}

pub fn rar_read_options(password: Option<&[u8]>) -> rars::ArchiveReadOptions<'_> {
    rars::ArchiveReadOptions::with_optional_password(password)
        .with_rar50_execution_policy(process_budget().rar_execution_policy())
        .with_rar50_max_window(rar_window_limit())
        .with_rar50_split_hash_seeding(rars::Rar50SplitHashSeeding::FirstFragment)
        .with_rar50_split_fragment_digests(rars::Rar50SplitFragmentDigests::DeferForStoredMembers)
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

/// The last total [`MemBudget::from_user_limit`] produced; 0 until a
/// person has supplied one.
static USER_LIMIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The published budget when it is a figure a PERSON chose, `None` when
/// nothing is published or what is published is not theirs.
///
/// [`published_budget`] cannot answer that, because the entry points that
/// take a limit also publish [`MemBudget::auto`] when nobody gave one - the
/// nzbfast CLI, the daemon after its saved settings, the embedded host. A
/// consumer that may RAISE its own default to meet a published budget
/// must not raise it to meet auto's: auto floors at 256 MiB and takes
/// half of a cgroup limit, where the repair's solve window and transform
/// budget are a quarter with no floor, so taking auto as a choice would
/// move the automatic default on every small box and container
/// (`par2repair::fastpar::clamp_to_published`, 15 Sep 2026).
///
/// Answered by VALUE against [`USER_LIMIT`], because that is where the
/// provenance survives: the daemon resolves its budget into `ServeOpts`
/// (from `--mem-limit` or the `mem_limit` setting) and republishes the
/// bare `MemBudget` later, so a flag set at the publish call would be lost
/// on the way. A republish of the same figure keeps the answer; a setting
/// of 0 that republishes auto over a CLI limit does not, unless auto
/// happens to be the same number - which is then a figure the person
/// typed, so reading it as theirs is the stated limit and not a defect.
pub fn published_user_limit() -> Option<MemBudget> {
    let total = PROCESS_BUDGET.load(std::sync::atomic::Ordering::Relaxed);
    (total != 0 && total == USER_LIMIT.load(std::sync::atomic::Ordering::Relaxed))
        .then_some(MemBudget { total })
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

    /// The same ceiling asked PORTABLY, which is the half the test above
    /// cannot give you: that one is `#[cfg(target_pointer_width =
    /// "32")]`, so on every box this fleet owns it compiles to nothing
    /// and the clamp is invisible.
    ///
    /// THAT INVISIBILITY IS NOT THEORETICAL. `armv7-cross` was red in
    /// nightly every night from 28 Aug 2026 on ONE assertion, in
    /// `nzbfast`'s `serve::requeue::pause_cost_tests`: a test that built
    /// `with_total(4 GiB)` and asserted the resulting `holds_cap` clears
    /// a 1 GB product threshold. True on every 64-bit target, and false
    /// on armv7 by ARITHMETIC rather than by accident - the clamp makes
    /// that budget 1 GiB, so 45% of it is 483,183,810 bytes, under half
    /// the threshold. The product was right; the test could not have
    /// known, because the number it needed was a private const behind a
    /// `cfg` nobody here compiles. Nothing reported the red for ten
    /// days, and nobody could have seen it without qemu.
    ///
    /// So this asserts what a caller may rely on ON WHATEVER TARGET IT
    /// IS COMPILED FOR: no budget ever exceeds [`MemBudget::max_total`],
    /// and no tier ever exceeds its own budget. The 64-bit arm is worth
    /// having in its own right - it drives the widest budget expressible,
    /// which is where `holds_cap`'s `try_from` belt would show if it ever
    /// went back to wrapping.
    #[test]
    fn no_budget_exceeds_what_this_target_can_address() {
        for asked in [MemBudget::MIN, 4u64 << 30, 64u64 << 30, u64::MAX] {
            let b = MemBudget::with_total(asked);
            assert!(
                b.total <= MemBudget::max_total(),
                "with_total({asked}) kept {} over this target's {} ceiling",
                b.total,
                MemBudget::max_total()
            );
            assert!(b.total <= asked.max(MemBudget::MIN));
            // Saturating, never wrapping: a tier wider than the budget
            // it came out of is the defect the `try_from` belt is for.
            assert!(b.holds_cap() as u64 <= b.total);
            assert!(b.partials_cap() as u64 <= b.total);
        }
        // The exact figure the nightly failure printed, DERIVED from the
        // ceiling rather than quoted, so moving the ceiling moves this
        // with it instead of leaving a frozen number behind.
        #[cfg(target_pointer_width = "32")]
        assert_eq!(
            MemBudget::with_total(4 << 30).holds_cap() as u64,
            MemBudget::max_total() / 100 * 45,
            "the 4 GiB budget the requeue screen test asks for IS the \
             ceiling here, so its holds cap is 45% of the ceiling"
        );
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

    /// A create's fold-width ceiling binds the thread that published it and
    /// no other - two creates in one process each pace their own fold
    /// (15 Sep 2026) - and `paced_folds` counts it for as long as it is
    /// held. Every assertion is one another test running a create at the
    /// same moment cannot disturb: the peer thread is fresh, and the
    /// counters only ever include this cap on top of whatever else is live.
    // test-global-gate: asserts only lower bounds on PACED_FOLDS and PACED_WIDTH_SUM, which any other live cap can only raise, and reads the cap itself thread-locally
    #[test]
    fn a_fold_width_cap_binds_only_the_thread_that_published_it() {
        let cap = FoldWidthCap::publish(1);
        assert_eq!(
            fold_workers(),
            1,
            "the publishing thread's fold is narrowed"
        );
        let (peer, peer_cores) = std::thread::spawn(|| (fold_workers(), cpu_workers().max(1)))
            .join()
            .expect("peer thread");
        assert_eq!(
            peer, peer_cores,
            "a cap on one thread narrowed another's fold"
        );
        let live = paced_folds();
        assert!(live.creates >= 1 && live.fold_workers >= 1, "{live:?}");
        drop(cap);
        assert_eq!(fold_workers(), cpu_workers().max(1), "Drop clears the cap");
    }

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

    /// The three `--mem-limit` spellings that mean nothing distinct,
    /// pinned as ARITHMETIC so the fixture family cannot drift back into
    /// believing they do.
    ///
    /// `sizes::parse_size` is DECIMAL, so `8M`/`32M`/`64M` are the three
    /// literals below and every one of them is under the floor - `64M`
    /// included, which is the half that surprises: it is 64 million, not
    /// 64 MiB. Twelve fixtures under `crates/nzbfast/tests/` pick one of
    /// the three and therefore share one configuration (cap 28.8 MiB,
    /// park mark 21.6 MiB), which is how `e2e_chaserepair`'s paged leg
    /// came to sit on the park mark and flake for two days.
    #[test]
    fn a_user_limit_reports_the_clamp_it_used_to_make_in_silence() {
        // The three decimal spellings, and what each one really becomes.
        for &decimal in &[8_000_000u64, 32_000_000, 64_000_000] {
            assert_eq!(
                MemBudget::limit_clamp(decimal),
                Some(MemBudget::MIN),
                "{decimal} is below the floor, so the clamp must be REPORTED"
            );
            assert_eq!(
                MemBudget::from_user_limit(decimal, "test").total,
                MemBudget::MIN
            );
        }
        // 64 MiB exactly is the first figure taken as asked - the
        // boundary, so a floor that moves has to move this line with it.
        assert_eq!(MemBudget::limit_clamp(MemBudget::MIN), None);
        assert_eq!(
            MemBudget::limit_clamp(MemBudget::MIN - 1),
            Some(MemBudget::MIN)
        );
        // An ordinary figure is silent: a warning on every run is a
        // warning nobody reads, which is the failure this is fixing.
        assert_eq!(MemBudget::limit_clamp(110_000_000), None);
        // 2 GB is ordinary on a 64-bit box and OVER THE CEILING on a
        // 32-bit one, whose whole budget stops at 1 GiB - so ask the
        // target what it can hold rather than asserting a figure that
        // is arithmetically impossible there. This line was a flat
        // `None` and was RED in nightly's `armv7-cross` on 31 Aug 2026
        // (run 33376949508). It is `5dd24e2fc`'s defect and NOT a lane
        // repeating it: this test landed at 31 Aug 02:44Z (`9134950de`)
        // and that fix at 04:28Z, so the two were written in parallel
        // and the fix had no log naming this one to read.
        let two_gb = 2_000_000_000u64;
        assert_eq!(
            MemBudget::limit_clamp(two_gb),
            (two_gb > MemBudget::max_total()).then_some(MemBudget::max_total()),
            "2 GB is silent where it fits and REPORTED where it does not"
        );
        // The 32-bit address-space ceiling is the OTHER silent clamp,
        // and it is the same question, so it is answered here too - its
        // own comment already calls the silence a defect.
        #[cfg(target_pointer_width = "32")]
        assert_eq!(
            MemBudget::limit_clamp(10 << 30),
            Some(MemBudget::ADDRESS_SPACE_CEIL)
        );
        #[cfg(not(target_pointer_width = "32"))]
        assert_eq!(MemBudget::limit_clamp(10 << 30), None);
        // Whatever it reports, the budget it hands back is the one
        // `with_total` would have: this reports, it does not decide.
        for &v in &[1u64, 8_000_000, 110_000_000, 10 << 30] {
            assert_eq!(
                MemBudget::from_user_limit(v, "test").total,
                MemBudget::with_total(v).total
            );
        }
        // The rule itself, stated in terms of this target's own floor
        // and ceiling rather than in bytes, so no line above can drift
        // back into asserting a figure one target cannot reach. Both
        // clamps are named here and neither is `cfg`-ed away: on a
        // 64-bit box the ceiling arm is unreachable (`max_total()` is
        // `u64::MAX`, so nothing is over it) and this reduces to the
        // floor, which is worth having in its own right; on armv7 all
        // three arms bite.
        for &r in &[
            1u64,
            MemBudget::MIN - 1,
            MemBudget::MIN,
            110_000_000,
            2_000_000_000,
            10 << 30,
            u64::MAX,
        ] {
            let want = if r < MemBudget::MIN {
                Some(MemBudget::MIN)
            } else if r > MemBudget::max_total() {
                Some(MemBudget::max_total())
            } else {
                None
            };
            assert_eq!(MemBudget::limit_clamp(r), want, "limit_clamp({r})");
        }
    }

    #[test]
    fn cgroup_available_discounts_only_the_unreclaimable_charge() {
        let gb = 1u64 << 30;
        // A cgroup that has read its member: nearly all of `current` is page
        // cache, which is reclaimable to make room for a mapping. Taking
        // `limit - current` here would answer 64 MiB and refuse a payload
        // that fits.
        assert_eq!(
            cgroup_available_from(4 * gb, 4 * gb - (64 << 20), 3 * gb),
            3 * gb + (64 << 20)
        );
        // A fresh create's own charge is anonymous and does bind.
        assert_eq!(cgroup_available_from(gb, 200 << 20, 0), gb - (200 << 20));
        // The measured knee, asked as the gate asks it: a 2 GiB payload
        // against the limits this round walked, with a create's ~50 MiB of
        // anon charge and nothing cached yet. Refuse at 1 and 2 GiB (147 s
        // and 36 s measured), admit at 3 (4.3 s).
        let payload = 2 * gb;
        let anon = 50 << 20;
        for (limit, want) in [(gb, false), (2 * gb, false), (3 * gb, true)] {
            let avail = cgroup_available_from(limit, anon, 0);
            assert_eq!(payload <= avail, want, "limit {limit}");
        }
        // Saturating, never wrapping: a cgroup over its own limit (v1 can
        // report usage above the limit briefly) answers zero, not u64::MAX.
        assert_eq!(cgroup_available_from(gb, 2 * gb, 0), 0);
    }

    #[test]
    fn tightest_available_takes_whichever_is_present() {
        let gb = 1u64 << 30;
        // The whole point: a 31 GB host reading and a 1 GiB cgroup reading.
        assert_eq!(tightest_available(Some(31 * gb), Some(gb)), Some(gb));
        assert_eq!(tightest_available(Some(gb), Some(31 * gb)), Some(gb));
        // Uncontained Linux, and a platform with no host figure at all.
        assert_eq!(tightest_available(Some(8 * gb), None), Some(8 * gb));
        assert_eq!(tightest_available(None, Some(8 * gb)), Some(8 * gb));
        // Neither: the caller keeps its old route, which is what the gate's
        // `is_none_or` turns into "map it".
        assert_eq!(tightest_available(None, None), None);
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
        // Current RSS is live, and the peak it is compared against is
        // NOT sampled at the same instant, so this races its window and
        // has to retry it rather than fail on one lagging read.
        //
        // On Linux `current_rss` reads /proc/self/statm, which the kernel
        // updates on every page fault, while `peak_rss` reads getrusage's
        // ru_maxrss - that is mm->hiwater_rss, which the kernel refreshes
        // only at the points that call update_hiwater_rss(), NOT on every
        // fault. So while RSS is climbing fast, a live current above the
        // last-recorded peak is an honest kernel reading and not a bug in
        // either reader. It cost main a red on 4 Sep 2026
        // (unit-one-process, run 33829011436, both attempts), where 1,287
        // tests allocating in one parallel libtest process is exactly the
        // fast climb this needs; nextest structurally cannot see it,
        // because there every test gets its own quiet process.
        //
        // The invariant is still load-bearing - the peak is monotone, so
        // it MUST catch up - and this asserts that it does. What it will
        // not do is fail on a single sample taken mid-climb.
        let cur = current_rss().unwrap_or(0);
        assert!(cur > 1 << 20);
        let mut caught_up = false;
        for _ in 0..50 {
            let cur = current_rss().unwrap_or(0);
            if cur <= peak_rss().unwrap_or(u64::MAX) {
                caught_up = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            caught_up,
            "peak RSS never caught up with current over 1s: current {:?}, peak {:?}",
            current_rss(),
            peak_rss()
        );
        // CPU clock is readable and monotone.
        let a = cpu_time_secs().unwrap();
        let b = cpu_time_secs().unwrap();
        assert!(a >= 0.0 && b >= a);
    }

    /// The write policy's whole reason for existing is that a 32-bit
    /// poster's budget is smaller than the writer's OWN default floor, so
    /// this pins the relationship the target actually needs rather than the
    /// arithmetic: whatever `max_total` is here, the allowance fits inside
    /// it and the tree it admits fits inside the allowance.
    #[test]
    fn rar_write_policy_fits_inside_the_budget_it_came_from() {
        for total in [
            MemBudget::MIN,
            256 << 20,
            1 << 30,
            8u64 << 30,
            MemBudget::max_total(),
        ] {
            let budget = MemBudget::with_total(total);
            let policy = budget.rar_write_policy();
            // The allowance never exceeds the budget it was cut from. The
            // stock encoder defaults - a 1 GiB wave floor plus 512 MiB of
            // hints - fail this at every 32-bit budget, which is the defect.
            assert!(
                policy.working_memory_limit <= budget.total.max(64 << 20),
                "{total}: allowance {} over budget {}",
                policy.working_memory_limit,
                budget.total,
            );
            // Ten bytes of tree per dictionary byte, inside the quarter of
            // the allowance set aside for it - unless the format floor is
            // wider than the allowance can pay for, which is a caller error
            // to report and not a dictionary to invent.
            let tree = policy.max_dictionary.saturating_mul(10);
            assert!(
                tree <= policy.working_memory_limit / 4
                    || policy.max_dictionary == rars::Rar50WritePolicy::MIN_DICTIONARY,
                "{total}: tree {tree} over its share of {}",
                policy.working_memory_limit,
            );
        }

        // Monotone: more budget never admits a narrower dictionary.
        let mut previous = MemBudget::with_total(MemBudget::MIN).rar_write_policy();
        for shift in 27..36 {
            let policy = MemBudget::with_total(1u64 << shift).rar_write_policy();
            assert!(
                policy.max_dictionary >= previous.max_dictionary,
                "1 << {shift}: {policy:?} under {previous:?}",
            );
            previous = policy;
        }
    }

    /// The RAR 5 streaming decoder reserves its ring at the DECLARED
    /// dictionary's size up front, and that number is a header field -
    /// so the ceiling on it has to come from the process budget rather
    /// than from the vendored crate's 1 GiB default, which nothing here
    /// overrode.
    ///
    /// NEGATIVE CONTROL, run: drop the `.with_rar50_max_window` line and
    /// `rar_read_options` leaves `rar50_max_window` as `None`, failing
    /// the first assertion.
    #[test]
    fn the_rar_window_ceiling_follows_the_budget_and_never_exceeds_the_default() {
        const CRATE_DEFAULT: u64 = 1 << 30;
        assert!(
            rar_read_options(None).rar50_max_window.is_some(),
            "the window must be budgeted, not left to the crate default"
        );
        // A host with room keeps exactly the behaviour it had: the cap is
        // the crate's own default, so nothing that could decode before
        // stops being able to. A 32-bit host has no such room by
        // construction - `with_total` clamps every input to the 1 GiB
        // `ADDRESS_SPACE_CEIL` there, so a quarter of the budget is
        // 256 MiB and the crate default is correctly NOT reached. The
        // `at(1 << 30)` pair below is what pins that side, and it holds
        // on every target.
        #[cfg(not(target_pointer_width = "32"))]
        assert_eq!(
            (MemBudget::with_total(64 << 30).total / 4).clamp(64 << 20, CRATE_DEFAULT),
            CRATE_DEFAULT
        );
        // A host that cannot afford the reserve is held tighter, and the
        // rule is monotone in the budget.
        let at =
            |total: u64| (MemBudget::with_total(total).total / 4).clamp(64 << 20, CRATE_DEFAULT);
        assert!(at(1 << 30) < CRATE_DEFAULT, "a 1 GiB host must be held");
        assert!(at(1 << 30) >= (64 << 20), "never below the floor");
        let mut previous = 0u64;
        for shift in 28..37 {
            let now = at(1u64 << shift);
            assert!(now >= previous, "1 << {shift}: {now} under {previous}");
            previous = now;
        }
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
            assert_eq!(large.max_tape_workers, rar_worker_cap().min(8), "{large:?}");
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

    // test-global-gate: touches no FoldWidthCap - its `drop(bufs)` is std's drop of a Vec, which the resolver matches by name to FoldWidthCap's Drop::drop in this unit
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
