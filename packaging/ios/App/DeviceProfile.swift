// What this phone is, expressed as the numbers the setup screen offers.
//
// IT HAS THE SAME THREE JOBS AS ITS ANDROID TWIN since TODO 281 IO2
// (packaging/android/.../DeviceProfile.kt): connections, the engine's
// memory budget and its CPU worker cap. The two arrive by different
// routes and that is the only real difference - the Android launcher
// starts the engine as a CHILD PROCESS and hands it `--mem-limit` on an
// argv, while this one is linked in, so the budget is the fifth
// argument of `nzbfast_start` and the worker cap is an environment
// variable read before the engine thread exists.
import Foundation
import Network
import os

enum DeviceProfile {

    // ---- memory ----

    /// The memory budget to hand `nzbfast_start`, in bytes.
    ///
    /// Total RAM / 16, clamped to 192 MB .. 512 MB - the SAME rule as
    /// `DeviceProfile.memLimitArg` on Android, deliberately, because the
    /// argument for the divisor is about phones and not about either OS.
    /// It is worth restating rather than citing, since the next person to
    /// touch one of the two will be looking at that one:
    ///
    ///   - The budget is not the process. `MemBudget` slices 45% to the
    ///     extractor's held spans and 30% to the verifier's partial
    ///     blocks, and neither tier counts decode scratch, repair
    ///     matrices or socket buffers, so a 512 MB budget is a process
    ///     comfortably past that.
    ///   - Every tier has a spill path, and both spills are CORRECT: past
    ///     the holds cap the extractor materialises volumes to disk, past
    ///     the partials cap the verifier spills. So a budget that is too
    ///     small costs wall-clock, and one that is too large costs the
    ///     whole job to the process being killed. On a phone those two
    ///     are not comparable, which is the whole reason the divisor is
    ///     16 and not the engine's own 4.
    ///
    /// WHAT iOS ADDS OVER ANDROID is that the kill is louder and the
    /// limit is lower. Jetsam judges `phys_footprint` against a per-device
    /// ceiling, and a foreground app that crosses it is killed outright
    /// with no low-memory callback that arrives in time to matter. The
    /// measured figures behind the clamp are in TODO 281 IO2.
    ///
    /// IN THE SIMULATOR `physicalMemory` IS THE MAC'S, which is exactly
    /// why the ceiling is not optional: a 512 GB dev box divides to 32 GB
    /// and the clamp brings it back to 512 MB, so a Simulator run
    /// measures the same budget a large phone would get rather than a
    /// desktop one. Without the clamp every Simulator measurement in this
    /// box would have been meaningless.
    static func memLimitBytes() -> UInt64 {
        let ram = ProcessInfo.processInfo.physicalMemory
        // A platform that will not say gets 4 GB, the modest end of what
        // runs this deployment target, so an unknown device is sized
        // conservatively rather than optimistically. Matches the Android
        // twin's FALLBACK_RAM for the same reason.
        let total = ram > 0 ? ram : 4_000_000_000
        return min(max(total / 16, 192_000_000), 512_000_000)
    }

    /// Bytes this process may still grow by before jetsam kills it, or
    /// nil where the platform will not say.
    ///
    /// `os_proc_available_memory` is the only API that answers the
    /// question that actually matters - not "how much RAM does this
    /// device have" but "how much of MY limit is left" - and it is the
    /// number the IO2 measurement is read against.
    ///
    /// IT ANSWERS 0 IN THE SIMULATOR, which is not a bug and is reported
    /// as nil rather than as "no headroom": the Simulator is a macOS
    /// process with no jetsam limit at all, so there is no ceiling for it
    /// to subtract from. A caller must therefore treat nil as "unknown"
    /// and never as "critical" - reading it the other way would put a
    /// permanent low-memory warning on every Simulator run and train
    /// whoever sees it to ignore the real one.
    static func availableMemoryBytes() -> UInt64? {
        let n = os_proc_available_memory()
        return n > 0 ? UInt64(n) : nil
    }

    /// This process's `phys_footprint` - the number jetsam judges, and
    /// NOT `resident_size`.
    ///
    /// The distinction is the whole point of having this rather than
    /// reading RSS: `phys_footprint` excludes pages the allocator has
    /// already offered back, and includes compressed and IOKit charges
    /// that resident size does not. An engine measured on RSS can look
    /// fine and still be killed, and can look bloated after a trim that
    /// really did give the memory back.
    static func footprintBytes() -> UInt64? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size
                                           / MemoryLayout<integer_t>.size)
        let rc = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard rc == KERN_SUCCESS, info.phys_footprint > 0 else { return nil }
        return UInt64(info.phys_footprint)
    }

    // ---- CPU ----

    /// How many CPU-bound workers the engine may run at once, for
    /// `NZBFAST_CPU_WORKERS`.
    ///
    /// The count of logical CPUs in the FASTEST performance level, floored
    /// at 2. On an Apple SoC that is the performance cluster, and leaving
    /// the efficiency cores out is the same deliberate trade the Android
    /// twin documents: every pool this caps is work-stealing, so a slow
    /// core is not a straggler holding the pool open - it is throughput,
    /// and dropping it really does cost some. What it buys is the thing a
    /// phone runs out of first. Threads past the performance cluster are
    /// paid for twice, once in power and again in the frequency the
    /// thermal throttle then takes off every other thread.
    ///
    /// `hw.perflevel0.logicalcpu` is the Apple counterpart of Android's
    /// `cpuinfo_max_freq` walk and is a far better one: the kernel already
    /// groups the cores by performance level, level 0 being the fastest,
    /// so there is nothing to infer from frequencies. A machine with one
    /// level (or a kernel that will not answer) falls back to half the
    /// cores, which is the same shape of guess the Android side makes when
    /// sysfs is silent.
    ///
    /// IN THE SIMULATOR THIS IS THE MAC'S PERFORMANCE CLUSTER and will be
    /// far larger than any phone's. That is worth knowing before reading a
    /// Simulator memory measurement: more workers means more decode and
    /// repair scratch live at once, so the Simulator's footprint is an
    /// UPPER bound on the phone's rather than a matching figure - which is
    /// the safe direction for a jetsam argument, but not a like-for-like
    /// one.
    static func cpuWorkers() -> Int {
        let all = max(1, ProcessInfo.processInfo.activeProcessorCount)
        if let fast = sysctlInt("hw.perflevel0.logicalcpu"), fast > 0 {
            return min(max(fast, 2), all)
        }
        return min(max(all / 2, 2), all)
    }

    private static func sysctlInt(_ name: String) -> Int? {
        var value: Int32 = 0
        var size = MemoryLayout<Int32>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
        return Int(value)
    }

    // ---- line rate ----

    /// Connections to open on the one news server a phone has.
    ///
    /// iOS publishes NO bandwidth estimate. Android's rule divides
    /// `linkDownstreamBandwidthKbps` by 25 Mbit; `NWPath` has no
    /// counterpart at all, and inventing one by measuring would mean
    /// downloading before the user has a server configured. So the
    /// answer here is the interface type, which is the honest amount
    /// this platform will say: wifi or wired gets the middle of
    /// Android's measured 4..12 band, cellular gets its floor.
    ///
    /// It is a DEFAULT and not a lock. The field on the setup screen is
    /// editable, because a provider's account limit is a fact about the
    /// account that no amount of measuring this end can discover.
    static func suggestedConnections(_ status: LinkStatus) -> Int {
        switch status {
        case .cellular: return 4
        case .wifi, .wired: return 8
        case .unknown: return 4
        }
    }

    static func lineNote(_ status: LinkStatus) -> String {
        switch status {
        case .cellular: return "On cellular, so this starts low."
        case .wifi: return "On wifi."
        case .wired: return "On a wired connection."
        case .unknown: return "No network seen yet."
        }
    }

    enum LinkStatus: Hashable { case wifi, wired, cellular, unknown }

    /// Free space where downloads actually land.
    ///
    /// Measured on the DOWNLOAD directory itself and not on the volume
    /// root: the only filesystem that can refuse the write is the one
    /// the bytes are going to. `volumeAvailableCapacityForImportantUsage`
    /// rather than the plain figure, because iOS holds back a purgeable
    /// reserve and the plain reading under-reports what an app can
    /// actually have.
    static func freeBytes(at url: URL) -> Int64 {
        let keys: Set<URLResourceKey> = [.volumeAvailableCapacityForImportantUsageKey,
                                         .volumeAvailableCapacityKey]
        guard let v = try? url.resourceValues(forKeys: keys) else { return 0 }
        if let important = v.volumeAvailableCapacityForImportantUsage, important > 0 {
            return important
        }
        return Int64(v.volumeAvailableCapacity ?? 0)
    }

    /// "1.4 GB" / "812 MB" - one place, so every surface reads alike.
    static func humanBytes(_ b: Int64) -> String {
        if b >= 1_000_000_000 { return String(format: "%.1f GB", Double(b) / 1e9) }
        if b >= 1_000_000 { return String(format: "%.0f MB", Double(b) / 1e6) }
        if b >= 1_000 { return String(format: "%.0f kB", Double(b) / 1e3) }
        return "\(b) bytes"
    }
}

/// The current network's shape, watched rather than asked for.
///
/// `NWPathMonitor` is a callback, not a poll: a phone that walks out of
/// wifi range has to be noticed at the moment it happens, because that
/// is exactly when a cellular hold is worth applying.
@MainActor
final class LinkWatcher: ObservableObject {
    @Published private(set) var status: DeviceProfile.LinkStatus = .unknown

    private let monitor = NWPathMonitor()

    init() {
        monitor.pathUpdateHandler = { [weak self] path in
            let s: DeviceProfile.LinkStatus
            if path.status != .satisfied {
                s = .unknown
            } else if path.usesInterfaceType(.wifi) {
                s = .wifi
            } else if path.usesInterfaceType(.wiredEthernet) {
                s = .wired
            } else if path.usesInterfaceType(.cellular) {
                s = .cellular
            } else {
                s = .unknown
            }
            Task { @MainActor [weak self] in self?.status = s }
        }
        monitor.start(queue: DispatchQueue(label: "nzbfast.link"))
    }

    deinit { monitor.cancel() }
}
