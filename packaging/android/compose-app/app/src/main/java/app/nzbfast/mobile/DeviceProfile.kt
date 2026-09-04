package app.nzbfast.mobile

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.StatFs
import java.io.File

/**
 * TODO 281 AN4: what a phone is, expressed as the numbers the engine
 * sizes itself from.
 *
 * The engine's own defaults are DESKTOP defaults and several of them are
 * right there and wrong here. `MemBudget::auto` takes a quarter of
 * physical RAM (nzbkit-base/src/mem.rs), which on a 12 GB phone is a 3 GB
 * budget for a process the platform is willing to kill for being large.
 * `available_parallelism` counts every core, and on a big.LITTLE phone
 * half of them are small and all of them share one thermal envelope. And
 * a news server's connection count is a number a desktop user typed once
 * for a line that does not move, where a phone changes line every time it
 * leaves the house.
 *
 * Nothing here guesses at something the platform can be asked for.
 */
object DeviceProfile {

    // ---- memory ----

    /**
     * The `--mem-limit` this phone should hand the engine, in the decimal
     * suffix form the flag parses (`serve::parse_size`: M = 1e6).
     *
     * Total RAM / 16, clamped to 192 MB .. 512 MB. Two reasons for the
     * divisor rather than the engine's own quarter:
     *
     *   - The budget is not the process. `MemBudget` slices 45% to the
     *     extractor's held spans and 30% to the verifier's partial blocks,
     *     and neither tier counts decode scratch, repair matrices or the
     *     socket buffers, so a 512 MB budget is a process comfortably past
     *     that. On Android that is a size the low-memory killer starts
     *     taking an interest in, and a foreground service is not immune to
     *     it - it is just further down the list.
     *   - The tiers have a spill path each. Past the holds cap the
     *     extractor materialises volumes to disk, and past the partials
     *     cap the verifier spills; both are slower and both are CORRECT.
     *     So the cost of a budget that is too small is wall-clock, and the
     *     cost of one that is too large is the job being killed outright.
     *     On a phone those two are not comparable.
     *
     * The floor sits below `MemBudget::AUTO_FLOOR` (256 MB) on purpose:
     * the engine's own hard minimum is 64 MB, and a 3 GB phone dividing to
     * 192 MB is still well clear of it.
     */
    fun memLimitArg(ctx: Context): String {
        val budget = (totalRamBytes(ctx) / 16).coerceIn(192L * 1_000_000L, 512L * 1_000_000L)
        return "${budget / 1_000_000}M"
    }

    fun totalRamBytes(ctx: Context): Long {
        val am = ctx.getSystemService(ActivityManager::class.java) ?: return FALLBACK_RAM
        val info = ActivityManager.MemoryInfo()
        am.getMemoryInfo(info)
        // 4 GB if the platform will not say, which is the modest end of
        // what runs the minSdk here, so an unknown device is sized
        // conservatively rather than optimistically.
        return if (info.totalMem > 0) info.totalMem else FALLBACK_RAM
    }

    private const val FALLBACK_RAM = 4L * 1_000_000_000L

    // ---- CPU ----

    /**
     * How many CPU-bound workers the engine may run at once, passed as
     * `NZBFAST_CPU_WORKERS`.
     *
     * The count of cores in the FASTEST frequency tier, floored at 2. On a
     * big.LITTLE phone that is the big cluster, and leaving the little
     * cores out is a deliberate trade rather than an oversight:
     *
     *   - Every one of the pools this caps is work-stealing (a shared
     *     `fetch_add` cursor over spans or blocks), so a little core is
     *     not a straggler holding the pool open. It is throughput, and
     *     dropping it really does cost some.
     *   - What it buys is the thing a phone actually runs out of. Eight
     *     threads of MD5 or Reed-Solomon reach the thermal limit in
     *     seconds, and past that the SoC clocks the big cores down - so
     *     the last threads are paid for twice, once in power and again in
     *     the frequency every other thread loses.
     *
     * Reading `cpuinfo_max_freq` is how the topology is discovered because
     * Android exposes no other way: there is no "how many big cores" API,
     * and `availableProcessors` counts every core equally.
     */
    fun cpuWorkers(): Int {
        val all = Runtime.getRuntime().availableProcessors().coerceAtLeast(1)
        val freqs = coreMaxFreqs()
        if (freqs.isEmpty()) {
            // No sysfs answer. Half the cores, floored at 2: near enough
            // every SoC that runs the minSdk here is two clusters of
            // roughly equal size, so half is the right shape of guess even
            // when the split cannot be read.
            return (all / 2).coerceAtLeast(2).coerceAtMost(all)
        }
        val top = freqs.max()
        return freqs.count { it == top }.coerceAtLeast(2).coerceAtMost(all)
    }

    /**
     * Each CPU's `cpuinfo_max_freq` in kHz, for the cores that report one.
     *
     * A core the kernel has parked has no `cpufreq` directory, so it is
     * simply absent - which is right, since a parked core is not one to
     * size a thread pool from. An unreadable file is skipped rather than
     * defaulted, so a partial answer stays an answer about the cores it
     * did cover. The walk stops at the first cpuN directory that does not
     * exist at all, which is the end of the numbering.
     */
    private fun coreMaxFreqs(): List<Long> {
        val out = ArrayList<Long>()
        for (i in 0 until 64) {
            if (!File("/sys/devices/system/cpu/cpu$i").exists()) break
            val f = File("/sys/devices/system/cpu/cpu$i/cpufreq/cpuinfo_max_freq")
            if (!f.exists()) continue
            runCatching { f.readText().trim().toLong() }
                .getOrNull()
                ?.takeIf { it > 0 }
                ?.let { out.add(it) }
        }
        return out
    }

    // ---- line rate ----

    /**
     * Connections to open on the one news server a phone has, derived from
     * the platform's downstream estimate for the network in use.
     *
     * One socket per 25 Mbit, clamped 4 .. 12. The shape comes from TODO
     * 277's measured fleet curve rather than from taste: that rule sizes
     * the WHOLE fleet at 25 sockets on a slow line and 50 on a very fast
     * one, across five providers, so the per-provider share it describes
     * runs from 5 to 10 and this spans that with a rung either side. The
     * engine's own line cap still applies on top of whatever is saved
     * here; this decides only the ceiling the account is willing to open,
     * which is the number a phone can get wrong in the expensive direction
     * by copying a desktop's 60.
     *
     * `linkDownstreamBandwidthKbps` is an ESTIMATE and says so in its own
     * documentation: on Wi-Fi it is the negotiated link rate, generously
     * above the real path, and on cellular it is a carrier figure. That is
     * tolerable precisely because both ends are clamped - a wildly
     * optimistic gigabit reading buys 12 sockets and not 40, and no
     * reading at all falls to the floor.
     */
    fun connectionsForLine(ctx: Context): Int {
        val mbit = downstreamMbit(ctx)
        if (mbit <= 0) return CONN_FLOOR
        return (mbit / 25).coerceIn(CONN_FLOOR, CONN_CEIL)
    }

    const val CONN_FLOOR = 4
    const val CONN_CEIL = 12

    /** The platform's downstream estimate in Mbit/s, or 0 when it will not say. */
    fun downstreamMbit(ctx: Context): Int {
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return 0
        val net = cm.activeNetwork ?: return 0
        val caps: NetworkCapabilities = cm.getNetworkCapabilities(net) ?: return 0
        return caps.linkDownstreamBandwidthKbps / 1000
    }

    /** True when the active network is metered - see [Settings.pauseOnMetered]. */
    fun isMetered(ctx: Context): Boolean {
        val cm = ctx.getSystemService(ConnectivityManager::class.java) ?: return false
        val caps = cm.getNetworkCapabilities(cm.activeNetwork ?: return false) ?: return false
        return !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
    }

    // ---- disk ----

    /**
     * Free bytes where downloads actually land, which is app-private
     * storage and NOT the volume a desktop install's settings page would
     * name.
     *
     * `StatFs` on the download directory itself rather than on
     * `Environment.getDataDirectory()`: on a device with adoptable storage,
     * or with `/data` and the app-private mount on different filesystems,
     * those are different answers, and the only one that can refuse a
     * write is the one the bytes are going to.
     */
    fun freeBytes(downloads: File): Long = runCatching {
        val st = StatFs(downloads.absolutePath)
        st.availableBlocksLong * st.blockSizeLong
    }.getOrDefault(0L)

    /** Where [EngineService] points the engine's `--out`. */
    fun downloadDir(ctx: Context): File = File(ctx.filesDir, "downloads")

    /** "1.4 GB" / "812 MB" - one place, so every surface reads alike. */
    fun humanBytes(b: Long): String = when {
        b >= 1_000_000_000L -> "%.1f GB".format(b / 1e9)
        b >= 1_000_000L -> "%.0f MB".format(b / 1e6)
        b >= 1_000L -> "%.0f kB".format(b / 1e3)
        else -> "$b bytes"
    }
}
