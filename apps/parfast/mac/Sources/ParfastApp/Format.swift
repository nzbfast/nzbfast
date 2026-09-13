import Foundation

/// Every number the window shows goes through here.
///
/// Binary units with thousands separators, per plan 5.7 and the house unit
/// convention: a PAR2 world quotes block sizes and release sizes in powers of
/// two everywhere, and printing a 1 MiB block size as "1.05 MB" reads as
/// parfast getting the arithmetic wrong.
///
/// rate-format-gate: this is not a fourth copy of the nzbfast speed rule. That
/// rule formats a DOWNLOAD rate in SI units with a bits arm driven by the
/// daemon's `unit_bits` setting, and its three copies are pinned by name in
/// tools/rate-format-gate.py. parfast is a separate product with no daemon, no
/// bits setting and no network rate: what it shows is disk throughput, in the
/// same binary units as every other size in this window, and it deliberately
/// never prints the SI symbols that rule owns.
enum Fmt {

    static let decimal: NumberFormatter = {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f
    }()

    /// `12,345`
    /// A file count WITH its noun: "1 file", "3 files".
    ///
    /// The Windows app has had `Fmt.FileCount` since it was written and this
    /// app had no equivalent, so every caller passed a bare number into a copy
    /// key that spelled the noun itself - which reads "1 files" for one file.
    /// Added 12 Sep 2026 with the Windows screenshot pass, which found the
    /// mirror of it over there: the same key, filled by a helper that already
    /// carried the noun, rendering "3 files files".
    static func fileCount(_ n: Int) -> String {
        n == 1 ? S.commonOneFile : S.commonFilesCount(files: count(n))
    }

    static func count(_ n: Int) -> String {
        decimal.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    static func count(_ n: Int64) -> String {
        decimal.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    private static let binaryUnits = ["bytes", "KiB", "MiB", "GiB", "TiB", "PiB"]

    /// `4.31 GiB`, `812 KiB`, `4,096 bytes`.
    static func bytes(_ value: Int64) -> String {
        guard value >= 1024 else { return "\(count(value)) bytes" }
        var v = Double(value)
        var unit = 0
        while v >= 1024 && unit < binaryUnits.count - 1 {
            v /= 1024
            unit += 1
        }
        let decimals = v >= 100 ? 0 : (v >= 10 ? 1 : 2)
        return "\(number(v, decimals: decimals)) \(binaryUnits[unit])"
    }

    /// A block size, which is always exact and reads better whole: `1 MiB`,
    /// `512 KiB`, `1,048,576 bytes` when it is not a round power of two.
    static func blockSize(_ value: Int64) -> String {
        guard value > 0 else { return "0 bytes" }
        if value % (1024 * 1024) == 0 && value >= 1024 * 1024 {
            return "\(count(value / (1024 * 1024))) MiB"
        }
        if value % 1024 == 0 && value >= 1024 {
            return "\(count(value / 1024)) KiB"
        }
        return "\(count(value)) bytes"
    }

    /// Disk throughput, binary units. See the gate note above.
    static func rate(_ bytesPerSecond: Int64) -> String {
        guard bytesPerSecond > 0 else { return "-" }
        let mib = Double(bytesPerSecond) / (1024 * 1024)
        if mib >= 1024 { return "\(number(mib / 1024, decimals: 2)) GiB/s" }
        if mib >= 100 { return "\(number(mib, decimals: 0)) MiB/s" }
        return "\(number(mib, decimals: 1)) MiB/s"
    }

    static func number(_ v: Double, decimals: Int) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        f.minimumFractionDigits = decimals
        f.maximumFractionDigits = decimals
        return f.string(from: NSNumber(value: v)) ?? String(format: "%.\(decimals)f", v)
    }

    /// `43%` for a bar, `99.98%` where the fraction is the point.
    static func percent(_ value: Double, decimals: Int = 0) -> String {
        "\(number(value, decimals: decimals))%"
    }

    static func progressPercent(_ fraction: Double) -> String {
        percent(max(0, min(1, fraction)) * 100)
    }

    /// `12.4 s`, `3 min 05 s`, `1 h 12 min`.
    static func duration(ms: Int64) -> String {
        let seconds = Double(ms) / 1000
        if seconds < 1 { return "\(number(seconds, decimals: 1)) s" }
        if seconds < 60 { return "\(number(seconds, decimals: 1)) s" }
        let total = Int(seconds.rounded())
        if total < 3600 {
            return String(format: "%d min %02d s", total / 60, total % 60)
        }
        return String(format: "%d h %02d min", total / 3600, (total % 3600) / 60)
    }

    /// A file-system date in the sources table.
    static let modified: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    static func date(iso: String) -> String {
        let parser = ISO8601DateFormatter()
        parser.formatOptions = [.withInternetDateTime]
        guard let d = parser.date(from: iso) else { return iso }
        return modified.string(from: d)
    }
}
