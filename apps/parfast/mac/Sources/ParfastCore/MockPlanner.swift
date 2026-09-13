import Foundation

/// The create planner the mock answers `planPreview` with.
///
/// The REAL planner is `parfast-session`'s (`crates/parfast-session/src/planner.rs`),
/// and this one exists so the Create screen has live numbers before the engine is
/// linked in - the demo, the screenshot set and every preview on a build without the
/// staticlib are drawn from here. So it is deliberately the same arithmetic, and
/// "deliberately" now means MEASURED: every number below was compared against
/// `pf_plan_preview` over real files on 12 September 2026, and the differences the
/// comparison found are written up at the site that had them.
///
/// # What that comparison found here
///
/// This file was the half that had not been swept. `source_bytes` and `source_files`
/// were never passed to `PlanPreview` at all, so they were nil - and the create
/// screen's cost bar divides by `source_bytes`, which is how the Windows lane drew a
/// two gigabyte source protected at ten per cent as ONE HUNDRED PER CENT RECOVERY.
/// The block size was DIVIDED out of a block count rather than searched for, the
/// "none" scheme merged the index and the recovery into one file the engine writes as
/// two, the volume names used a fixed three-digit width where par2cmdline measures
/// two, every size was a placeholder rather than the packets the writer writes, and
/// `maxRecoveryFiles` read 32,768 where the CLI's cap is 31.
///
/// # The flags
///
/// `crates/parfast/src/cli.rs`'s own, compared switch for switch against
/// `planner::command_args`: a line the Copy command button pastes has to build the set
/// this pane just drew. The two long options - `--volume-blocks=N` and `--std-naming` -
/// are parfast's rather than the reference's, and both are real: `pf_capabilities`
/// `volume_limit_explicit` has been true since 12 September 2026, so an explicit volume
/// ceiling is carried rather than apologised for.
public enum MockPlanner {

    public struct Source: Hashable {
        public var name: String
        public var size: Int64
        public var path: String

        public init(name: String, size: Int64, path: String) {
            self.name = name
            self.size = size
            self.path = path
        }
    }

    /// PAR2's ceiling on source blocks (`par2gen::MAX_INPUT_SLICES`). The engine
    /// ENFORCES it by raising the block size; see `legalBlockSize`.
    public static let maxSourceBlocks = 32768

    /// The CLI's cap on recovery files (`parfast::help::MAX_RECOVERY_FILES`).
    /// THIRTY-ONE. This read 32,768 until 12 September 2026 - three orders out, which
    /// made the clamp unreachable and let the Create screen's uniform-files field offer
    /// a number the engine would quietly reduce.
    public static let maxRecoveryFiles = 31

    /// The engine's redundancy when a spec names none (`help::DEFAULT_REDUNDANCY_PCT`).
    public static let defaultRedundancyPct = 5

    /// A recovery slice on disk carries a packet header of this size.
    static let slicePacketOverhead: Int64 = 68

    /// The creator packet: a 64-byte header and `"nzbfast " + version`, padded to a
    /// multiple of four - 16 bytes for every version this project can plausibly reach.
    /// The one quantity here read off the engine rather than derived.
    static let creatorPacketBytes: Int64 = 64 + 16

    public static func plan(spec: CreateSpec, sources: [Source]) -> PlanPreview {
        let totalBytes = sources.reduce(Int64(0)) { $0 + $1.size }
        var warnings: [String] = []

        // --- block size and count ---------------------------------------
        let blockSize = resolveBlockSize(spec.block, sources: sources, warnings: &warnings)
        var blockCount = sliceTotal(sources, blockSize)
        if blockCount == 0 && !sources.isEmpty { blockCount = sources.count }

        let occupied = Int64(blockCount) * blockSize
        let padding = max(0, occupied - totalBytes)
        // Both percentages are of the PADDED GRID, so they are complements and sum to a
        // hundred: `pct(padding_bytes, padded)` beside `pct(source_bytes, padded)`.
        let paddingPct = occupied == 0 ? 0 : Double(padding) / Double(occupied) * 100
        let efficiency = occupied == 0 ? 0 : Double(totalBytes) / Double(occupied) * 100

        // --- recovery -----------------------------------------------------
        let recoveryBlocks = resolveRecoveryBlocks(spec.recovery, blockCount: blockCount,
                                                  blockSize: blockSize, warnings: &warnings)
        let recoveryPercent = blockCount == 0 ? 0 : Double(recoveryBlocks) / Double(blockCount) * 100
        let recoveryBytes = Int64(recoveryBlocks) * blockSize

        if recoveryBlocks == 0 {
            warnings.append("No recovery blocks. The set can detect damage but not repair it.")
        }
        // THE EXPONENT CEILING IS THIS MOCK'S OWN WARNING and the engine has none: a
        // create whose recovery exponents pass 65,535 is REFUSED by
        // `par2gen::check_create_inputs`, but `planner::preview` does not look, so the
        // engine's own pane can draw a set the create will then refuse. Reported rather
        // than worked around - and this no longer CLAMPS the count, because a clamp
        // makes the preview disagree with the engine about a number as well.
        if spec.first_recovery_block + recoveryBlocks > 65535 {
            warnings.append("A PAR2 set's recovery blocks are numbered up to 65,535, and this set would "
                            + "run past that. Lower the recovery or the first block number.")
        }

        // --- volume layout -------------------------------------------------
        let stem = outputStem(spec.output, sources: sources)
        // `-l` is a ceiling in BYTES - no volume larger than the largest input file -
        // and it FLOOR-divides into slices: a twenty-and-a-half block member caps a
        // volume at twenty, because a ceiling that rounds up is not a ceiling.
        let largestSource = sources.map(\.size).max() ?? 0
        let askedVolumes = uniformVolumeCount(spec.volumes, recoveryBlocks: recoveryBlocks,
                                              blockSize: blockSize)
        var layout = volumeLayout(
            scheme: spec.volumes,
            recoveryBlocks: recoveryBlocks,
            blockSize: blockSize,
            largestSource: largestSource,
            warnings: &warnings)
        if layout.count > maxRecoveryFiles * 2 && spec.volumes.family == .uniform {
            // Unreachable through `uniformVolumeCount`, which clamps; kept as a floor
            // under a caller that builds a layout some other way.
            layout = Array(layout.prefix(maxRecoveryFiles))
        }

        // --- the files ------------------------------------------------------
        // The index is the whole critical block; a volume is its slices plus
        // `copies` repeats of that block, `copies` being the BIT LENGTH of the slice
        // count. `nzbkit::par2gen::plan_files_with_comment` is the authority and these
        // are its bytes exactly, over every fixture the parity sweep compared.
        let indexSize = criticalBlockBytes(sources, blockSize: blockSize)
        var files: [PreviewFile] = [
            PreviewFile(name: "\(stem).par2", size: indexSize, blocks: 0, efficiency_pct: 0)
        ]
        let names = volumeNames(stem: stem, layout: layout, firstBlock: spec.first_recovery_block,
                                recovery: recoveryBlocks, stdNaming: spec.std_naming)
        for (i, blocks) in layout.enumerated() {
            let size = volumeSize(sources, blockSize: blockSize, blocks: blocks)
            let payload = Int64(blocks) * blockSize
            files.append(PreviewFile(
                name: names[i], size: size, blocks: blocks,
                efficiency_pct: size == 0 ? 0 : Double(payload) / Double(size) * 100))
        }

        let total = files.reduce(Int64(0)) { $0 + $1.size }
        return PlanPreview(
            block_size: blockSize,
            block_count: blockCount,
            padding_bytes: padding,
            padding_pct: paddingPct,
            efficiency_pct: efficiency,
            recovery_blocks: recoveryBlocks,
            recovery_percent: recoveryPercent,
            recovery_bytes: recoveryBytes,
            total_bytes: total,
            files: files,
            command: command(spec: spec, sources: sources, blockSize: blockSize,
                             recoveryBlocks: recoveryBlocks, volumeCount: askedVolumes),
            warnings: warnings,
            // THE TWO FIELDS API.md MARKS ADDED, AND THEY WERE NEVER SET.
            // The real planner fills both; this one took the nil default, and
            // nothing in the mac tree read either - so the omission was
            // invisible until the create cost bar arrived and made the whole
            // of its part-to-whole bar `source + total`. With `source_bytes`
            // nil that whole IS the PAR2 set, and a 2 GiB source protected at
            // ten per cent draws as ONE HUNDRED PER CENT RECOVERY,
            // confidently, on the mock-driven demo and the whole screenshot
            // set. Found by the Windows lane's own cost-bar test (chart (a) of
            // the 12 Sep 2026 prettiness review) and mirrored here.
            //
            // `padding_pct` above is NOT the Windows defect's twin and must
            // not be "fixed" to match it: this one already divides by
            // `occupied`, the PADDED GRID, which is what the engine does and
            // what makes padding and efficiency complements summing to a
            // hundred. Checked 12 Sep 2026 before this edit.
            //
            // The remaining PlanPreview fields WERE claim
            // `parfast-planpreview-field-parity`'s sweep, and it landed the
            // same day: twenty-three disagreements across the two mocks, the
            // rest of this file's rewrite, and a `PlannerParityTests` on each
            // side that compares every field against the real engine rather
            // than against a number somebody measured once.
            source_bytes: totalBytes,
            source_files: sources.count)
    }

    // MARK: - Pieces

    static func roundUpTo4(_ n: Int64) -> Int64 { max(4, (n + 3) / 4 * 4) }

    /// Slices this grid costs: per FILE, never over the pooled total.
    static func sliceTotal(_ sources: [Source], _ blockSize: Int64) -> Int {
        guard blockSize > 0 else { return 0 }
        return sources.reduce(0) { $0 + Int(($1.size + blockSize - 1) / blockSize) }
    }

    /// The block size the spec resolves to (`parfast::create::block_size`).
    ///
    /// A COUNT IS A SEARCH AND NOT A DIVISION, and this file divided until
    /// 12 September 2026. A slice never spans a file boundary, so the count is the sum
    /// of per-file ceilings and the remainders do not pool: over 40,000 and 17,000 bytes
    /// at `-b64` the division gives 892, which slices into 45 + 20 = 65 - one MORE than
    /// was asked for - where the reference answers 896 and gets 45 + 19 = 64. Asking for
    /// more slices than the tool will accept is not cosmetic, because 32,768 is a hard
    /// ceiling other PAR2 tools refuse above.
    ///
    /// A count below the FILE count is unreachable at any size. The engine's search runs
    /// out and lands on the payload itself - one slice per member - so that is the answer
    /// here too, with a warning this mock adds and the engine does not.
    static func resolveBlockSize(_ block: BlockChoice, sources: [Source],
                                 warnings: inout [String]) -> Int64 {
        let total = sources.reduce(Int64(0)) { $0 + $1.size }
        switch block {
        case .size(let s):
            let rounded = roundUpTo4(s)
            if rounded != s {
                warnings.append("The block size was rounded up to \(rounded) bytes, a multiple of 4.")
            }
            return legalBlockSize(sources, asked: rounded, warnings: &warnings)
        case .count(let n):
            let wanted = max(1, n)
            var bs = roundUpTo4(total / Int64(wanted) + (total % Int64(wanted) == 0 ? 0 : 1))
            let ceilingSize = max(total, 4)
            while bs < ceilingSize && sliceTotal(sources, bs) > wanted {
                bs += 4
            }
            if sliceTotal(sources, bs) > wanted {
                bs = roundUpTo4(total)
            }
            if wanted < sources.count {
                warnings.append("\(formatted(wanted)) blocks is fewer than the \(formatted(sources.count)) "
                                + "files in the set, and every file needs at least one block, so the set "
                                + "has \(formatted(sliceTotal(sources, bs))).")
            }
            return legalBlockSize(sources, asked: bs, warnings: &warnings)
        }
    }

    /// Raises a slice size until the set fits `maxSourceBlocks`, and says so
    /// (`parfast::create::legal_block_size`).
    ///
    /// THE ENGINE ENFORCES THE CEILING; this file only warned about it and kept the
    /// illegal size, so the pane drew a block size and a count the create would never
    /// use. The raise is to a MULTIPLE of what was asked for rather than to the first
    /// size that fits: Usenet loses whole articles, and a block size that is an exact
    /// multiple of the article size never lets an article straddle two blocks.
    static func legalBlockSize(_ sources: [Source], asked: Int64,
                               warnings: inout [String]) -> Int64 {
        guard asked > 0, sliceTotal(sources, asked) > maxSourceBlocks else { return asked }
        let total = sources.reduce(Int64(0)) { $0 + $1.size }
        var mult: Int64 = 2
        while asked * mult <= max(total, 4) {
            let candidate = asked * mult
            if sliceTotal(sources, candidate) <= maxSourceBlocks {
                warnings.append("A block size of \(formatted64(asked)) would put the set over the spec's "
                                + "\(formatted(maxSourceBlocks)) input slices, so "
                                + "\(formatted64(candidate)) is used.")
                return candidate
            }
            mult += 1
        }
        var bs = max(asked, roundUpTo4(total / Int64(maxSourceBlocks)))
        while bs < max(total, 4) && sliceTotal(sources, bs) > maxSourceBlocks {
            bs += 4
        }
        warnings.append("A block size of \(formatted64(asked)) would put the set over the spec's "
                        + "\(formatted(maxSourceBlocks)) input slices, so \(formatted64(bs)) is used.")
        return bs
    }

    /// How many recovery slices the spec asks for (`parfast::create::recovery_blocks`).
    ///
    /// A SIZE is a ceiling over the block size, so a target the block size does not
    /// divide buys the slice that covers it. A PERCENTAGE is round-to-nearest with a
    /// FLOOR OF ONE BLOCK - measured against par2cmdline-turbo 1.5.0 over 32 blocks,
    /// `-r49 -r50 -r51` all give 16 and `-r52` gives 17 - and the floor is what this file
    /// was missing: `-r1` over 32 blocks drew a set with NO recovery in it. `-r` is an
    /// INTEGER percent in the reference's dialect, so a fractional ask is rounded and
    /// said out loud rather than quietly taken as something else.
    static func resolveRecoveryBlocks(_ recovery: RecoveryChoice, blockCount: Int,
                                      blockSize: Int64, warnings: inout [String]) -> Int {
        switch recovery {
        case .percent(let p):
            let whole = max(0, p).rounded()
            if abs(whole - max(0, p)) > .ulpOfOne {
                warnings.append("The reference takes whole percents, so \(trim(p))% was taken as "
                                + "\(trim(whole))%. Use a recovery block count for finer control.")
            }
            return percentBlocks(blockCount, Int(whole))
        case .count(let n):
            return max(0, n)
        case .size(let b):
            guard blockSize > 0 else { return 0 }
            return Int((max(0, b) + blockSize - 1) / blockSize)
        }
    }

    /// The reference's percentage rule: round to nearest, halves up, never fewer than
    /// one block for a non-zero ask (`parfast::create::percent_blocks`).
    public static func percentBlocks(_ blockCount: Int, _ pct: Int) -> Int {
        guard pct > 0, blockCount > 0 else { return 0 }
        return max(1, (blockCount * pct + 50) / 100)
    }

    /// Blocks per recovery volume, in order. Empty only when the set has no recovery.
    ///
    /// THE "NONE" SCHEME IS NOT ONE MERGED FILE. A `-n1` create writes the critical
    /// packets to `set.par2` and every recovery slice to ONE volume beside it, so the
    /// preview lists two files - this file merged them and listed one. The uniform arms
    /// resolve a volume COUNT and then split EVENLY, which gives the remainder to the
    /// FIRST volumes: 100 slices over 7 files are 15 15 14 14 14 14 14.
    static func volumeLayout(scheme: VolumeScheme, recoveryBlocks: Int, blockSize: Int64,
                             largestSource: Int64, warnings: inout [String]) -> [Int] {
        guard recoveryBlocks > 0 else { return [] }
        switch scheme {
        case .none:
            return evenSplit(recoveryBlocks, volumes: 1)
        case .uniformFiles, .uniformBlocksPerFile, .uniformFileSize:
            return evenSplit(recoveryBlocks,
                             volumes: uniformVolumeCount(scheme, recoveryBlocks: recoveryBlocks,
                                                         blockSize: blockSize))
        case .pow2:
            return pow2(recoveryBlocks, cap: Int.max)
        case .pow2LimitLargestSource:
            return pow2(recoveryBlocks, cap: max(1, Int(largestSource / max(1, blockSize))))
        case .pow2LimitBlocks(let b):
            return pow2(recoveryBlocks, cap: max(1, b))
        case .pow2LimitSize(let s):
            // A ceiling in bytes is one in slices at this block size, and a slice costs
            // its own bytes PLUS the writer's 68: at a 1 MiB block a 10 MiB volume holds
            // nine slices, not ten. The engine says which number the bytes became.
            let cap = max(1, Int(s / max(1, blockSize + slicePacketOverhead)))
            warnings.append("A ceiling of \(formatted64(s)) bytes per volume is \(formatted(cap)) recovery "
                            + "block(s) at this block size. Each volume also carries a copy of the set's "
                            + "critical packets, so a file is a little larger than that.")
            return pow2(recoveryBlocks, cap: cap)
        }
    }

    /// `par2gen::VolumePlan::Even`: `k` volumes of `n/k`, remainder to the FIRST ones.
    public static func evenSplit(_ recoveryBlocks: Int, volumes: Int) -> [Int] {
        let k = min(max(1, volumes), max(1, recoveryBlocks))
        let (base, remainder) = (recoveryBlocks / k, recoveryBlocks % k)
        return (0..<k).map { base + ($0 < remainder ? 1 : 0) }
    }

    /// How many volumes the uniform scheme's three spellings mean, which is also the
    /// number `-n` carries (`parfast::create::recovery_file_count` and the planner's own
    /// translation - both clamp to `maxRecoveryFiles`).
    ///
    /// The count the LINE spells is the one that was asked for, and the LAYOUT is that
    /// capped by the slice count: a set of four slices asked for seven volumes writes
    /// four and still pastes `-n7`, because the engine caps it at the far end.
    public static func uniformVolumeCount(_ scheme: VolumeScheme, recoveryBlocks: Int,
                                          blockSize: Int64) -> Int {
        func clamp(_ n: Int) -> Int { min(max(1, n), maxRecoveryFiles) }
        switch scheme {
        case .uniformFiles(let f):
            return clamp(f)
        case .uniformBlocksPerFile(let b):
            let per = max(1, b)
            return clamp((recoveryBlocks + per - 1) / per)
        case .uniformFileSize(let s):
            let per = max(1, Int(s / max(1, blockSize + slicePacketOverhead)))
            return clamp((recoveryBlocks + per - 1) / per)
        case .none:
            return 1
        default:
            return 0
        }
    }

    /// 1, 2, 4, 8 ... capped, then the remainder, which is what "variable" recovery
    /// file sizing means in every tool in this family.
    static func pow2(_ total: Int, cap: Int) -> [Int] {
        var out: [Int] = []
        var size = 1
        var left = total
        while left > 0 {
            let take = min(min(size, cap), left)
            out.append(take)
            left -= take
            if size < cap && size <= Int.max / 2 { size *= 2 }
        }
        return out
    }

    static func outputStem(_ output: String, sources: [Source]) -> String {
        if !output.isEmpty {
            var name = (output as NSString).lastPathComponent
            if name.lowercased().hasSuffix(".par2") { name = String(name.dropLast(5)) }
            if !name.isEmpty { return name }
        }
        if sources.count == 1 {
            return ((sources[0].name as NSString).deletingPathExtension)
        }
        return sources.first.map { ($0.name as NSString).deletingPathExtension } ?? "recovery"
    }

    /// The whole set's volume names (`parfast::create::final_volume_names`).
    ///
    /// THE TWO FIELDS HAVE DIFFERENT WIDTHS AND NEITHER IS THREE. This file padded both
    /// to `%03d`, so it drew `vol000+016` where par2cmdline writes `vol00+1` for the same
    /// set - and the next tool along finds a set's volumes by that pattern. The first
    /// field is as wide as `first + recovery`, the exponent one PAST the last written;
    /// the second is as wide as the largest COUNT that appears; and under `--std-naming`
    /// both fields are exponents, so both take the first field's width. Hence a function
    /// over the LIST: one volume's name depends on the whole set.
    public static func volumeNames(stem: String, layout: [Int], firstBlock: Int,
                                   recovery: Int, stdNaming: Bool) -> [String] {
        let firstWidth = digits(firstBlock + recovery)
        let countWidth = layout.map(digits).max() ?? 1
        var out: [String] = []
        var first = firstBlock
        for blocks in layout {
            out.append(volumeName(stem: stem, first: first, blocks: blocks, stdNaming: stdNaming,
                                  firstWidth: firstWidth, countWidth: countWidth))
            first += blocks
        }
        return out
    }

    /// One volume's name at the widths `volumeNames` measured for the set:
    /// `name.vol00+10.par2`, or the spec's own `name.vol00-09.par2` under `--std-naming`.
    public static func volumeName(stem: String, first: Int, blocks: Int, stdNaming: Bool,
                                  firstWidth: Int, countWidth: Int) -> String {
        let a = pad(first, firstWidth)
        if stdNaming {
            return "\(stem).vol\(a)-\(pad(first + max(0, blocks - 1), firstWidth)).par2"
        }
        return "\(stem).vol\(a)+\(pad(blocks, countWidth)).par2"
    }

    static func pad(_ n: Int, _ width: Int) -> String {
        let s = String(max(0, n))
        return s.count >= width ? s : String(repeating: "0", count: width - s.count) + s
    }

    static func digits(_ n: Int) -> Int { String(max(0, n)).count }

    /// The index file: the whole critical block, and no recovery data.
    ///
    /// `nzbkit::par2gen::critical_packets` is what this models - a main packet naming
    /// every file, then per member a description packet and an input file slice checksum
    /// packet (16 bytes of MD5 and 4 of CRC32 per block), then the creator packet. This
    /// file used `1024 + 512 * files` until 12 September 2026, which is the right order
    /// of magnitude and the wrong number for every set.
    static func criticalBlockBytes(_ sources: [Source], blockSize: Int64) -> Int64 {
        let header: Int64 = 64
        var total = header + 12 + 16 * Int64(sources.count)
        for s in sources {
            let nameBytes = Int64(s.name.utf8.count)
            let blocks = blockSize > 0 ? (s.size + blockSize - 1) / blockSize : 0
            total += header + 56 + (nameBytes + 3) / 4 * 4 + header + 16 + 20 * blocks
        }
        return total + creatorPacketBytes
    }

    /// One recovery volume's size on disk (`par2gen::plan_files_with_comment`).
    ///
    /// THE CRITICAL BLOCK IS REPEATED, LOGARITHMICALLY: the writer interleaves `copies`
    /// whole copies of everything but the creator packet, where `copies` is the BIT
    /// LENGTH of the volume's slice count - one slice gets one copy, sixteen get five.
    /// So a volume is logarithmically more redundant and not proportionally so.
    static func volumeSize(_ sources: [Source], blockSize: Int64, blocks: Int) -> Int64 {
        let cycle = criticalBlockBytes(sources, blockSize: blockSize) - creatorPacketBytes
        var copies: Int64 = 0
        var n = blocks
        while n > 0 {
            copies += 1
            n >>= 1
        }
        return Int64(blocks) * (blockSize + slicePacketOverhead) + copies * cycle + creatorPacketBytes
    }

    /// The equivalent `parfast c` line, for the Copy command button.
    ///
    /// Measured switch for switch against `planner::command_args`, which the engine
    /// asserts parses BACK into the same options it was built from. Five things here were
    /// lines that would not have built the set the pane drew:
    ///
    /// - `-B` was emitted as two arguments. The reference's short options take an
    ///   ATTACHED value, so `-B /abs` is an empty base path and `/abs` becomes the first
    ///   bare argument - which is the OUTPUT path. The whole line shifted by one.
    /// - a recovery SIZE pasted `-rm<MB>` off a truncating division, so a target that was
    ///   not a whole number of mebibytes asked for a different amount. `-r` takes a k, m
    ///   or g multiple and nothing else, so a size no unit divides is spelled as the exact
    ///   `-c` count it resolves to anyway.
    /// - a block or byte volume ceiling carried no switch and a warning saying the CLI
    ///   could not express it. It can: `--volume-blocks=N`.
    /// - `--std-naming` was not on the line at all.
    /// - the member list was TRUNCATED at twelve with "... N more" in it, which is not a
    ///   command. The engine lists every member, so this does.
    ///
    /// `-R` is not on the line either: the engine expands a directory source itself and
    /// names the members, which is what the sources handed to this function already are.
    public static func command(spec: CreateSpec, sources: [Source], blockSize: Int64,
                              recoveryBlocks: Int, volumeCount: Int) -> String {
        var parts = ["parfast", "c"]
        switch spec.block {
        // THE SIZE THAT WAS ASKED FOR, not the one the rules resolved: the CLI applies
        // the rounding and the slice-ceiling raise itself.
        case .size(let s): parts.append("-s\(s)")
        case .count(let n): parts.append("-b\(n)")
        }
        switch spec.recovery {
        case .percent(let p):
            parts.append("-r\(Int(max(0, p).rounded()))")
        case .count(let n):
            parts.append("-c\(n)")
        case .size(let b):
            parts.append(scaled(b).map { "-r\($0)" } ?? "-c\(recoveryBlocks)")
        }
        switch spec.volumes {
        case .none:
            parts.append("-n1")
        case .uniformFiles, .uniformBlocksPerFile, .uniformFileSize:
            parts.append("-n\(max(1, volumeCount))")
        case .pow2:
            break                                  // variable is the CLI default
        case .pow2LimitLargestSource:
            parts.append("-l")
        case .pow2LimitBlocks(let b):
            parts.append("--volume-blocks=\(max(1, b))")
        case .pow2LimitSize(let s):
            parts.append("--volume-blocks=\(max(1, Int(s / max(1, blockSize + slicePacketOverhead))))")
        }
        if spec.std_naming { parts.append("--std-naming") }
        if spec.first_recovery_block != 0 { parts.append("-f\(spec.first_recovery_block)") }
        if let threads = spec.perf.threads { parts.append("-t\(threads)") }
        if let mb = spec.perf.memory_mb { parts.append("-m\(mb)") }
        if spec.path_mode == .relative, let base = spec.base_path, !base.isEmpty {
            parts.append("-B" + quote(base))
        }
        if !spec.comment.isEmpty { parts.append("--comment=" + quote(spec.comment)) }
        parts.append(quote(spec.output.isEmpty
            ? "\(outputStem(spec.output, sources: sources)).par2" : spec.output))
        for s in sources { parts.append(quote(s.path)) }
        return parts.joined(separator: " ")
    }

    /// `-r`'s scaled spelling for a byte count, largest unit first, or nil for a count
    /// no unit divides exactly (`planner::scaled`).
    static func scaled(_ bytes: Int64) -> String? {
        for (letter, unit) in [("g", Int64(1) << 30), ("m", Int64(1) << 20), ("k", Int64(1) << 10)] {
            if bytes >= unit && bytes % unit == 0 { return "\(letter)\(bytes / unit)" }
        }
        return nil
    }

    static func quote(_ s: String) -> String {
        s.rangeOfCharacter(from: CharacterSet(charactersIn: " \t'\"\\")) == nil
            ? s : "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func trim(_ value: Double) -> String {
        value == value.rounded(.down) ? "\(Int(value))" : String(format: "%g", value)
    }

    static func formatted(_ n: Int) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }

    static func formatted64(_ n: Int64) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }
}
