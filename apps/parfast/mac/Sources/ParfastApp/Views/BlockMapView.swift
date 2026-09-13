import SwiftUI
import ParfastCore

/// The signature visual (plan 5.2): one cell per source block, coloured by
/// state, with a recovery band under it.
///
/// QuickPar's availability strip is the thing every later tool copied, and
/// this is the one visual worth doing beautifully. Two behaviours make it
/// worth more than a coloured bar:
///
///  * ABOVE `T.sizeBlockMergeThreshold` cells merge into proportional
///    segments and each segment takes the WORST state in its range, because a
///    ten-thousand-block set on a 900-point strip has eleven blocks per pixel
///    and averaging them hides exactly the damage the user opened the app to
///    find. The hover readout then gives the real census for the range.
///  * The RECOVERY BAND draws what is available against what is needed, with
///    the needed count marked, so "repairable" and "not repairable" are a
///    picture before they are a sentence.
struct BlockMapView: View {

    var states: [BlockState]
    var recoveryAvailable: Int
    var recoveryNeeded: Int
    var verdict: SurveyVerdict
    @Binding var hover: BlockMapHover?

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(alignment: .leading, spacing: T.spacingS) {
            GeometryReader { geo in
                Canvas { context, size in
                    draw(context: context, size: size)
                }
                .onAppear { mergedColumns = columns(for: geo.size.width) }
                .onChange(of: geo.size.width) { _, width in
                    mergedColumns = columns(for: width)
                }
                .onContinuousHover { phase in
                    switch phase {
                    case .active(let point):
                        hover = hit(at: point.x, width: geo.size.width)
                    case .ended:
                        hover = nil
                    }
                }
            }
            .frame(height: T.sizeBlockMapHeight)
            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .strokeBorder(T.surfaceCardBorder, lineWidth: 1)
            )
            .accessibilityElement()
            .accessibilityLabel(S.verifyMapTitle)
            .accessibilityValue(textSummary)

            RecoveryBand(available: recoveryAvailable, needed: recoveryNeeded, verdict: verdict)

            HStack(spacing: T.spacingL) {
                legend
                Spacer(minLength: T.spacingM)
                // THE MERGED NOTE, NOT THE CENSUS. The census moved onto the
                // legend's swatches on 12 Sep 2026, where each number sits beside
                // the colour it counts; restating all five here as a grey run-on
                // sentence made the reader match word to word instead of colour to
                // count. Losing it costs nothing for a screen reader - the map's
                // own accessibility value IS `textSummary`, set above - and this
                // is the placement the Windows app already uses.
                //
                // What is left here is the one thing the legend cannot say:
                // whether a cell is a block or a bundle of them, and on hover the
                // census of the range under the pointer. The Windows app carries
                // the hover half in a tooltip, so this slot is the same content in
                // the idiom each platform reads.
                Text(hoverText ?? mergedNote ?? "")
                    .font(.system(size: 11))
                    .monospacedDigit()
                    .foregroundStyle(T.textTertiary)
                    .lineLimit(1)
                    .animation(reduceMotion ? nil : .easeOut(duration: 0.12), value: hoverText)
            }
        }
    }

    // MARK: - Drawing

    private func columns(for width: CGFloat) -> Int {
        guard !states.isEmpty else { return 0 }
        let byWidth = max(1, Int(width / T.sizeBlockCellMin))
        return min(states.count, byWidth)
    }

    private var isMerged: Bool { states.count > Int(T.sizeBlockMergeThreshold) }

    private func draw(context: GraphicsContext, size: CGSize) {
        guard !states.isEmpty else {
            context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(T.surfaceWell))
            return
        }
        let cols = columns(for: size.width)
        guard cols > 0 else { return }
        let cellWidth = size.width / CGFloat(cols)
        // A gap only reads as a gap when the cell is wide enough to carry one.
        let gap: CGFloat = cellWidth >= 5 ? 1 : 0
        let merged = cols < states.count

        // Adjacent columns of the same state are drawn as ONE rect, with the
        // edges snapped to whole points. Drawing a separate fractional-width
        // rect per column leaves an antialiased seam between every pair, and a
        // thousand of those read as grey stripes over a healthy set.
        func rect(from startColumn: Int, to endColumn: Int) -> CGRect {
            let x0 = (CGFloat(startColumn) * cellWidth).rounded(.down)
            let x1 = (CGFloat(endColumn + 1) * cellWidth).rounded(.down)
            let inset = (gap > 0 && endColumn > startColumn) ? gap : 0
            return CGRect(x: x0, y: 0, width: max(1, x1 - x0 - inset), height: size.height)
        }

        var runStart = 0
        var runState = groundState(column: 0, of: cols)
        for column in 1..<max(1, cols) {
            let state = groundState(column: column, of: cols)
            if state != runState {
                context.fill(Path(rect(from: runStart, to: column - 1)),
                             with: .color(ground(runState)))
                runStart = column
                runState = state
            }
        }
        context.fill(Path(rect(from: runStart, to: cols - 1)),
                     with: .color(ground(runState)))

        // MERGED CELLS ONLY: a tick along the bottom wherever the range holds
        // at least one bad block.
        //
        // The ground above is the MAJORITY state, which keeps the areas
        // honest - the first cut took the worst state in the range, and 188
        // damaged blocks scattered through a 10,000-block set painted a fifth
        // of the map red. The ground alone would then hide a single bad block
        // among twenty-five, which is the opposite failure and the worse one.
        // Ground for the proportion, tick for the presence; the readout under
        // the map carries the exact census either way.
        if merged {
            let tickHeight = max(3, size.height * 0.22)
            var tickStart: Int? = nil
            var tickState: BlockState = .damaged
            func flushTick(_ endColumn: Int) {
                guard let start = tickStart else { return }
                var r = rect(from: start, to: endColumn)
                r.origin.y = size.height - tickHeight
                r.size.height = tickHeight
                // A mark that says "something is wrong here" must not
                // antialias away. Chip C's finding, and it is the same defect
                // as not drawing it at all.
                r.size.width = max(CGFloat(BlockMapRule.minimumMarkWidth), r.size.width)
                context.fill(Path(r), with: .color(T.blockPalette[Int(tickState.rawValue)]))
                tickStart = nil
            }
            for column in 0..<cols {
                let (first, last) = range(column: column, of: cols)
                let bad = worstBadState(from: first, through: last)
                if let bad {
                    if tickStart == nil || bad != tickState {
                        flushTick(column - 1)
                        tickStart = column
                        tickState = bad
                    }
                } else {
                    flushTick(column - 1)
                }
            }
            flushTick(cols - 1)
        }

        // The hovered range gets a hairline over it, so the readout below has
        // something to point at.
        if let hover {
            let x0 = size.width * CGFloat(hover.first) / CGFloat(states.count)
            let x1 = size.width * CGFloat(hover.last + 1) / CGFloat(states.count)
            let r = CGRect(x: x0, y: 0, width: max(2, x1 - x0), height: size.height)
            context.stroke(Path(r.insetBy(dx: 0.5, dy: 0.5)),
                           with: .color(T.textPrimary.opacity(0.75)), lineWidth: 1)
        }
    }

    private func range(column: Int, of cols: Int) -> (Int, Int) {
        let r = BlockMapRule.range(column: column, of: cols, blocks: states.count)
        return (r.lowerBound, r.upperBound)
    }

    /// Both halves of the cell rule live in `ParfastCore.BlockMapRule`, which
    /// carries the measurement that chose them and is pinned by tests. The
    /// view does not get its own copy.
    /// The colour a run is grounded in, which is not always the colour that
    /// names its state. The rule and its measurements live in
    /// `BlockPalette.ground(_:)`, which is CALLED and never restated - a key or
    /// a row strip whose green is twice the green of the strip it explains is
    /// the disagreement that function exists to prevent.
    private func ground(_ state: BlockState) -> Color { BlockPalette.ground(state) }

    private func groundState(column: Int, of cols: Int) -> BlockState {
        BlockMapRule.ground(states, in: BlockMapRule.range(column: column, of: cols,
                                                           blocks: states.count))
    }

    private func worstBadState(from first: Int, through last: Int) -> BlockState? {
        BlockMapRule.badMark(states, in: first...last)
    }

    private func rank(_ s: BlockState) -> Int { BlockMapRule.rank(s) }

    private func hit(at x: CGFloat, width: CGFloat) -> BlockMapHover? {
        guard !states.isEmpty, width > 0, x >= 0, x <= width else { return nil }
        let cols = columns(for: width)
        let column = min(cols - 1, max(0, Int(x / (width / CGFloat(cols)))))
        let first = states.count * column / cols
        let last = max(first, states.count * (column + 1) / cols - 1)
        var counts: [BlockState: Int] = [:]
        for i in first...min(last, states.count - 1) {
            counts[states[i], default: 0] += 1
        }
        return BlockMapHover(first: first, last: last, counts: counts)
    }

    // MARK: - Words

    private var hoverText: String? {
        guard let hover else { return nil }
        if hover.isSingle {
            let state = states.indices.contains(hover.first) ? states[hover.first] : .pending
            return S.verifyMapHoverSingle(index: Fmt.count(hover.first + 1),
                                          state: T.blockLabels[Int(state.rawValue)])
        }
        let detail = hover.counts
            .sorted { rank($0.key) > rank($1.key) }
            .map { "\(Fmt.count($0.value)) \(T.blockLabels[Int($0.key.rawValue)].lowercased())" }
            .joined(separator: ", ")
        return S.verifyMapHoverRange(first: Fmt.count(hover.first + 1),
                                     last: Fmt.count(hover.last + 1),
                                     detail: detail)
    }

    /// The map's text equivalent, for VoiceOver and for the line under it.
    var textSummary: String {
        let tally = counts
        return S.verifyMapSummary(
            present: Fmt.count(tally[.present] ?? 0),
            damaged: Fmt.count(tally[.damaged] ?? 0),
            missing: Fmt.count(tally[.missing] ?? 0),
            misnamed: Fmt.count(tally[.misnamed] ?? 0),
            total: Fmt.count(states.count))
    }

    /// The key under the map: a swatch, a word and A COUNT per state, with the
    /// states at zero DIMMED rather than dropped.
    ///
    /// Two reasons for the counts, and the second is the one that matters. The
    /// obvious one: the census under the map used to restate all five numbers as
    /// a grey sentence beside a key that had none, so the reader matched word to
    /// word instead of colour to count. The real one: the strip tells its states
    /// apart by COLOUR ALONE, and two of its pairs sit close enough that a
    /// colourblind reader cannot separate them - a count beside each swatch is
    /// the secondary channel that makes the key readable without colour at all.
    ///
    /// Dimming rather than hiding keeps the key a fixed list, so its shape does
    /// not change as a verify walks and states appear under the pointer. Ported
    /// from the Windows `Legend.cs`, whose header carries the same reasoning.
    private var legend: some View {
        // Tallied ONCE, not once per swatch: this is a walk of the whole strip
        // and the strip can be ten thousand blocks long.
        let tally = counts
        return HStack(spacing: T.spacingM) {
            ForEach(Self.legendStates, id: \.self) { state in
                let count = tally[state] ?? 0
                HStack(spacing: 5) {
                    // `ground(_:)`, not the raw palette: the swatch has to show
                    // what the STRIP draws, and a present run is drawn washed. A
                    // key whose green is twice the green of the thing it explains
                    // is the disagreement this legend exists to prevent.
                    RoundedRectangle(cornerRadius: 2)
                        .fill(ground(state))
                        .frame(width: 9, height: 9)
                    Text(T.blockLabels[Int(state.rawValue)])
                        .font(.system(size: 11))
                        .foregroundStyle(T.textSecondary)
                    Text(Fmt.count(count))
                        .font(.system(size: 11, weight: .semibold))
                        .monospacedDigit()
                        .foregroundStyle(T.textPrimary)
                }
                .opacity(count == 0 ? 0.4 : 1)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(textSummary)
    }

    /// Every state the key lists, in wire-code order, whatever this set happens
    /// to hold. Pending is left out: "not read yet" is the ground the strip
    /// starts as, and naming it in the key invites the reader to hunt for a
    /// colour that means nothing is wrong. Same rule, same order, as the Windows
    /// app's `BlockPalette.Legend`.
    private static let legendStates: [BlockState] =
        BlockState.allCases.filter { $0 != .pending }

    /// One pass over the strip for every figure the key and the summary quote,
    /// so a count beside a swatch and the same count in the accessibility text
    /// cannot disagree.
    private var counts: [BlockState: Int] {
        var counts: [BlockState: Int] = [:]
        for s in states { counts[s, default: 0] += 1 }
        return counts
    }

    /// Columns the last draw used, so the merged note can name the real
    /// number of blocks a cell covers rather than a guess.
    @State private var mergedColumns: Int = 0

    /// Present only once the column count is known. `mergedColumns` is a
    /// @State that onAppear fills in, so it is zero on the first pass, and the
    /// old arithmetic turned that zero into a per-cell figure equal to the
    /// TOTAL block count. Absent beats wrong: the note appears on the next pass.
    private var mergedNote: String? {
        guard isMerged,
              let per = BlockMapRule.blocksPerCell(blocks: states.count,
                                                   columns: mergedColumns)
        else { return nil }
        return S.verifyMapMergedNote(per: Fmt.count(per))
    }
}

/// Recovery blocks available, drawn against the number needed.
struct RecoveryBand: View {
    var available: Int
    var needed: Int
    var verdict: SurveyVerdict

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            GeometryReader { geo in
                let total = max(1, max(available, needed))
                let fill = geo.size.width * CGFloat(available) / CGFloat(total)
                let mark = geo.size.width * CGFloat(needed) / CGFloat(total)
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 3).fill(T.recoverySpare)
                    RoundedRectangle(cornerRadius: 3)
                        .fill(bandColour)
                        .frame(width: fill)
                        .animation(reduceMotion ? nil : .easeOut(duration: 0.25), value: available)
                    if needed > 0 {
                        Rectangle()
                            .fill(T.recoveryNeeded)
                            .frame(width: 2)
                            .offset(x: max(0, min(geo.size.width - 2, mark)))
                    }
                }
            }
            .frame(height: T.sizeRecoveryBandHeight)
            HStack(spacing: T.spacingS) {
                Text(S.verifyMapLegendRecovery)
                    .font(.system(size: 11))
                    .foregroundStyle(T.textSecondary)
                Text(Fmt.count(available))
                    .font(.system(size: 11, weight: .semibold))
                    .monospacedDigit()
                    .foregroundStyle(T.textPrimary)
                if needed > 0 {
                    Text(S.verifyMapNeededMarker(needed: Fmt.count(needed)))
                        .font(.system(size: 11))
                        .monospacedDigit()
                        .foregroundStyle(needed > available ? T.statusBad : T.textSecondary)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }

    /// A finished verify animates the band into its verdict colour (5.7).
    private var bandColour: Color {
        switch verdict {
        case .complete, .repaired: return T.statusGood
        case .repairable: return T.recoveryAvailable
        case .unrepairable, .failed: return T.statusBad
        case .verifying: return T.recoveryAvailable
        }
    }
}
