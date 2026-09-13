import Foundation

/// How a merged block-map cell picks its colour.
///
/// It lives here, as pure functions over a state array, rather than inside the
/// view, for two reasons: it is the one rendering rule the two apps must agree
/// on down to the pixel (it is THE signature visual), and it is the kind of
/// rule that is argued about from intuition unless somebody measures it.
///
/// THE MEASUREMENT, on the mock's ten-thousand-block set (188 damaged blocks,
/// 1.88%, scattered - which is what dropped articles look like) at the two
/// cell counts a real window produces:
///
/// | rule | 10,000 blocks, 188 scattered damaged | one lone bad block in 10,000 |
/// |---|---|---|
/// | worst state wins | **19.5% of the strip red** for 1.88% damage | 1 cell red |
/// | majority state only | 0% red - **damage invisible** | **0 cells red** |
/// | majority + bad tick | 0% red, 19.5% ticked | **1 cell ticked** |
///
/// So worst-wins over-states damage by an order of magnitude and majority
/// alone hides it completely; the third rule does neither, which is why it is
/// the one both apps implement. Ground for the PROPORTION, tick for the
/// PRESENCE, and the census under the map for the exact numbers.
///
/// Chip C (the Windows lane) argued for worst-wins on 12 Sep 2026, from the
/// correct premise that a merged cell must never hide a bad block. That
/// premise is what the tick satisfies. Do not "simplify" this back to one
/// rule without re-running the table above.
public enum BlockMapRule {

    /// How much a state matters when two are tied, and the order the hover
    /// readout lists them in. Not a severity ranking of the DATA - a ranking
    /// of what the user needs to see first.
    public static func rank(_ state: BlockState) -> Int {
        switch state {
        case .present: return 0
        case .pending: return 1
        case .hashing: return 2
        case .misnamed: return 3
        case .damaged: return 4
        case .missing: return 5
        }
    }

    /// A state is "bad" when it means data the set does not have where it
    /// expects it. MISNAMED IS NOT BAD: the data is on the disk under another
    /// name, it costs no recovery blocks, and painting it as damage makes a
    /// set two renames from perfect look nearly lost.
    public static func isBad(_ state: BlockState) -> Bool {
        switch state {
        case .damaged, .missing: return true
        case .present, .pending, .hashing, .misnamed: return false
        }
    }

    /// The half-open block range a merged cell covers.
    public static func range(column: Int, of columns: Int, blocks: Int) -> ClosedRange<Int> {
        let first = blocks * column / columns
        let last = max(first, blocks * (column + 1) / columns - 1)
        return first...min(last, blocks - 1)
    }

    /// The cell's ground colour: the most common state in its range, ties
    /// going to the one that matters more.
    public static func ground(_ states: [BlockState], in range: ClosedRange<Int>) -> BlockState {
        if range.lowerBound == range.upperBound { return states[range.lowerBound] }
        var counts = [Int](repeating: 0, count: BlockState.allCases.count)
        for i in range { counts[Int(states[i].rawValue)] += 1 }
        var best = BlockState.pending
        var bestCount = -1
        for state in BlockState.allCases {
            let n = counts[Int(state.rawValue)]
            if n > bestCount || (n == bestCount && rank(state) > rank(best)) {
                best = state
                bestCount = n
            }
        }
        return best
    }

    /// The tick along the bottom of the cell: the worst BAD state in the
    /// range, or nil when the range holds none. This is what stops the
    /// majority ground from hiding a single bad block in forty.
    public static func badMark(_ states: [BlockState], in range: ClosedRange<Int>) -> BlockState? {
        var worst: BlockState?
        for i in range {
            let s = states[i]
            guard isBad(s) else { continue }
            if worst == nil || rank(s) > rank(worst!) { worst = s }
        }
        return worst
    }

    /// How many blocks one merged cell covers, or nil when that is not yet
    /// knowable.
    ///
    /// NIL IS THE POINT. The caller's column count comes from a `@State`
    /// that `onAppear` fills in, so on the first render pass it is still
    /// zero - and the arithmetic that used to live at the call site,
    /// `blocks / max(1, columns)`, turns a zero column count into a
    /// per-cell figure of `blocks`. On the ten thousand block acceptance
    /// scenario that rendered as "each one covers 10,000 blocks" beside a
    /// map of about fourteen hundred cells: not a rounding error, the
    /// TOTAL, printed as if it were the per-cell count. Found 12 Sep 2026
    /// by the QA lane grading that scenario's screenshot against the
    /// corpus's measured numbers.
    ///
    /// A count is returned only when it can be computed, so a caller that
    /// has no columns yet shows NOTHING rather than something wrong. The
    /// floor of 2 is kept from the original: a merged map by definition
    /// has more blocks than cells, so a per-cell count of one means the
    /// division rounded down and two is the honest smallest answer.
    public static func blocksPerCell(blocks: Int, columns: Int) -> Int? {
        guard blocks > 0, columns > 0 else { return nil }
        return max(2, blocks / columns)
    }

    /// Minimum width, in POINTS, of any mark that says "something is wrong
    /// here". Chip C's finding, and it is the same defect as hiding the mark
    /// outright: a sub-pixel rectangle antialiases to nearly nothing, so a
    /// lone damaged cell can be drawn and still be invisible. Two points is
    /// two device pixels at 1x and four at 2x.
    public static let minimumMarkWidth: Double = 2
}
