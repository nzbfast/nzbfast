import SwiftUI
import ParfastCore

/// One file table row's own block strip: the same picture as the map above it,
/// cut to this member's blocks.
///
/// Section 4 of the 12 September 2026 prettiness review, chart (c). The table said
/// `29 / 32` and the strip above said where the damage was, and nothing joined the
/// two, so a reader had to take on trust that the three bad blocks in the strip
/// were the three the row was counting. This is that join, and it is drawn from
/// the SAME expanded states through the SAME `BlockMapRule`, so it cannot
/// disagree - see `FileStripModel` for how the slice is derived and for the
/// reconciliation that makes it refuse rather than guess.
///
/// A GROUND PLUS A BAD TICK, exactly as the big map draws: the majority state
/// carries the proportion and a tick along the bottom carries the presence,
/// floored at `BlockMapRule.minimumMarkWidth` so a lone damaged block in a hundred
/// is drawn rather than antialiased into nothing. Both of the obvious one-rule
/// alternatives fail silently in opposite directions and the measurement that
/// chose this one is in that type's header; this view re-derives none of it.
///
/// THE COLOUR RULE IS CALLED, NEVER RESTATED. `BlockPalette.ground(_:)` is where a
/// present run's washed ground lives, and it is washed because present at full
/// strength beside the misnamed amber measures dE 5.1 to a protanope - under the
/// floor at which two colours are tellable apart at all - while washed, the worst
/// pair in the map is 12.7 and every pair passes in both themes. A second copy of
/// `state == .present ? ...` here would be a silently inaccessible strip that no
/// test in either app could see. That is why the function exists and why this is
/// its third caller.
///
/// NO KEY OF ITS OWN. The block map's legend under the big strip already carries
/// the five states in wire-code order with counts, and a second key beside a four
/// point strip would be a duplicate that can drift from it.
///
/// THE COST IS BOUNDED BY THE COLUMN, not by the set. The model cuts at most
/// `FileStripModel.targetCells` cells and adjacent cells of one ground are merged
/// into a single fill first, so a clean member is ONE rectangle and the worst case
/// is a handful - the same bound the big map is built to.
struct MiniBlockStripView: View {

    var strip: FileStripModel

    /// How tall the strip is: a sixth of the signature map's height.
    ///
    /// A row strip is a supplement to the figure above it, not a second signature
    /// visual, and a table of twenty of them at the map's own 24 points would
    /// compete with the thing it is a detail of. Four points is the same weight as
    /// the hashing row's progress bar two columns to the left.
    private let stripHeight: CGFloat = 4

    /// How tall the bad tick is, in a strip this thin.
    private let tickHeight: CGFloat = 2

    var body: some View {
        Canvas { context, size in draw(context: context, size: size) }
            .frame(height: stripHeight)
            .clipShape(RoundedRectangle(cornerRadius: 1, style: .continuous))
            .help(strip.accessibleSummary())
            .accessibilityElement()
            .accessibilityLabel(strip.accessibleSummary())
    }

    private func draw(context: GraphicsContext, size: CGSize) {
        let cells = strip.cells
        guard !cells.isEmpty, size.width > 1 else { return }
        let count = CGFloat(cells.count)

        // Ground first, then ticks, and the ORDER IS THE RULE rather than a
        // convenience: a tick drawn before the next cell's ground would be covered
        // by it once the mark is widened to its floor.
        var start = 0
        while start < cells.count {
            let ground = cells[start].ground
            var end = start + 1
            while end < cells.count && cells[end].ground == ground { end += 1 }
            let x0 = CGFloat(start) / count * size.width
            let x1 = CGFloat(end) / count * size.width
            context.fill(
                Path(CGRect(x: x0, y: 0, width: max(x1 - x0, 1), height: size.height)),
                with: .color(BlockPalette.ground(ground)))
            start = end
        }

        for (index, cell) in cells.enumerated() {
            guard let bad = cell.badMark else { continue }
            var x0 = CGFloat(index) / count * size.width
            let width = max(CGFloat(index + 1) / count * size.width - x0,
                            CGFloat(BlockMapRule.minimumMarkWidth))
            x0 = min(x0, size.width - width)
            // The TICK is the raw palette and never the washed ground: damaged,
            // missing and misnamed are small marks and are meant to be loud. Same
            // pairing the big map draws.
            context.fill(
                Path(CGRect(x: max(0, x0), y: size.height - tickHeight,
                            width: width, height: tickHeight)),
                with: .color(T.blockPalette[Int(bad.rawValue)]))
        }
    }
}
