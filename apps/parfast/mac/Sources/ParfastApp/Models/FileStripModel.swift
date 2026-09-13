import Foundation
import ParfastCore

/// One merged cell of a row strip: which blocks it covers, what it is grounded
/// in, and whether anything bad is hiding inside it.
///
/// The mac block map draws straight from `BlockMapRule` inside its `Canvas` and
/// never needed a cell type; a row strip does, because the cells are cut in the
/// model (where they can be compared between snapshots and tested) and drawn in
/// the view. It carries exactly what the two of those need and nothing else.
struct FileStripCell: Hashable {
    /// First block of the range, in the FILE's own numbering.
    var first: Int
    var length: Int
    /// The majority state, which carries the proportion.
    var ground: BlockState
    /// The worst bad state in the range, which carries the presence, or nil.
    var badMark: BlockState?
}

/// One file table row's slice of the block map: the same blocks, the same rule, a
/// sixth of the height.
///
/// Section 4 of the 12 September 2026 prettiness review, chart (c), and the
/// SwiftUI half of `Parfast.ViewModels/FileStripModel.cs`.
///
/// WHAT IT IS FOR. The file table carries `29 / 32` as text and the big strip
/// above carries the whole set as one run, so nothing on the screen connected a
/// damaged run to the file it lives in: the reader could see that three blocks
/// were bad and which file was damaged, and had to take on trust that they were
/// the same three. A per-row strip is that connection, and it is free - it is
/// literally the file's own slice of the strip already drawn above it.
///
/// THE SLICE IS DERIVED, WHICH IS WHY IT CANNOT DISAGREE WITH THE BIG MAP.
/// `survey.block_runs` is one strip over the source blocks in SET order, and the
/// engine builds it by walking the members in `survey.files` order and pushing
/// each member's blocks in turn (`survey.rs`'s `push_blocks` inside the loop over
/// targets; `MockCore.surveyFor` does the same with an explicit `cursor`). So a
/// member's blocks are the contiguous range starting at the sum of the preceding
/// members' `blocks_total`, and this type does no decoding, no re-derivation and
/// no second reading of the states - it takes the array the map already expanded
/// and cuts it.
///
/// IT IS CUT OVER THE UNFILTERED SURVEY LIST, AND THAT IS LOAD-BEARING. The
/// offsets are a running sum, so the Problems only filter - which removes rows
/// from the TABLE - must not come near them. Cutting over the filtered list would
/// slide every surviving strip onto some other file's blocks and draw a confident
/// picture of the wrong file. `VerifyModel.strips` is keyed BY NAME for exactly
/// this reason: the table looks a row's strip up, the cut never sees the filter.
///
/// AND IT REFUSES RATHER THAN GUESSING. If the members' `blocks_total` do not add
/// up to the strip's length the offsets mean nothing, so `build` answers nil for
/// every row and the rows keep the figure they had before this existed. A
/// plausible strip beside the wrong name reads as information; a blank cell in a
/// table does not read as a broken screen the way a blank signature visual does.
///
/// A REPAIR'S PRE-FOLD SURVEY reports how many of a member's blocks are present
/// rather than which, so its present blocks are drawn first (API.md). The slice is
/// then honest about the COUNT and arbitrary about the POSITION, exactly as the
/// big map above it is - which is the property that matters: the two pictures are
/// the same picture.
///
/// ONE THING IS DELIBERATELY NOT PORTED, and it is worth saying which. The Windows
/// version takes the PREVIOUS strips and hands the same INSTANCE back for a row
/// whose picture has not moved, because over there a row strip lives in a
/// `DataTemplate` whose dependency property only repaints on a reference change -
/// so "always a new instance" repaints a settled table ten times a second and
/// "never a new instance" never repaints at all. SwiftUI's mechanism is the
/// opposite one: a view is a value rebuilt every pass and redrawn only where its
/// inputs COMPARE unequal. So the mac answer to the same problem is `Equatable` on
/// this type and on its cells, and adding an instance cache on top would buy
/// nothing and give the value semantics somewhere to go wrong. Port the reasoning,
/// not the mechanism.
struct FileStripModel: Equatable {

    /// How many cells a row strip is cut into.
    ///
    /// The Blocks column is a fixed width in the file table, so the budget is
    /// fixed too: about 112 points of strip at two points a cell. The view
    /// stretches the cells it is given to whatever width it actually has, which is
    /// honest for a proportional strip, and floors a bad tick at
    /// `BlockMapRule.minimumMarkWidth` the same way the big map does.
    ///
    /// IT IS A CEILING AND NOT A TARGET: a member with eight blocks gets eight
    /// cells, not fifty-six, because `BlockMapRule.range` is used for both paths
    /// and a cell is never smaller than a block.
    static let targetCells = 56

    /// The cells to draw, left to right.
    private(set) var cells: [FileStripCell]
    /// How many source blocks this member owns.
    private(set) var blocks: Int
    /// How many of them the set has, from the row's own census.
    private(set) var ok: Int
    /// How many of them are damaged or missing, counted from the slice.
    private(set) var bad: Int

    /// The help text, and the text VoiceOver gets instead of the strip.
    func accessibleSummary() -> String {
        S.verifyFileStripSummary(ok: Fmt.count(ok), total: Fmt.count(blocks))
    }

    /// Cuts one strip per member of `files`, keyed by name, or an EMPTY table when
    /// the members' block totals do not reconcile with `setStates`.
    ///
    /// - Parameters:
    ///   - setStates: The expanded set-wide block states - `Survey.expandedStates()`,
    ///     the same array the big map draws, walked once here rather than per row.
    ///   - files: The survey's files, IN SURVEY ORDER and UNFILTERED. See the
    ///     type's own note: passing the table's filtered rows here is the one way
    ///     to make this chart lie.
    ///
    /// Keyed by name rather than positional, because the table sorts and filters
    /// its rows and a positional array would have to be re-indexed at the call
    /// site - which is the same offset arithmetic this type exists to keep in one
    /// place. `SurveyFile.id` is the name already, so the table's row identity and
    /// this key are the same thing.
    static func build(setStates: [BlockState],
                      files: [SurveyFile]) -> [String: FileStripModel] {
        guard !files.isEmpty, !setStates.isEmpty else { return [:] }

        // THE RECONCILIATION, and it is the whole guard. The offsets are a running
        // sum of blocks_total, so they are only meaningful if that sum IS the
        // strip.
        let owed = files.reduce(0) { $0 + max(0, $1.blocks_total) }
        guard owed == setStates.count else { return [:] }

        var strips: [String: FileStripModel] = [:]
        var offset = 0
        for file in files {
            let blocks = max(0, file.blocks_total)
            // An extra file owns no source blocks and must still appear in the
            // table, so it gets NO strip rather than an empty one.
            guard blocks > 0 else { continue }
            strips[file.name] = cut(setStates, offset: offset, blocks: blocks,
                                    ok: max(0, file.blocks_ok))
            offset += blocks
        }
        return strips
    }

    private static func cut(_ setStates: [BlockState], offset: Int, blocks: Int,
                            ok: Int) -> FileStripModel {
        // The slice is copied once, per member, so `BlockMapRule` sees indices
        // 0..<blocks and the cells it produces are the FILE's block numbers rather
        // than the set's. One copy of the set in total, which is what the big map
        // already pays for its own expansion.
        let slice = Array(setStates[offset..<min(setStates.count, offset + blocks)])
        guard !slice.isEmpty else {
            return FileStripModel(cells: [], blocks: blocks, ok: ok, bad: 0)
        }

        let count = min(targetCells, slice.count)
        var cells: [FileStripCell] = []
        cells.reserveCapacity(count)
        var bad = 0
        for c in 0..<count {
            let range = BlockMapRule.range(column: c, of: count, blocks: slice.count)
            for i in range where BlockMapRule.isBad(slice[i]) { bad += 1 }
            cells.append(FileStripCell(
                first: range.lowerBound,
                length: range.count,
                ground: BlockMapRule.ground(slice, in: range),
                badMark: BlockMapRule.badMark(slice, in: range)))
        }
        return FileStripModel(cells: cells, blocks: blocks, ok: ok, bad: bad)
    }
}
