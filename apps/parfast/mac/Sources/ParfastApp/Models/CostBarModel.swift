import Foundation
import ParfastCore

/// Which quantity a segment of the cost bar stands for.
enum CostSegmentKind: Hashable {
    /// The files being protected, which are already on the disk.
    case source
    /// Every byte the create writes: the index file and the recovery volumes.
    case par2
}

/// One segment of the cost bar: what it is, how big, and its share of the whole.
struct CostBarSegment: Hashable, Identifiable {
    var kind: CostSegmentKind
    /// The legend word, from the shared copy table.
    var label: String
    var bytes: Int64
    /// Its fraction of `CostBarModel.footprintBytes`, 0 to 1.
    var share: Double

    var id: CostSegmentKind { kind }
}

/// What a create will cost on disk, as a two-segment part-to-whole bar: the
/// source files it protects, then the PAR2 set it writes beside them.
///
/// Section 4 of the 12 September 2026 prettiness review, chart (a), and the
/// SwiftUI half of `Parfast.ViewModels/CostBarModel.cs` - same arithmetic, same
/// two refusals, same copy keys, so the two apps draw the same picture.
///
/// The numbers are `PlanPreview`'s and are recomputed on every edit for the
/// Create screen's live preview, so the bar moves as the recovery slider moves.
/// Before this existed they were spent on three separate figures - a padding
/// size, an efficiency percentage and a "N files, X GiB" caption - none of which
/// answers "what is this going to cost me" without arithmetic.
///
/// Everything here is pure; `CostBarView` does the drawing. Same split as the
/// block map, and for the same reason: this is what the tests can assert on.
///
/// THE WHOLE IS source + PAR2, NOT source ALONE, and the difference shows on
/// screen. `recovery_percent` is parity as a share of the SOURCE blocks, so a
/// ten per cent set draws 9.1 per cent of this bar. A reader who checks one
/// figure against the other would find them disagreeing if the bar claimed to be
/// the recovery percentage. It does not: the caption names the footprint the bar
/// is a proportion OF, and the recovery percentage keeps its own figure in the
/// Recovery card where it belongs. Do not "reconcile" the two.
///
/// TWO QUANTITIES ARE DELIBERATELY NUMBERS AND NOT SEGMENTS.
///
///  1. **Padding is not a disk cost at all.** `padding_bytes` is the zero fill in
///     the last block of each member - the engine's own words, "the slice grid is
///     per FILE, so this is the sum of every member's own remainder". It is what
///     the parity is computed OVER and is never written anywhere, so a segment for
///     it inside a footprint bar would count bytes that do not exist. It is
///     reported beside the bar WITH that reason, at every size, because there is
///     no width at which drawing it becomes honest.
///  2. **The index file is real and is always sub-pixel.** It is
///     `total_bytes - recovery_bytes`: the critical packets plus twenty bytes per
///     block. On a 2 GiB set over 2,000 blocks that is ~40 KiB against 2.2 GiB =
///     0.01 of ONE PIXEL on a 600 point bar. It rides inside the PAR2 segment and
///     is named in that segment's own legend line.
///
/// THE FLOOR HERE DROPS A SEGMENT WHERE THE BLOCK MAP'S FLOOR WIDENS A MARK, and
/// the two rules are opposite on purpose. `BlockMapRule.minimumMarkWidth` widens a
/// bad tick because that mark's job is PRESENCE and the ground beside it carries
/// the proportion. In a part-to-whole bar the width IS the value, so widening
/// lies - flooring a 40 KiB index to a visible two points overstates it by four
/// orders of magnitude.
///
/// WHY TWO SEGMENTS AND NOT THREE, measured rather than argued. The Windows lane's
/// first version drew source, recovery and index as three, in the pending grey,
/// the recovery pink and `recovery.spare`. The house palette validator refused it:
/// the grey against the pale pink measures dE 5.9 to FULL colour vision and 2.2 to
/// a protanope, against floors of 15 and 8. Dropping the index segment - which the
/// arithmetic above says was never drawable - leaves one pair at dE 28.2 normal
/// and 22.2 deutan. Re-run here on this tree's own tokens before this was written,
/// same numbers, plus 39.2 / 29.5 in dark. The accessibility fix and the
/// arithmetic fix were the same fix.
struct CostBarModel {

    /// Narrowest segment, in POINTS, that this bar will draw.
    ///
    /// Three rather than the block map's two, and for the opposite reason - see
    /// the type's own note on the two floors. Three is where a filled sliver stops
    /// reading as a colour and starts reading as an edge artefact of its
    /// neighbour.
    static let minimumSegmentWidth: Double = 3

    private var preview: PlanPreview?

    /// The segments, in drawing order, or empty when there is no plan.
    private(set) var segments: [CostBarSegment] = []

    /// What is on the disk after the create: the sources plus the PAR2 set.
    private(set) var footprintBytes: Int64 = 0

    init(_ preview: PlanPreview? = nil) {
        update(preview)
    }

    /// True once there is a plan worth drawing.
    var hasPlan: Bool { footprintBytes > 0 && !segments.isEmpty }

    /// The caption over the bar: the footprint it is a proportion of.
    var footprintText: String { hasPlan ? Fmt.bytes(footprintBytes) : "" }

    /// The PAR2 set's share of the footprint, which is the headline this bar
    /// exists to give at a glance.
    var par2Share: Double { segments.first { $0.kind == .par2 }?.share ?? 0 }

    /// The padding note, or an empty string when there is no plan.
    ///
    /// It carries the REASON padding is not in the bar, because a figure sitting
    /// beside a part-to-whole picture reads as a part somebody forgot to draw.
    var paddingText: String {
        guard hasPlan, let preview else { return "" }
        return S.createCostPadding(bytes: Fmt.bytes(preview.padding_bytes),
                                   percent: Fmt.percent(preview.padding_pct, decimals: 2))
    }

    /// Whether a segment of this share is wide enough to draw honestly in a bar of
    /// this point width.
    ///
    /// Static and shared with the view rather than restated there, so the legend's
    /// "too small to plot" note and the bar's own decision to skip a segment can
    /// never disagree - the case where they did would be a reader hunting the
    /// picture for a colour that is not in it.
    static func isDrawable(share: Double, width: Double) -> Bool {
        share > 0 && share * width >= minimumSegmentWidth
    }

    /// Rebuilds from a fresh plan preview.
    mutating func update(_ preview: PlanPreview?) {
        self.preview = preview
        guard let preview else {
            footprintBytes = 0
            segments = []
            return
        }

        // A plan with no sources and a plan mid-edit both arrive here, and both
        // have to leave the bar EMPTY rather than drawing a 100 per cent
        // something: the Create screen's preview is filled in left to right and a
        // full bar over no files is a claim.
        let source = max(0, preview.source_bytes ?? 0)
        let par2 = max(0, preview.total_bytes)
        footprintBytes = source + par2
        guard footprintBytes > 0, preview.block_count > 0 else {
            footprintBytes = 0
            segments = []
            return
        }

        let whole = Double(footprintBytes)
        segments = [
            CostBarSegment(kind: .source, label: S.createCostSource, bytes: source,
                           share: Double(source) / whole),
            CostBarSegment(kind: .par2, label: S.createCostPar2, bytes: par2,
                           share: Double(par2) / whole),
        ]
    }

    /// The legend line for a segment: its size, and its share of the footprint.
    ///
    /// `Fmt.percent` takes a figure ALREADY out of a hundred and does not clamp,
    /// so the share is scaled here. (This is the mac spelling of the Windows
    /// `Fmt.Pct` / `Fmt.Percent` trap: over there the unscaled-and-clamping one is
    /// the default-looking name.)
    func describe(_ segment: CostBarSegment) -> String {
        S.createCostSegment(bytes: Fmt.bytes(segment.bytes),
                            percent: Fmt.percent(segment.share * 100, decimals: 1))
    }

    /// What rides inside the PAR2 segment, for that segment's second legend line,
    /// or an empty string for any other segment.
    ///
    /// The index file is the difference between what the create WRITES and the
    /// parity inside it, and this is where it is accounted for rather than drawn.
    func describeInside(_ segment: CostBarSegment) -> String {
        guard segment.kind == .par2, hasPlan, let preview else { return "" }
        let index = max(0, preview.total_bytes - preview.recovery_bytes)
        return S.createCostPar2Inside(parity: Fmt.bytes(preview.recovery_bytes),
                                      index: Fmt.bytes(index))
    }

    /// The sentence a screen reader gets instead of the picture, the same way the
    /// block map answers (plan 5.7).
    func accessibleSummary() -> String {
        guard hasPlan, let preview else { return S.createCostNoPlan }
        return S.createCostSummary(
            source: Fmt.bytes(preview.source_bytes ?? 0),
            par2: Fmt.bytes(preview.total_bytes),
            share: Fmt.percent(par2Share * 100, decimals: 1),
            total: Fmt.bytes(footprintBytes))
    }
}
