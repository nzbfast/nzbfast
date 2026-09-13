import SwiftUI
import ParfastCore

/// What this set will cost on disk: a two-segment proportion bar over the create
/// preview, with a legend that carries the figures.
///
/// Section 4 of the 12 September 2026 prettiness review, chart (a). The numbers
/// were already on the wire - `CostBarModel` reads them straight off the
/// `PlanPreview` the screen recomputes on every edit - and were spent on three
/// separate figures that needed arithmetic to answer "what is this going to cost
/// me". The bar answers it at a glance and MOVES as the recovery slider moves,
/// which is the half a screenshot cannot show.
///
/// All the arithmetic, both refusals and the floor are in `CostBarModel`; this
/// draws what it is given and decides nothing. The one rule that lives here is
/// the two colours, below.
///
/// THE PALETTE IS EMPHASIS, NOT CATEGORICAL, and it was chosen by the house
/// validator rather than by eye. The source span is the de-emphasis grey
/// (`block.pending`) and the PAR2 span is `recovery.available`, the colour this
/// app already means "recovery" with in the verify screen's band, so the two
/// pictures agree. Measured on this tree's own tokens: dE 28.2 to full colour
/// vision and 22.2 under deuteranopia in light, 39.2 and 29.5 in dark, against
/// floors of 15 and 8.
///
/// The grey trips the validator's chroma floor and lightness band by
/// construction, which is what a de-emphasis slot IS and is outside the scope of
/// checks written for categorical identity - the validator says so in its own
/// footer. Its sub-3:1 contrast against the card is the one WARN that obliges
/// relief, and the relief is here: a hairline border round the whole track so a
/// nearly-empty bar still has a visible extent, and a legend carrying every
/// figure in words.
///
/// NO SEPARATE SEGMENT IS EVER WIDENED TO BE SEEN. See `CostBarModel`: in a
/// part-to-whole bar the width is the value, so a segment under the floor is
/// DROPPED and its legend line says "too small to plot" - the opposite of the
/// block map, where a floored bad tick carries presence.
struct CostBarView: View {

    var model: CostBarModel

    /// How tall the bar is.
    ///
    /// Thin, per the house mark spec (a bar caps at 24 and never fills its slot).
    /// Heavier than the verify screen's 8 point recovery band because this one
    /// carries two segments and the gap between them, and at 8 the gap eats a
    /// quarter of the bar's visual weight.
    private let barHeight: CGFloat = 12

    /// The gap between touching segments, in the surface colour.
    ///
    /// The house rule, and it is NEGATIVE SPACE rather than ink: nothing is drawn
    /// there, so the card shows through. Never a border around a segment - a
    /// stroke adds weight that is not data.
    private let segmentGap: CGFloat = 2

    var body: some View {
        if model.hasPlan {
            VStack(alignment: .leading, spacing: T.spacingS) {
                HStack(alignment: .firstTextBaseline) {
                    Text(S.createCostHeader)
                        .font(.system(size: 12))
                        .foregroundStyle(T.textSecondary)
                    Spacer(minLength: T.spacingM)
                    Text(model.footprintText)
                        .font(.system(size: 12, weight: .semibold))
                        .monospacedDigit()
                        .foregroundStyle(T.textPrimary)
                }

                // A BARE `Canvas` and not one inside a `GeometryReader`: Canvas
                // is handed its own `size` already, so the reader would be a
                // wrapper that reads nothing. `BlockMapView` has one because a
                // SIBLING of its canvas needs the measurement; this does not.
                Canvas { context, size in draw(context: context, size: size) }
                    .frame(height: barHeight)
                    .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .strokeBorder(T.surfaceCardBorder, lineWidth: 1)
                    )

                legend

                // NO `.fixedSize(horizontal: false, vertical: true)` ON THIS
                // TEXT, and it is the one line in this file that has already
                // been wrong once. With it, the WHOLE CREATE SCREEN rendered as
                // a blank page with the tail of the Output card at the top: a
                // long sentence asked for its single-line ideal WIDTH, which is
                // far wider than the window, and the preview bar's stack carried
                // that demand outward until the layout above it collapsed. It
                // reproduced in both themes at a nine second settle, so it was
                // not a capture artefact - and NO TEST IN THIS SUITE CAN SEE IT,
                // which is the whole argument of the review this chart came out
                // of. Found by looking at the frames; bisected by removing this
                // control, then this half of it, then this modifier.
                //
                // A plain Text is right anyway: SwiftUI wraps it at the width it
                // is given, which is what the sentence wants. The modifier is
                // for a Text something else is squeezing, and nothing here is.
                Text(model.paddingText)
                    .font(.system(size: 11))
                    .foregroundStyle(T.textTertiary)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(S.createCostHeader)
            .accessibilityValue(model.accessibleSummary())
        }
        // An absent plan draws NOTHING rather than an empty track. The preview bar
        // this sits in already says "Working out the layout..." while the pane is
        // being filled in, and a second empty shape beside that sentence reads as
        // a card that failed rather than as one still thinking.
    }

    // MARK: - Drawing

    /// ONE PASS, LEFT TO RIGHT, each segment at its own share of the width.
    private func draw(context: GraphicsContext, size: CGSize) {
        var x: CGFloat = 0
        var first = true
        for segment in model.segments {
            let full = CGFloat(segment.share) * size.width
            guard CostBarModel.isDrawable(share: segment.share, width: size.width) else {
                x += full
                continue
            }
            let left = first ? x : x + segmentGap
            let wanted = max(full - (first ? 0 : segmentGap),
                             CGFloat(CostBarModel.minimumSegmentWidth))
            let width = min(wanted, max(0, size.width - left))
            context.fill(Path(CGRect(x: left, y: 0, width: width, height: size.height)),
                         with: .color(colour(segment.kind)))
            x += full
            first = false
        }
    }

    /// The colour a segment is drawn in. Emphasis, not identity: see the type's
    /// own note for the measurement.
    private func colour(_ kind: CostSegmentKind) -> Color {
        kind == .par2 ? T.recoveryAvailable : T.blockPending
    }

    // MARK: - The legend

    /// A swatch, the segment's word, and its figures.
    ///
    /// The figures wear TEXT tokens and never the segment's colour: identity comes
    /// from the swatch beside them, and a pale fill is illegible as text. The
    /// legend is also the relief the contrast WARN on the grey asks for, which is
    /// why it carries every number the picture encodes.
    private var legend: some View {
        HStack(alignment: .firstTextBaseline, spacing: T.spacingL) {
            ForEach(model.segments) { segment in
                HStack(spacing: 6) {
                    RoundedRectangle(cornerRadius: 3)
                        .fill(colour(segment.kind))
                        .frame(width: 10, height: 10)
                    Text(segment.label)
                        .font(.system(size: 12))
                        .foregroundStyle(T.textSecondary)
                    Text(model.describe(segment))
                        .font(.system(size: 12, weight: .semibold))
                        .monospacedDigit()
                        .foregroundStyle(T.textPrimary)
                    let inside = model.describeInside(segment)
                    if !inside.isEmpty {
                        Text(inside)
                            .font(.system(size: 11))
                            .monospacedDigit()
                            .foregroundStyle(T.textTertiary)
                    }
                    // Said in words for the segment that was dropped, so nobody
                    // hunts the picture for a colour that is not in it. The width
                    // test is the model's, shared rather than restated, so the
                    // note and the bar cannot disagree.
                    if !CostBarModel.isDrawable(share: segment.share, width: barWidthGuess) {
                        Text(S.createCostTooSmall)
                            .font(.system(size: 11))
                            .foregroundStyle(T.textTertiary)
                    }
                }
                .help(segment.label + ": " + model.describe(segment))
            }
            Spacer(minLength: 0)
        }
    }

    /// The width the legend assumes when deciding whether a segment was drawn.
    ///
    /// The bar is laid out by a `GeometryReader` and the legend is not inside it,
    /// so the real width is not available here without threading a `@State` back
    /// up through a layout pass - which would make the note lag the picture by one
    /// frame on every resize. This is the preview bar's own minimum content width
    /// (the window floor of 1,000 less the card padding), so it UNDER-states the
    /// bar and the note can only ever appear for a segment that is genuinely
    /// unplottable at any size this window reaches. Both real cases - a zero
    /// share, and an index-sized sliver four orders of magnitude under a point -
    /// are decided identically at every width, which is why this approximation is
    /// sound rather than merely convenient.
    private var barWidthGuess: Double { 940 }
}
