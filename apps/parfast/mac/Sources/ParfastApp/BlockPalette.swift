import SwiftUI
import ParfastCore

/// The one mapping from a block state to the colour the map actually paints it.
///
/// IT LIVES HERE, NOT IN `ParfastCore`. The rule is a sibling of
/// `ParfastCore.BlockMapRule` and belongs beside it by subject, but `ParfastCore`
/// is deliberately UI-free - no `import SwiftUI` anywhere in it - and `T` is
/// generated into `ParfastApp`. Moving a `Color`-returning function down would
/// drag SwiftUI and the whole token table into a layer whose point is not having
/// them, which is a worse change than the duplication it prevents. The Windows
/// app resolves it the same way for the same reason: `BlockPalette.Ground` sits
/// in `Parfast.ViewModels`, the layer that has the tokens, and not in
/// `Parfast.Core.Contracts`.
enum BlockPalette {

    /// The colour a RUN is GROUNDED in, which is not always the colour that
    /// names its state.
    ///
    /// A present run takes the washed `map.present_ground` token rather than the
    /// full-strength green, and every other state keeps its own. A set is almost
    /// always overwhelmingly present, so painting that at full saturation spends
    /// the whole strip saying nothing is wrong and leaves the damage - the only
    /// thing anyone opened the app to find - as a hairline against it.
    ///
    /// It is also what makes the palette legible rather than merely calmer.
    /// Present at full strength beside the misnamed amber measures dE 5.1 to a
    /// protanope, under the floor at which two colours are tellable apart at
    /// all; washed, the worst pair in the map is 12.7 and every pair passes in
    /// both themes. The prettiness fix and the accessibility fix were the same
    /// change.
    ///
    /// Damaged, missing and misnamed are never washed: they are small marks and
    /// are meant to be loud.
    ///
    /// WHY IT IS A SHARED FUNCTION AND NOT A LINE AT EACH SITE. It was written
    /// out inside `BlockMapView` with two callers - the strip's draw and the key
    /// under it - and a third site is now foreseeable: the per-file mini block
    /// strip in the verify file table, which the Windows app has already built.
    /// The Windows lane hit exactly this and hoisted the rule when its third
    /// caller arrived. A key, or a row strip, whose green is twice the green of
    /// the strip it explains is the disagreement this function exists to
    /// prevent - and because the failure is a drifted COLOUR rather than a wrong
    /// number, no test in this repo can see it. Call it; never restate it.
    static func ground(_ state: BlockState) -> Color {
        state == .present ? T.mapPresentGround : T.blockPalette[Int(state.rawValue)]
    }
}
