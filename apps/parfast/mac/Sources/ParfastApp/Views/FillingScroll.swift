import SwiftUI

/// A scroll view whose content is at least as tall as the space it was given.
///
/// The empty states are whole-content-area drop zones (plan 5.1), and a plain
/// ScrollView hands its content the content's own intrinsic height - so a drop
/// zone asking for `maxHeight: .infinity` collapses to the height of its text.
/// This is the one place that is fixed.
struct FillingScroll<Content: View>: View {
    @ViewBuilder var content: () -> Content

    var body: some View {
        GeometryReader { geo in
            ScrollView {
                content()
                    // TOP aligned: a min-height frame centres its content by
                    // default, which floated every screen in the middle of the
                    // window and looked like a layout bug.
                    .frame(minHeight: geo.size.height, alignment: .top)
            }
        }
    }
}
