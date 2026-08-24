import AppKit

/// The menu bar glyph: the nzbfast bolt, as a template image.
///
/// The geometry is `packaging/icon/icon-small.svg` transcribed, not a
/// rasterised copy of it. That file is the SMALL art - bolt alone, no
/// slipstream, every corner blunted with a short quadratic so the tip
/// does not vanish at 16 px - and a menu bar item is exactly the size it
/// was drawn for. Transcribing keeps it vector at every backing scale,
/// which is the whole point of the split that master exists to make; a
/// PNG in Resources would need one file per scale and would still be a
/// downscale of art meant for 1024.
///
/// `isTemplate` means AppKit reads the ALPHA only and paints the result
/// itself, so this comes out black on a light menu bar, white on a dark
/// one, and inverts under the highlight when the menu is open. The fill
/// colour below is therefore arbitrary; do not add a stroke or a
/// gradient trying to control the appearance, both are discarded.
enum MenuBarIcon {
    /// The bolt in `icon-small.svg`'s 1024-unit space, as (point,
    /// quadratic control) pairs. A nil control is a straight line to the
    /// point. Kept in the source order of the `d` attribute so the two
    /// can be diffed by eye if the master is ever retraced.
    private static let bolt: [(NSPoint, NSPoint?)] = [
        (NSPoint(x: 432.7, y: 179.9), nil),  // M
        (NSPoint(x: 481.9, y: 149.5), NSPoint(x: 447.9, y: 149.5)),
        (NSPoint(x: 713.2, y: 149.5), nil),
        (NSPoint(x: 727.7, y: 177.3), NSPoint(x: 747.2, y: 149.5)),
        (NSPoint(x: 576.4, y: 394.0), nil),
        (NSPoint(x: 590.9, y: 421.8), NSPoint(x: 556.9, y: 421.8)),
        (NSPoint(x: 742.3, y: 421.8), nil),
        (NSPoint(x: 754.6, y: 453.9), NSPoint(x: 790.3, y: 421.8)),
        (NSPoint(x: 329.4, y: 836.1), nil),
        (NSPoint(x: 307.4, y: 819.2), NSPoint(x: 272.9, y: 886.9)),
        (NSPoint(x: 427.7, y: 583.3), nil),
        (NSPoint(x: 409.1, y: 553.0), NSPoint(x: 443.1, y: 553.0)),
        (NSPoint(x: 290.2, y: 553.0), nil),
        (NSPoint(x: 265.9, y: 513.6), NSPoint(x: 246.2, y: 553.0)),
    ]

    /// The bolt's extent in those units, including the control points -
    /// a quadratic stays inside the hull of (start, control, end), so
    /// the listed points bound the drawn curve exactly.
    private static let box = NSRect(x: 246.2, y: 149.5, width: 544.1, height: 737.4)

    /// Canvas 12 x 16 pt with a 14 pt bolt centred in it. The bar is 22
    /// pt tall and AppKit adds its own padding either side, so the glyph
    /// wants to be smaller than the canvas rather than filling it.
    static let image: NSImage = {
        let canvas = NSSize(width: 12, height: 16)
        let glyphHeight: CGFloat = 14
        let img = NSImage(size: canvas, flipped: false) { _ in
            let scale = min(canvas.width / box.width, glyphHeight / box.height)
            let dx = (canvas.width - box.width * scale) / 2
            let dy = (canvas.height - box.height * scale) / 2
            // SVG counts y downwards and AppKit counts it up, so the
            // mapper flips as it scales rather than leaving an upside
            // down bolt for a transform further down to fix.
            let p = { (q: NSPoint) -> NSPoint in
                NSPoint(
                    x: dx + (q.x - box.minX) * scale,
                    y: dy + (box.maxY - q.y) * scale)
            }
            let path = NSBezierPath()
            for (i, step) in bolt.enumerated() {
                if i == 0 {
                    path.move(to: p(step.0))
                } else if let control = step.1 {
                    quadCurve(path, to: p(step.0), control: p(control))
                } else {
                    path.line(to: p(step.0))
                }
            }
            path.close()
            NSColor.black.setFill()
            path.fill()
            return true
        }
        img.isTemplate = true
        return img
    }()

    /// A quadratic segment on an NSBezierPath, which only speaks cubic.
    /// The standard degree elevation: each cubic control sits two thirds
    /// of the way from its own end towards the quadratic's one control,
    /// which reproduces the curve exactly rather than approximating it.
    private static func quadCurve(_ path: NSBezierPath, to end: NSPoint, control q: NSPoint) {
        let start = path.currentPoint
        let lift = { (a: NSPoint) in
            NSPoint(x: a.x + 2 / 3.0 * (q.x - a.x), y: a.y + 2 / 3.0 * (q.y - a.y))
        }
        path.curve(to: end, controlPoint1: lift(start), controlPoint2: lift(end))
    }
}
