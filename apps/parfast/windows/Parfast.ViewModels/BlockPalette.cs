using Parfast.Core.Contracts;

namespace Parfast.ViewModels;

/// <summary>
/// The one mapping from a block state to the colour and the word that describe it.
/// </summary>
/// <remarks>
/// It is a thin layer over the generated <see cref="Tokens.Block"/> now, and that
/// is the point: chip B's shared tokens file carries, per state, both colours AND
/// the wire code from <c>survey.block_runs</c> AND the legend word. So the strip,
/// the legend and the hover text all resolve through one table that both apps
/// generate from, and the hand-written legend this file used to carry is gone.
/// A legend that can disagree with the strip it explains is worse than no legend.
/// <para>
/// This layer still earns its place for one reason: it maps the C# enum to the
/// token by WIRE CODE rather than by name, so a state the shared file renames
/// still resolves, and a state this build has never heard of falls back to
/// pending instead of throwing inside a 10 Hz redraw.
/// </para>
/// </remarks>
public static class BlockPalette
{
    public static BlockToken Token(BlockState state) => Tokens.Block.ForCode((int)state);

    public static TokenColor For(BlockState state, bool dark) => Token(state).For(dark);

    /// <summary>
    /// The colour a RUN is GROUNDED in, which is not always the colour that names its
    /// state.
    /// </summary>
    /// <remarks>
    /// A present run is drawn in the washed <c>map.present_ground</c> token rather than
    /// at full strength, and every other state keeps its own colour. The point is to
    /// put the ink where the information is: a set is almost always overwhelmingly
    /// present, so painting that at full saturation spends the whole strip on the news
    /// that nothing is wrong and leaves the damage - the only thing anyone opened the
    /// app to find - as a hairline against it. Washed, the damaged and missing marks
    /// are the only saturated thing in the card and they read instantly.
    /// <para>
    /// It is also what makes the palette legible rather than merely calmer. Present at
    /// full strength against the misnamed amber measures dE 5.1 to a protanope, under
    /// the floor at which two colours are tellable apart at all; washed, the worst pair
    /// in the map is 12.7 and every pair passes in both themes. The prettiness fix and
    /// the accessibility fix turned out to be the same change.
    /// </para>
    /// <para>
    /// DAMAGED, MISSING AND MISNAMED ARE NEVER WASHED. They are small marks, and the
    /// house guidance reserves saturation for exactly that: saturated fills are for
    /// small marks and accents, never large blocks.
    /// </para>
    /// <para>
    /// IT LIVES HERE BECAUSE THERE ARE THREE CALLERS NOW - the block map, the key
    /// under it, and the per-row mini strip in the file table - and a key or a row
    /// strip whose green is twice the green of the strip it explains is exactly the
    /// disagreement this class exists to prevent. It was written out at each of the
    /// first two sites and the third would have been a third copy.
    /// </para>
    /// </remarks>
    public static TokenColor Ground(BlockState state, bool dark) =>
        state == BlockState.Present ? Tokens.Map.PresentGround(dark) : For(state, dark);

    public static string Label(BlockState state) => Token(state).Label;

    public static TokenColor Recovery(bool dark) => Tokens.Recovery.Available(dark);

    public static TokenColor RecoverySpare(bool dark) => Tokens.Recovery.Spare(dark);

    public static TokenColor NeededMarker(bool dark) => Tokens.Recovery.Needed(dark);

    /// <summary>The status pill's ground and the text that goes on it.</summary>
    public static (TokenColor Fg, TokenColor Bg) Pill(PillTone tone, bool dark) => tone switch
    {
        PillTone.Busy => (Tokens.Status.OnWorking(dark), Tokens.Status.Working(dark)),
        PillTone.Good => (Tokens.Status.OnGood(dark), Tokens.Status.Good(dark)),
        PillTone.Warn => (Tokens.Status.OnWarn(dark), Tokens.Status.Warn(dark)),
        PillTone.Bad => (Tokens.Status.OnBad(dark), Tokens.Status.Bad(dark)),
        _ => (Tokens.Status.OnNeutral(dark), Tokens.Status.Neutral(dark)),
    };

    /// <summary>
    /// The legend under the block map, in wire-code order, straight from the
    /// shared tokens file. Pending is left out: "not read yet" is the ground the
    /// strip starts as, and naming it in the key invites the reader to hunt for a
    /// colour that means nothing is wrong.
    /// </summary>
    public static IReadOnlyList<BlockToken> Legend { get; } =
        Tokens.Block.All.Where(t => t.Code != (int)BlockState.Pending).ToList();
}
