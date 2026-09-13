using Parfast.Core.Contracts;

namespace Parfast.ViewModels;

/// <summary>Which quantity a segment of the cost bar stands for.</summary>
public enum CostSegment
{
    /// <summary>The files being protected, which are already on the disk.</summary>
    Source,

    /// <summary>Every byte the create writes: the index file and the recovery volumes.</summary>
    Par2,
}

/// <summary>One segment of the cost bar: what it is, how big, and its share of the whole.</summary>
/// <param name="Kind">Which quantity.</param>
/// <param name="Label">The legend word, from the shared copy table.</param>
/// <param name="Bytes">The quantity itself.</param>
/// <param name="Share">Its fraction of <see cref="CostBarModel.FootprintBytes"/>, 0 to 1.</param>
public readonly record struct CostBarSegment(CostSegment Kind, string Label, long Bytes, double Share);

/// <summary>
/// What a create will cost on disk, as a two-segment part-to-whole bar: the
/// source files it protects, then the PAR2 set it writes beside them.
/// </summary>
/// <remarks>
/// The numbers are <see cref="PlanPreview"/>'s and are recomputed on every edit
/// for the Create screen's live preview, so the bar moves as the recovery slider
/// moves. Before this existed they were spent on three separate figures - a
/// padding size, an efficiency percentage and a "N files, X GiB" caption - none
/// of which answers "what is this going to cost me" without arithmetic.
/// <para>
/// Everything here is pure. <see cref="Parfast.App.Controls"/>'s CostBar does the
/// drawing; this is what the tests assert on, which is the same split the block
/// map uses.
/// </para>
/// <para>
/// THE WHOLE IS source + PAR2, NOT source ALONE, and the difference shows on
/// screen. <c>recovery_percent</c> is parity as a share of the SOURCE blocks, so
/// a 10 per cent set draws 9.1 per cent of this bar, and a reader who checks one
/// figure against the other would find them disagreeing if the bar claimed to be
/// the recovery percentage. It does not: the caption names the footprint the bar
/// is a proportion of, and the recovery percentage keeps its own figure in the
/// Recovery group where it belongs.
/// </para>
/// <para>
/// TWO THINGS ARE DELIBERATELY NUMBERS AND NOT SEGMENTS, which is the part of
/// this control that took the longest to get right.
/// </para>
/// <list type="number">
/// <item>
/// <description>
/// <b>Padding is not a disk cost at all.</b> <c>padding_bytes</c> is the zero fill
/// in the last block of each member (the engine's own words: "the slice grid is
/// per FILE, so this is the sum of every member's own remainder"). It is what the
/// parity is computed OVER and is never written anywhere, so a segment for it
/// inside a footprint bar would be counting bytes that do not exist. It is
/// reported beside the bar with that reason, always, at whatever size - which is
/// a stronger reading of "leave it as a number when it cannot be drawn honestly"
/// than a width test would have been, because there is no width at which it
/// becomes honest here.
/// </description>
/// </item>
/// <item>
/// <description>
/// <b>The index file is real and is always sub-pixel.</b> It is
/// <c>total_bytes - recovery_bytes</c>: the critical packets plus twenty bytes per
/// block. On a two-gigabyte set over 2,000 blocks that is about 40 KiB against
/// 2.2 GiB, which is 0.01 of one pixel on a 600 pixel bar - so a third segment
/// for it could never be drawn at any plausible size, and flooring it to a
/// visible two pixels would overstate it by four orders of magnitude. A
/// proportion bar's width IS its value, so flooring lies here in a way it does
/// not in the block map, where a floored bad tick carries PRESENCE and the ground
/// beside it carries the proportion. It therefore rides inside the PAR2 segment
/// and is named in that segment's own legend line.
/// </description>
/// </item>
/// </list>
/// <para>
/// WHY TWO SEGMENTS AND NOT THREE, measured rather than argued. The first version
/// drew source, recovery and index as three segments in the pending grey, the
/// recovery pink and <c>recovery.spare</c>. The house palette validator refused
/// it: the grey against the pale pink measures dE 5.9 to FULL colour vision and
/// 2.2 to a protanope, against a floor of 15 and 8. Dropping the index segment -
/// which the arithmetic above says was never drawable anyway - leaves one pair,
/// grey against the recovery pink, at dE 28.2 normal and 22.2 deutan. The
/// accessibility fix and the arithmetic fix were the same fix.
/// </para>
/// </remarks>
public sealed class CostBarModel
{
    /// <summary>
    /// Narrowest segment, in device-independent pixels, that this bar will draw.
    /// </summary>
    /// <remarks>
    /// Three rather than the block map's two, and for the opposite reason. There a
    /// two pixel floor WIDENS a mark that would otherwise antialias to nothing,
    /// because the mark's job is to say a bad block is present. Here the width is
    /// the value, so nothing is widened: a segment under this many pixels is
    /// dropped from the picture and reported as a number instead. Three is where a
    /// filled sliver stops reading as a colour and starts reading as an edge
    /// artefact of its neighbour.
    /// </remarks>
    public const double MinimumSegmentWidth = 3;

    private PlanPreview _preview = PlanPreview.Empty;

    /// <summary>The segments, in drawing order, or empty when there is no plan.</summary>
    public IReadOnlyList<CostBarSegment> Segments { get; private set; } = [];

    /// <summary>What is on the disk after the create: the sources plus the PAR2 set.</summary>
    public long FootprintBytes { get; private set; }

    /// <summary>True once there is a plan worth drawing.</summary>
    public bool HasPlan => FootprintBytes > 0 && Segments.Count > 0;

    /// <summary>The caption over the bar: the footprint it is a proportion of.</summary>
    public string FootprintText => HasPlan ? Fmt.Bytes(FootprintBytes) : string.Empty;

    /// <summary>
    /// The PAR2 set's share of the footprint, which is the headline this bar
    /// exists to give at a glance.
    /// </summary>
    public double Par2Share =>
        Segments.FirstOrDefault(s => s.Kind == CostSegment.Par2).Share;

    /// <summary>The padding note, or an empty string when there is no plan.</summary>
    /// <remarks>
    /// It carries the REASON padding is not in the bar, because a figure sitting
    /// beside a part-to-whole picture reads as a part somebody forgot to draw.
    /// </remarks>
    public string PaddingText => !HasPlan
        ? string.Empty
        : Strings.Fill(Strings.CreateCostPadding,
            "bytes", Fmt.Bytes(_preview.PaddingBytes),
            "percent", Fmt.Pct(_preview.PaddingPct, 2));

    /// <summary>
    /// Whether a segment of this share is wide enough to draw honestly in a bar of
    /// this pixel width.
    /// </summary>
    /// <remarks>
    /// Pure, and shared with the control rather than duplicated there, so the
    /// legend's "too small to plot" note and the bar's own decision to skip a
    /// segment can never disagree - the case where they did would be a reader
    /// hunting a picture for a colour that is not in it.
    /// </remarks>
    public static bool IsDrawable(double share, double widthPixels) =>
        share > 0 && share * widthPixels >= MinimumSegmentWidth;

    /// <summary>Rebuilds from a fresh plan preview.</summary>
    public void Update(PlanPreview? preview)
    {
        _preview = preview ?? PlanPreview.Empty;

        // A plan with no sources and a plan mid-edit both arrive here, and both
        // have to leave the bar empty rather than drawing a 100 per cent
        // something: the Create screen's preview is filled in left to right and a
        // full bar over no files is a claim.
        var source = Math.Max(0, _preview.SourceBytes);
        var par2 = Math.Max(0, _preview.TotalBytes);
        FootprintBytes = source + par2;
        if (FootprintBytes <= 0 || _preview.BlockCount == 0)
        {
            FootprintBytes = 0;
            Segments = [];
            return;
        }

        Segments =
        [
            new CostBarSegment(CostSegment.Source, Strings.CreateCostSource, source,
                (double)source / FootprintBytes),
            new CostBarSegment(CostSegment.Par2, Strings.CreateCostPar2, par2,
                (double)par2 / FootprintBytes),
        ];
    }

    /// <summary>
    /// The legend line for a segment: its size, and its share of the footprint.
    /// </summary>
    public string Describe(CostBarSegment segment) =>
        Strings.Fill(Strings.CreateCostSegment,
            "bytes", Fmt.Bytes(segment.Bytes),
            "percent", Fmt.Percent(segment.Share, 1));

    /// <summary>
    /// What rides inside the PAR2 segment, for that segment's second legend line,
    /// or an empty string for any other segment.
    /// </summary>
    /// <remarks>
    /// The index file is the difference between what the create WRITES and the
    /// parity inside it, and this is where it is accounted for rather than drawn.
    /// See the class remarks for why it is never a segment of its own.
    /// </remarks>
    public string DescribeInside(CostBarSegment segment)
    {
        if (segment.Kind != CostSegment.Par2 || !HasPlan)
        {
            return string.Empty;
        }

        var index = Math.Max(0, _preview.TotalBytes - _preview.RecoveryBytes);
        return Strings.Fill(Strings.CreateCostPar2Inside,
            "parity", Fmt.Bytes(_preview.RecoveryBytes),
            "index", Fmt.Bytes(index));
    }

    /// <summary>
    /// The sentence a screen reader gets instead of the picture, the same way the
    /// block map answers (plan 5.7).
    /// </summary>
    public string AccessibleSummary() => !HasPlan
        ? Strings.CreateCostNoPlan
        : Strings.Fill(Strings.CreateCostSummary,
            "source", Fmt.Bytes(_preview.SourceBytes),
            "par2", Fmt.Bytes(_preview.TotalBytes),
            "share", Fmt.Percent(Par2Share, 1),
            "total", Fmt.Bytes(FootprintBytes));
}
