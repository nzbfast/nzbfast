using Parfast.Core.Contracts;
using Parfast.Core.Mock;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// The create planner's arithmetic. These are the assertions chip A's
/// <c>parfast-session::planner</c> has to agree with, so a disagreement at
/// integration is a finding with a number attached rather than an argument.
/// </summary>
public class PlannerTests
{
    private const long Mib = 1048576;

    private static List<PlannedSource> Sources(params long[] sizes) =>
        sizes.Select((s, i) => new PlannedSource($@"C:\set\part{i + 1:D2}.rar", s)).ToList();

    private static CreateSpec Spec(BlockSpec block, RecoverySpec recovery, VolumeSpec? volumes = null) => new()
    {
        Sources = [new SourceSpec { Path = @"C:\set" }],
        Output = @"C:\set\set.par2",
        Block = block,
        Recovery = recovery,
        Volumes = volumes ?? VolumeSpec.None(),
    };

    [Fact]
    public void BlockCountIsTheSumOfPerFileCeilings()
    {
        // Three files of 2.5 blocks each is 3+3+3 = 9, not ceil(7.5) = 8. PAR2
        // blocks never span a file boundary, and getting this wrong understates
        // every set by one block per file.
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByPercent(10)),
            Sources(Mib * 5 / 2, Mib * 5 / 2, Mib * 5 / 2));
        Assert.Equal(9, plan.BlockCount);
    }

    [Fact]
    public void PaddingIsWhatTheLastPartialBlockWastes()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByPercent(0)),
            Sources(Mib + 1));
        Assert.Equal(2, plan.BlockCount);
        Assert.Equal((2 * Mib) - (Mib + 1), plan.PaddingBytes);
        Assert.True(plan.EfficiencyPct is > 49 and < 51, $"efficiency was {plan.EfficiencyPct}");
    }

    [Fact]
    public void BlockSizeIsRoundedUpToAMultipleOfFourAndSaysSo()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(1023), RecoverySpec.ByPercent(10)),
            Sources(Mib));
        Assert.Equal(1024, plan.BlockSize);
        Assert.Contains(plan.Warnings, w => w.Contains("multiple of 4", StringComparison.Ordinal));
    }

    [Fact]
    public void ABlockCountRequestLandsAtOrUnderWhatWasAsked()
    {
        // The contract is a count the user typed; the format stores a SIZE. The
        // resolved size must not produce MORE blocks than asked for, because
        // 32,768 is a hard ceiling in other tools and overshooting it silently
        // is how a set becomes unreadable elsewhere.
        foreach (var wanted in new[] { 10, 97, 1000, 2000, 32768 })
        {
            var plan = MockPlanner.Plan(
                Spec(BlockSpec.ByCount(wanted), RecoverySpec.ByPercent(10)),
                Sources(700 * Mib, 700 * Mib, 137 * Mib));
            Assert.True(plan.BlockCount <= wanted,
                $"asked for {wanted} blocks, planner produced {plan.BlockCount}");
            Assert.True(plan.BlockSize % 4 == 0, $"block size {plan.BlockSize} is not a multiple of 4");
        }
    }

    [Fact]
    public void RecoveryPercentCountAndSizeAgreeOnTheSameSet()
    {
        var sources = Sources(1000 * Mib);
        var byPercent = MockPlanner.Plan(Spec(BlockSpec.BySize(Mib), RecoverySpec.ByPercent(10)), sources);
        Assert.Equal(100, byPercent.RecoveryBlocks);

        var byCount = MockPlanner.Plan(Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(100)), sources);
        Assert.Equal(100, byCount.RecoveryBlocks);
        // recovery_percent is the slice count as a share of the INPUT slice count.
        Assert.Equal(10.0, byCount.RecoveryPercent, 3);
        Assert.Equal((double)byCount.RecoveryBlocks / byCount.BlockCount * 100, byCount.RecoveryPercent, 9);

        var bySize = MockPlanner.Plan(Spec(BlockSpec.BySize(Mib), RecoverySpec.BySize(100 * Mib)), sources);
        Assert.Equal(100, bySize.RecoveryBlocks);
    }

    /// <summary>
    /// recovery_blocks: a recovery SIZE is a CEILING over the block size, not a floor.
    /// </summary>
    /// <remarks>
    /// <c>parfast::create::recovery_blocks</c> is <c>bytes.div_ceil(block)</c>, so a
    /// target the block size does not divide buys the slice that covers it. This planner
    /// floor-divided until 12 September 2026: measured through pf_plan_preview, 100 MiB
    /// plus one byte at a 1 MiB block is 101 slices, and this drew 100 - a set that does
    /// not reach the size the user asked to protect.
    /// </remarks>
    [Fact]
    public void ARecoverySizeRoundsUpToTheSliceThatCoversIt()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.BySize((100 * Mib) + 1)),
            Sources(1000 * Mib));

        Assert.Equal(101, plan.RecoveryBlocks);
        Assert.Equal(101 * Mib, plan.RecoveryBytes);
        // No k/m/g unit divides 100 MiB + 1, so the line spells the resolved count.
        Assert.Contains("-c101", plan.Command, StringComparison.Ordinal);
        // One that does is spelled in the scaled form the reference takes.
        var exact = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.BySize(100 * Mib)), Sources(1000 * Mib));
        Assert.Contains("-rm100", exact.Command, StringComparison.Ordinal);
    }

    /// <summary>
    /// recovery_blocks: a percentage is round-to-nearest with a FLOOR OF ONE BLOCK, and a
    /// spec naming no recovery at all is the reference's five per cent rather than none.
    /// </summary>
    /// <remarks>
    /// The rounding rule is <c>parfast::create::percent_blocks</c>, probed against
    /// par2cmdline-turbo 1.5.0 over 32 input blocks: -r49 to 16, -r50 to 16, -r51 to 16,
    /// -r52 to 17. This planner had that and not the floor, so <c>-r1</c> over 32 blocks
    /// drew a set with NO recovery in it - and then warned that the set could not repair,
    /// which made a wrong number look like a deliberate one. Every arm measured through
    /// pf_plan_preview.
    /// </remarks>
    [Fact]
    public void ARecoveryPercentageNeverRoundsDownToNoRecoveryAtAll()
    {
        foreach (var (ask, want) in new[] { (49, 16), (50, 16), (51, 16), (52, 17), (1, 1) })
        {
            var plan = MockPlanner.Plan(
                Spec(BlockSpec.BySize(1024), RecoverySpec.ByPercent(ask)), Sources(32768));
            Assert.Equal(32, plan.BlockCount);
            Assert.Equal(want, plan.RecoveryBlocks);
        }

        // Nothing asked for is the reference's default of five per cent: over ten input
        // blocks that is one slice, not zero.
        var unset = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), new RecoverySpec()), Sources(10 * Mib));
        Assert.Equal(MockPlanner.DefaultRedundancyPct, 5);
        Assert.Equal(1, unset.RecoveryBlocks);
        Assert.DoesNotContain(unset.Warnings, w => w.Contains("detect damage", StringComparison.Ordinal));

        // An explicit zero is still zero, and still says what that costs.
        var none = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByPercent(0)), Sources(10 * Mib));
        Assert.Equal(0, none.RecoveryBlocks);
        Assert.Single(none.Files);
    }

    /// <summary>
    /// warnings: <c>-r</c> is an integer percent in the reference's dialect, so a
    /// fractional ask is rounded and said out loud.
    /// </summary>
    [Fact]
    public void AFractionalRecoveryPercentageIsRoundedAndSaidOutLoud()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByPercent(7.5)), Sources(100 * Mib));

        Assert.Equal(8, plan.RecoveryBlocks);
        Assert.Contains(plan.Warnings, w => w.Contains("whole percents", StringComparison.Ordinal));
        Assert.Contains("-r8", plan.Command, StringComparison.Ordinal);
    }

    /// <summary>
    /// block_size and block_count: the grid is the reference's own SEARCH over
    /// multiples of four, not a division of the payload.
    /// </summary>
    /// <remarks>
    /// A slice never spans a file boundary, so the count is the sum of per-file ceilings
    /// and the remainders do not pool. The engine's own fixture is two members of 40,000
    /// and 17,000 bytes at <c>-b64</c>: the division gives 892, which slices into
    /// 45 + 20 = 65 - one MORE than asked for - where the reference answers 896 and gets
    /// 45 + 19 = 64. Measured through pf_plan_preview, which is also where the padding
    /// figures below come from.
    /// </remarks>
    [Fact]
    public void TheGridIsTheReferencesSearchAndNotADivision()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.ByCount(64), RecoverySpec.ByPercent(5)), Sources(40_000, 17_000));

        Assert.Equal(896, plan.BlockSize);
        Assert.Equal(64, plan.BlockCount);
        Assert.Equal(344, plan.PaddingBytes);
        Assert.Equal(57_000, plan.SourceBytes);
    }

    /// <summary>
    /// files: the "none" scheme is an index AND ONE VOLUME, not one merged file.
    /// </summary>
    /// <remarks>
    /// This test asserted <c>Assert.Single</c> until 12 September 2026, and the planner
    /// obliged by growing the index file to carry the recovery itself. The engine does
    /// not: a <c>-n1</c> create writes the critical packets to <c>set.par2</c> and every
    /// recovery slice to one <c>set.vol00+10.par2</c> beside it. Measured through
    /// pf_plan_preview: 2,384 bytes and 10,495,736 bytes, two files. The old shape was
    /// a preview that under-counted the file list by one and mis-stated both sizes, and
    /// the test said so in its name.
    /// </remarks>
    [Fact]
    public void SchemeNoneIsAnIndexAndOneVolumeHoldingEverything()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(10), VolumeSpec.None()),
            Sources(100 * Mib));

        Assert.Equal(2, plan.Files.Count);
        Assert.Equal("set.par2", plan.Files[0].Name);
        Assert.Equal(0, plan.Files[0].Blocks);
        Assert.Equal(2_384, plan.Files[0].Size);
        Assert.Equal("set.vol00+10.par2", plan.Files[1].Name);
        Assert.Equal(10, plan.Files[1].Blocks);
        Assert.Equal(10_495_736, plan.Files[1].Size);
        Assert.Contains("-n1", plan.Command, StringComparison.Ordinal);
    }

    /// <summary>
    /// files: an even split gives the REMAINDER TO THE FIRST volumes, and this took
    /// blocks-per-file off the front until the blocks ran out.
    /// </summary>
    /// <remarks>
    /// <c>par2gen::VolumePlan::Even</c> over 100 slices in 7 volumes is
    /// 15 15 14 14 14 14 14; this planner drew 15 15 15 15 15 15 10, and the test that
    /// covered it asserted exactly that last ten. Measured through pf_plan_preview,
    /// down to the bytes: the 15-slice volumes are 15,810,956 and the 14-slice ones
    /// 14,762,312.
    /// </remarks>
    [Fact]
    public void UniformBySevenFilesSplitsEvenlyWithTheRemainderOnTheFirstVolumes()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(100), VolumeSpec.UniformFiles(7)),
            Sources(1000 * Mib));

        var volumes = plan.Files.Skip(1).ToList();
        Assert.Equal(7, volumes.Count);
        Assert.Equal(100, volumes.Sum(f => f.Blocks));
        Assert.Equal([15, 15, 14, 14, 14, 14, 14], volumes.Select(f => f.Blocks));
        Assert.Equal(15_810_956, volumes[0].Size);
        Assert.Equal(14_762_312, volumes[^1].Size);
        // `-u` does not ride with a count: the engine spells a counted uniform set `-n`.
        Assert.Contains("-n7", plan.Command, StringComparison.Ordinal);
        Assert.DoesNotContain("-u", plan.Command, StringComparison.Ordinal);
    }

    /// <summary>
    /// files: bare <c>-u</c> - the uniform scheme naming no count - keeps however many
    /// volumes the exponential plan would have written and makes them equal sizes.
    /// </summary>
    /// <remarks>
    /// It does NOT mean one volume, which is what this planner answered until
    /// 12 September 2026 (<c>volumes.Files ?? 1</c>). Measured through pf_plan_preview
    /// over 20 slices: five volumes of four, because
    /// <c>par2gen::variable_volume_count(20)</c> is 5 - the 1+2+4+8+5 plan has five
    /// files in it, and uniform changes their sizes rather than their number.
    /// </remarks>
    [Fact]
    public void BareUniformKeepsTheExponentialPlansVolumeCountAndEvensTheSizes()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(20),
                 new VolumeSpec { Scheme = VolumeScheme.Uniform }),
            Sources(100 * Mib));

        Assert.Equal([4, 4, 4, 4, 4], plan.Files.Skip(1).Select(f => f.Blocks));
        Assert.Contains("-u", plan.Command, StringComparison.Ordinal);
        // No `-n` SWITCH, asserted over the tokens rather than as a substring of the
        // whole line: `--no-clobber` contains the two characters `-n`, so the substring
        // spelling this used to carry started failing the moment the line grew that
        // switch on 17 September 2026 - a red that named nothing about volume counts at
        // all. `--no-clobber` contains `-c` too, so the same trap is waiting for any
        // later assertion written the short way.
        Assert.DoesNotContain(plan.Command.Split(' '), t => t.StartsWith("-n", StringComparison.Ordinal));
    }

    /// <summary>
    /// files: a volume count asked for above the CLI's cap of 31 recovery files is
    /// clamped to it, as <c>planner::apply_scheme</c> clamps it.
    /// </summary>
    [Fact]
    public void AUniformCountAboveTheCliCapIsClamped()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(100), VolumeSpec.UniformFiles(99)),
            Sources(1000 * Mib));

        var volumes = plan.Files.Skip(1).ToList();
        Assert.Equal(MockPlanner.MaxRecoveryFiles, volumes.Count);
        Assert.Equal(100, volumes.Sum(f => f.Blocks));
        // 100 over 31 is 3 each with 7 left over, and the 7 go to the front.
        Assert.Equal(4, volumes[0].Blocks);
        Assert.Equal(4, volumes[6].Blocks);
        Assert.Equal(3, volumes[7].Blocks);
    }

    /// <summary>
    /// files: a uniform volume SIZE divides by the slice's cost ON DISK - the block plus
    /// the writer's 68-byte packet head - so a 10 MiB volume at a 1 MiB block holds NINE
    /// slices, not ten.
    /// </summary>
    /// <remarks>
    /// This planner divided by the block size alone until 12 September 2026 and drew ten
    /// volumes of ten, whose tenth slice would have put every file over the size the user
    /// typed. Measured through pf_plan_preview: TWELVE volumes, the first four of nine
    /// slices and the rest of eight, because 100 slices at nine per volume is twelve
    /// volumes and the engine then evens them out.
    /// </remarks>
    [Fact]
    public void AUniformVolumeSizeCountsTheSlicesPacketHeadToo()
    {
        var byBlocks = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(100), VolumeSpec.UniformBlocksPerFile(10)),
            Sources(1000 * Mib));
        Assert.Equal(10, byBlocks.Files.Skip(1).Count());
        Assert.All(byBlocks.Files.Skip(1), f => Assert.Equal(10, f.Blocks));

        var bySize = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(100), VolumeSpec.UniformFileSize(10 * Mib)),
            Sources(1000 * Mib));
        Assert.Equal(12, bySize.Files.Skip(1).Count());
        Assert.Equal([9, 9, 9, 9, 8, 8, 8, 8, 8, 8, 8, 8], bySize.Files.Skip(1).Select(f => f.Blocks));
    }

    [Fact]
    public void Pow2DoublesUntilTheBlocksRunOut()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(100), VolumeSpec.Pow2()),
            Sources(1000 * Mib));

        var blocks = plan.Files.Skip(1).Select(f => f.Blocks).ToList();
        Assert.Equal([1, 2, 4, 8, 16, 32, 37], blocks);
        Assert.Equal(100, blocks.Sum());
    }

    [Fact]
    public void Pow2WithALimitStopsDoublingAtTheCap()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(100), VolumeSpec.Pow2LimitBlocks(8)),
            Sources(1000 * Mib));

        var blocks = plan.Files.Skip(1).Select(f => f.Blocks).ToList();
        Assert.Equal([1, 2, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 5], blocks);
        Assert.Equal(100, blocks.Sum());
    }

    /// <summary>
    /// files: the pow2 ceilings FLOOR-divide. A ceiling that rounds up is not a ceiling.
    /// </summary>
    /// <remarks>
    /// The largest member here is twenty and a HALF blocks, so no volume may carry more
    /// than twenty; this planner took the ceiling of that division and allowed 21 until
    /// 12 September 2026. A byte ceiling divides by block + 68 for the same reason a
    /// uniform volume size does, and the engine says which block count the bytes became.
    /// Both measured through pf_plan_preview.
    /// </remarks>
    [Fact]
    public void Pow2CeilingsFloorDivideAndABytesCeilingSaysWhatItBecame()
    {
        var largest = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(100), VolumeSpec.Pow2LargestSource()),
            Sources((20 * Mib) + (Mib / 2), 8 * Mib));

        var blocks = largest.Files.Skip(1).Select(f => f.Blocks).ToList();
        Assert.Equal([1, 2, 4, 8, 16, 20, 20, 20, 9], blocks);
        Assert.Equal(100, blocks.Sum());
        Assert.Contains(" -l", largest.Command, StringComparison.Ordinal);

        var bySize = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(100), VolumeSpec.Pow2LimitSize(10 * Mib)),
            Sources(1000 * Mib));
        Assert.Equal([1, 2, 4, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 4],
                     bySize.Files.Skip(1).Select(f => f.Blocks));
        Assert.Contains(bySize.Warnings, w => w.Contains("9 recovery block(s)", StringComparison.Ordinal));
        // A block ceiling is parfast's own long option and NOT `-l`, which means
        // "largest source file" and nothing else.
        Assert.Contains("--volume-blocks=9", bySize.Command, StringComparison.Ordinal);
    }

    /// <summary>
    /// files[].name: the two fields have DIFFERENT widths and neither is floored at
    /// three, so the names in the pane are the names that will be on the disk.
    /// </summary>
    /// <remarks>
    /// Measured against the engine over thirteen slices from zero:
    /// <c>vol00+1 vol01+2 vol03+4 vol07+6</c>. The first field is as wide as
    /// <c>first + recovery</c> - 13, two digits - and NOT as wide as the largest index
    /// that appears, which is 7. The second is as wide as the largest COUNT, which is
    /// one digit. This planner padded both to <c>max(3, digits(first + recovery))</c> and
    /// drew <c>vol000+001</c>, a third spelling that is neither the engine's internal
    /// <c>vol000+01</c> nor par2cmdline's measured widths - and the next tool along finds
    /// a set's volumes by this pattern.
    /// </remarks>
    [Fact]
    public void VolumeNamesUseParCmdlinesTwoMeasuredFieldWidths()
    {
        var thirteen = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(13), VolumeSpec.Pow2()),
            Sources(100 * Mib));
        Assert.Equal(
            ["set.vol00+1.par2", "set.vol01+2.par2", "set.vol03+4.par2", "set.vol07+6.par2"],
            thirteen.Files.Skip(1).Select(f => f.Name));

        // Under --std-naming both fields are EXPONENTS, so both take the first field's
        // width, and the second is the volume's LAST exponent rather than its count.
        var std = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(13), VolumeSpec.Pow2())
                with { StdNaming = true },
            Sources(100 * Mib));
        Assert.Equal(
            ["set.vol00-00.par2", "set.vol01-02.par2", "set.vol03-06.par2", "set.vol07-12.par2"],
            std.Files.Skip(1).Select(f => f.Name));
        Assert.Contains("--std-naming", std.Command, StringComparison.Ordinal);

        // The first field is sized by the exponent one PAST the last written, so nine
        // slices from 95 run to 104 and go three wide.
        var offset = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(9), VolumeSpec.Pow2())
                with { FirstRecoveryBlock = 95 },
            Sources(100 * Mib));
        Assert.Equal(
            ["set.vol095+1.par2", "set.vol096+2.par2", "set.vol098+4.par2", "set.vol102+2.par2"],
            offset.Files.Skip(1).Select(f => f.Name));
        Assert.Contains("-f95", offset.Command, StringComparison.Ordinal);
    }

    /// <summary>
    /// files[].size and total_bytes: every file's size is the engine's, byte for byte,
    /// because a volume REPEATS the critical block logarithmically.
    /// </summary>
    /// <remarks>
    /// The engine interleaves <c>copies</c> whole copies of every critical packet but the
    /// creator, where <c>copies</c> is the BIT LENGTH of the volume's slice count. This
    /// planner carried exactly one copy, and that copy left out the per-block slice
    /// checksums - which on a large set are most of the block. Every number below is
    /// pf_plan_preview's over the same fixture.
    /// </remarks>
    [Fact]
    public void EveryFilesSizeIsTheEnginesAndTheTotalIsTheirSum()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(31), VolumeSpec.Pow2()),
            Sources(100 * Mib));

        Assert.Equal(2_384, plan.Files[0].Size);
        Assert.Equal(
            [1_051_028L, 2_101_976, 4_201_568, 8_398_448, 16_789_904],
            plan.Files.Skip(1).Select(f => f.Size));
        Assert.Equal(32_545_308, plan.TotalBytes);
        Assert.Equal(plan.Files.Sum(f => f.Size), plan.TotalBytes);

        // files[].efficiency_pct is the recovery payload as a share of the file's OWN
        // size - how much of what a downloader fetches is parity.
        Assert.Equal(0, plan.Files[0].EfficiencyPct);
        Assert.Equal(16.0 * Mib / 16_789_904 * 100, plan.Files[^1].EfficiencyPct, 9);
    }

    /// <summary>
    /// recovery_bytes is the PAYLOAD - slices times slice size - and not the bytes the
    /// volumes occupy.
    /// </summary>
    /// <remarks>
    /// This planner answered <c>files.Sum(size) - indexSize</c> until 12 September 2026,
    /// which counted every volume's packet heads and its repeated critical block as
    /// though they were parity. Over the fixture above the engine says 32,505,856 and
    /// that expression says 32,542,924; the gap grows with the volume count, so the two
    /// agreed most closely in the single-volume case a reader would check by hand.
    /// </remarks>
    [Fact]
    public void RecoveryBytesIsTheSliceCountTimesTheSliceSize()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(31), VolumeSpec.Pow2()),
            Sources(100 * Mib));

        Assert.Equal(31 * Mib, plan.RecoveryBytes);
        Assert.True(plan.RecoveryBytes < plan.TotalBytes - plan.Files[0].Size,
            "the payload is strictly less than the bytes the volumes take up");
    }

    /// <summary>
    /// block_size and block_count: the spec's input-slice ceiling is ENFORCED, not
    /// warned about, and the raise is to a MULTIPLE of the size that was asked for.
    /// </summary>
    /// <remarks>
    /// Measured against the engine through pf_plan_preview over one gibibyte at a 4,096
    /// byte block: 32,768 bytes and 32,768 slices, with the warning. This planner kept
    /// 4,096 and reported 262,144 slices until 12 September 2026 - a block size and a
    /// block count the create would never use, with a warning underneath saying other
    /// tools would refuse the set.
    /// </remarks>
    [Fact]
    public void ABlockSizeThatOverflowsTheSliceCeilingIsRaisedToAMultipleOfItself()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(4096), RecoverySpec.ByCount(2)),
            Sources(1024 * Mib));

        Assert.Equal(32768, plan.BlockSize);
        Assert.Equal(32768, plan.BlockCount);
        Assert.Equal(0, plan.BlockSize % 4096);
        Assert.Contains(plan.Warnings, w => w.Contains("32,768", StringComparison.Ordinal));
    }

    [Fact]
    public void ZeroRecoveryWarnsThatTheSetCannotRepair()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByPercent(0)),
            Sources(10 * Mib));
        Assert.Equal(0, plan.RecoveryBlocks);
        Assert.Equal(0, plan.RecoveryBytes);
        // The index and nothing else, which is the engine's answer too: 584 bytes over
        // one 10 MiB member at a 1 MiB block, and total_bytes is exactly that one file.
        Assert.Single(plan.Files);
        Assert.Equal(plan.Files[0].Size, plan.TotalBytes);
        Assert.Contains(plan.Warnings, w => w.Contains("detect damage but not repair", StringComparison.Ordinal));
    }

    /// <summary>
    /// command: the switches are the engine's, and the line names the MEMBERS rather
    /// than the sources the user picked.
    /// </summary>
    /// <remarks>
    /// <c>planner::command_args</c> expands a directory source itself and lists every
    /// member, so there is no <c>-R</c> on the line at all - this emitted one, beside the
    /// unexpanded paths, until 12 September 2026. The engine asserts its own line parses
    /// BACK into the same options it was built from, which is why every switch here is
    /// measured against it rather than read off the help text.
    /// </remarks>
    [Fact]
    public void TheCopyCommandUsesTheRealParfastSwitches()
    {
        var spec = Spec(BlockSpec.BySize(768000), RecoverySpec.ByPercent(15), VolumeSpec.UniformFiles(7)) with
        {
            PathMode = PathMode.Relative,
            BasePath = @"C:\set",
            Sources = [new SourceSpec { Path = @"C:\set", Recursive = true }],
            Perf = new PerfSpec { Threads = 3, MemoryMb = 512 },
        };
        var plan = MockPlanner.Plan(spec, Sources(10 * Mib, 10 * Mib));

        Assert.StartsWith("parfast c ", plan.Command, StringComparison.Ordinal);
        Assert.Contains("-s768000", plan.Command, StringComparison.Ordinal);
        Assert.Contains("-r15", plan.Command, StringComparison.Ordinal);
        // Seven volumes were asked for and the set has only four slices, so the engine
        // still spells the ask and `recovery_file_count` caps the layout at the far end.
        Assert.Contains("-n7", plan.Command, StringComparison.Ordinal);
        Assert.Equal(4, plan.Files.Skip(1).Count());
        Assert.Contains(@"-BC:\set", plan.Command, StringComparison.Ordinal);
        Assert.Contains("-t3", plan.Command, StringComparison.Ordinal);
        Assert.Contains("-m512", plan.Command, StringComparison.Ordinal);
        Assert.DoesNotContain("-R", plan.Command, StringComparison.Ordinal);
        Assert.EndsWith(@"C:\set\set.par2 C:\set\part01.rar C:\set\part02.rar", plan.Command,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// command: the line carries the Overwrite decision, both ways round.
    /// </summary>
    /// <remarks>
    /// The engine's <c>command_args</c> has spelled <c>--no-clobber</c> since
    /// 17 September 2026 and this mock did not, which
    /// <c>PlannerParityTests</c> caught on every one of its cases at once. The parity
    /// test is the stronger claim and it is COMPILED PAST on a box with no cdylib, so
    /// the value assertion lives here too: the mock is exactly what draws the pane on
    /// such a box, and a pane that protects the set while handing the user a line that
    /// overwrites it is the pane lying about the one tick that decides whether a file
    /// survives. The ticked arm is beside it so the switch is conditional rather than
    /// unconditional - the way the engine's own test is written.
    /// </remarks>
    [Fact]
    public void TheCopiedLineCarriesTheOverwriteDecision()
    {
        var spec = Spec(BlockSpec.BySize(Mib), RecoverySpec.ByCount(2));

        var guarded = MockPlanner.Plan(spec with { Overwrite = false }, Sources(10 * Mib));
        Assert.Contains("--no-clobber", guarded.Command, StringComparison.Ordinal);

        var plain = MockPlanner.Plan(spec with { Overwrite = true }, Sources(10 * Mib));
        Assert.DoesNotContain("--no-clobber", plain.Command, StringComparison.Ordinal);
    }

    [Fact]
    public void ABlockCountRequestCopiesAsDashBAndNotDashS()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.ByCount(2000), RecoverySpec.ByCount(50)),
            Sources(100 * Mib));
        Assert.Contains("-b2000", plan.Command, StringComparison.Ordinal);
        Assert.DoesNotContain("-s", plan.Command, StringComparison.Ordinal);
        Assert.Contains("-c50", plan.Command, StringComparison.Ordinal);
    }

    [Fact]
    public void PathsWithSpacesAreQuoted()
    {
        var spec = Spec(BlockSpec.BySize(Mib), RecoverySpec.ByPercent(10)) with
        {
            Output = @"C:\my sets\the set.par2",
            Sources = [new SourceSpec { Path = @"C:\my sets" }],
        };
        // The line names the MEMBERS, so the path that has to survive the paste is the
        // planned source's and not the picked folder's.
        var plan = MockPlanner.Plan(spec, [new PlannedSource(@"C:\my sets\a b.bin", Mib)]);
        Assert.Contains("\"C:\\my sets\\the set.par2\"", plan.Command, StringComparison.Ordinal);
        Assert.Contains("\"C:\\my sets\\a b.bin\"", plan.Command, StringComparison.Ordinal);
    }

    [Fact]
    public void TheVerifyAndRepairCommandLinesCarryTheirOwnSwitches()
    {
        var options = new VerifyOptions { RenameOnly = true, DataSkipping = true, SkipLeaway = 128, Threads = 8 };
        var verify = MockPlanner.CommandLine(@"C:\set\set.par2", options, repair: false, purge: false);
        Assert.Equal(@"parfast v -O -N -S128 -t8 C:\set\set.par2", verify);

        var repair = MockPlanner.CommandLine(@"C:\set\set.par2", new VerifyOptions(), repair: true, purge: true);
        Assert.Equal(@"parfast r -p C:\set\set.par2", repair);
    }

    [Fact]
    public void NoSourcesIsAnEmptyPreviewAndNotAnException()
    {
        var plan = MockPlanner.Plan(Spec(BlockSpec.ByCount(2000), RecoverySpec.ByPercent(10)), []);
        Assert.Equal(0, plan.BlockCount);
        Assert.Empty(plan.Files);
    }

    /// <summary>
    /// The two fields API.md marks <b>ADDED</b>, which this planner simply did not set
    /// until 12 September 2026.
    /// </summary>
    /// <remarks>
    /// Found by the create screen's cost bar, which is the first thing to draw them.
    /// With <c>source_bytes</c> zero its whole is the PAR2 set alone, so a mock-driven
    /// screen showed a two gigabyte source protected at ten per cent as ONE HUNDRED per
    /// cent recovery - confidently, and in the demo and the screenshot set, which are
    /// mock-driven by design. A field the specification does not mention is the
    /// quietest way for the mock and the engine to disagree, and no test here named
    /// either of these.
    /// </remarks>
    [Fact]
    public void TheAddedSourceFieldsAreSetLikeTheRealPlannerSetsThem()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(Mib), RecoverySpec.ByPercent(10)),
            Sources(4 * Mib, 6 * Mib));

        Assert.Equal(10 * Mib, plan.SourceBytes);
        Assert.Equal(2, plan.SourceFiles);
    }

    /// <summary>
    /// Padding and efficiency are percentages of the SAME denominator - the padded grid
    /// - so they are complements and sum to a hundred.
    /// </summary>
    /// <remarks>
    /// The real planner is <c>pct(padding_bytes, padded)</c> beside
    /// <c>pct(source_bytes, padded)</c>. This one divided the padding by the SOURCE
    /// until 12 September 2026, which put two numbers on one screen that were
    /// percentages of different things: on the engine's own fixture - two 5,000 byte
    /// members at a 4,096 block - the engine says 38.96% and the mock said 63.84% for
    /// the same set. Unpinned, because the padding test above pins the BYTES.
    /// </remarks>
    [Fact]
    public void PaddingAndEfficiencyArePercentagesOfTheSameThing()
    {
        var plan = MockPlanner.Plan(
            Spec(BlockSpec.BySize(4_096), RecoverySpec.ByPercent(0)),
            Sources(5_000, 5_000));

        Assert.Equal(4, plan.BlockCount);
        Assert.Equal(2 * (8_192 - 5_000), plan.PaddingBytes);
        Assert.Equal(6_384.0 / 16_384 * 100, plan.PaddingPct, 9);
        Assert.Equal(100.0, plan.PaddingPct + plan.EfficiencyPct, 9);
    }
}
