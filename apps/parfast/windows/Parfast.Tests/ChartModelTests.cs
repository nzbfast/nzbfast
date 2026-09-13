using Parfast.Core.Contracts;
using Parfast.Core.Mock;
using Parfast.ViewModels;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// The three charts of the 12 September 2026 prettiness review, section 4, in the
/// only place they can be tested without a window: their pure models.
/// </summary>
/// <remarks>
/// TESTS ARE NECESSARY AND NOT SUFFICIENT HERE, and the review itself is the
/// evidence - it came out of looking at pictures of an app whose whole suite was
/// green. So these pin the things a picture cannot show: the arithmetic, the refusal
/// arms, and the two cases where a chart must decline to draw rather than draw
/// something plausible. The picture is checked by building on the Windows box and
/// shooting it.
/// </remarks>
public class ChartModelTests
{
    // ---- (a) the create cost bar ----

    private static PlanPreview Plan(
        long sourceBytes, long totalBytes, long recoveryBytes, long paddingBytes = 4_096) =>
        new()
        {
            BlockSize = 1 << 20,
            BlockCount = 2_000,
            SourceBytes = sourceBytes,
            TotalBytes = totalBytes,
            RecoveryBytes = recoveryBytes,
            PaddingBytes = paddingBytes,
            PaddingPct = sourceBytes == 0 ? 0 : (double)paddingBytes / sourceBytes * 100,
        };

    [Fact]
    public void CostBarIsEmptyWithNoPlan()
    {
        var model = new CostBarModel();
        model.Update(PlanPreview.Empty);

        Assert.False(model.HasPlan);
        Assert.Empty(model.Segments);
        Assert.Equal(string.Empty, model.FootprintText);
        Assert.Equal(string.Empty, model.PaddingText);
    }

    /// <summary>
    /// The whole is source PLUS the PAR2 set, so a ten per cent set is nine point one
    /// per cent of the bar. This is the number a reader could check against the
    /// recovery percentage beside it, and the two are allowed to differ only because
    /// the bar's caption names what it is a proportion OF.
    /// </summary>
    [Fact]
    public void CostBarWholeIsTheFootprintAndNotTheSource()
    {
        var model = new CostBarModel();
        model.Update(Plan(sourceBytes: 1_000_000_000, totalBytes: 100_000_000, recoveryBytes: 99_000_000));

        Assert.True(model.HasPlan);
        Assert.Equal(1_100_000_000, model.FootprintBytes);
        Assert.Equal(2, model.Segments.Count);
        Assert.Equal(CostSegment.Source, model.Segments[0].Kind);
        Assert.Equal(CostSegment.Par2, model.Segments[1].Kind);
        Assert.Equal(1.0, model.Segments[0].Share + model.Segments[1].Share, 9);
        Assert.Equal(100_000_000.0 / 1_100_000_000, model.Par2Share, 9);
    }

    /// <summary>
    /// Padding is never a segment at any size, because it is never written. The
    /// figure is reported instead, WITH the reason - a bare number beside a
    /// part-to-whole picture reads as a part somebody forgot to draw.
    /// </summary>
    [Fact]
    public void PaddingIsNeverASegmentAndCarriesItsReason()
    {
        var model = new CostBarModel();
        model.Update(Plan(1_000_000_000, 100_000_000, 99_000_000, paddingBytes: 900_000_000));

        Assert.DoesNotContain(model.Segments, s => s.Bytes == 900_000_000);
        Assert.Equal(2, model.Segments.Count);
        Assert.Contains("not part of the bar", model.PaddingText);
    }

    /// <summary>
    /// A share whose pixel width is under the floor is NOT drawn and NOT widened: in a
    /// proportion bar the width is the value. The block map floors a bad tick instead,
    /// because there the tick carries presence and the ground beside it carries the
    /// proportion - the two rules are opposite on purpose.
    /// </summary>
    [Theory]
    [InlineData(0.0, 600, false)]
    [InlineData(0.000_018, 600, false)] // a 40 KiB index against 2.2 GiB
    [InlineData(0.004, 600, false)] // 2.4 px, under the floor
    [InlineData(0.005, 600, true)] // 3.0 px, exactly at it
    [InlineData(0.5, 600, true)]
    [InlineData(0.5, 4, false)] // a bar too narrow to draw anything honestly
    public void IsDrawableIsAPixelTestAndNotAShareTest(double share, double width, bool drawable) =>
        Assert.Equal(drawable, CostBarModel.IsDrawable(share, width));

    [Fact]
    public void Par2SegmentAccountsForTheIndexInWordsRatherThanInInk()
    {
        var model = new CostBarModel();
        model.Update(Plan(1_000_000_000, 100_040_960, 100_000_000));

        var par2 = model.Segments[1];
        var inside = model.DescribeInside(par2);
        Assert.Contains("parity", inside);
        Assert.Contains("index", inside);
        Assert.Equal(string.Empty, model.DescribeInside(model.Segments[0]));
    }

    [Fact]
    public void CostBarSummaryIsASentenceAndNotALabel()
    {
        var model = new CostBarModel();
        Assert.Equal("No plan yet.", model.AccessibleSummary());

        model.Update(Plan(1_000_000_000, 100_000_000, 99_000_000));
        var summary = model.AccessibleSummary();
        Assert.Contains("PAR2 set", summary);
        Assert.Contains("on disk", summary);
        Assert.DoesNotContain("{", summary);
    }

    /// <summary>
    /// The bar has to MOVE as the recovery slider moves, which is the whole reason it
    /// is drawn from the live preview rather than from a finished plan.
    /// </summary>
    [Fact]
    public void CostBarGrowsWithRecovery()
    {
        var model = new CostBarModel();
        model.Update(Plan(1_000_000_000, 50_000_000, 49_500_000));
        var small = model.Par2Share;

        model.Update(Plan(1_000_000_000, 200_000_000, 198_000_000));
        Assert.True(model.Par2Share > small,
            $"the PAR2 share went {small} -> {model.Par2Share} as recovery quadrupled");
    }

    // ---- (b) the rate history ----

    [Fact]
    public void RateHistoryHasNoShapeUntilThereIsOne()
    {
        var rates = new RateHistory();
        Assert.False(rates.HasShape);

        rates.Push(0, 1_000_000);
        Assert.False(rates.HasShape); // one sample is a point, not a shape

        rates.Push(1_000, 2_000_000);
        Assert.True(rates.HasShape);
    }

    /// <summary>
    /// A series of zeroes is not a shape. A job in a phase that moves no bytes would
    /// otherwise draw a flat line along the floor, which reads as a stall rather than
    /// as an absence of measurement.
    /// </summary>
    [Fact]
    public void AllZeroesIsNotAShape()
    {
        var rates = new RateHistory();
        for (var s = 0; s < 30; s++)
        {
            rates.Push(s * 1_000, 0);
        }

        Assert.Equal(30, rates.Count);
        Assert.False(rates.HasShape);
        Assert.True(rates.DisplayMax >= 1, "the scale never divides by zero");
    }

    /// <summary>
    /// THE X AXIS IS ELAPSED SECONDS, NOT POLLS. Twenty snapshots inside one second
    /// are one sample, and the LATEST reading wins - averaging would smooth the series
    /// before the chart's own smoothing got to it.
    /// </summary>
    [Fact]
    public void ManySnapshotsInOneSecondAreOneSample()
    {
        var rates = new RateHistory();
        for (var i = 0; i < 20; i++)
        {
            rates.Push(500 + (i * 10), 1_000_000 + i);
        }

        Assert.Equal(1, rates.Count);
        Assert.Equal(1_000_019, rates.Current);
    }

    /// <summary>
    /// A short gap is carried forward so the axis stays a real time axis; a long one
    /// clears the history rather than manufacturing a flat plateau nobody observed.
    /// </summary>
    [Fact]
    public void AShortGapIsCarriedAndALongOneClears()
    {
        var rates = new RateHistory();
        rates.Push(0, 5_000_000);
        rates.Push(1_000, 6_000_000);

        // Three unobserved seconds, inside the carry budget.
        rates.Push(5_000, 7_000_000);
        Assert.Equal(6, rates.Count);
        Assert.Equal(6_000_000, rates[2]);
        Assert.Equal(6_000_000, rates[4]);
        Assert.Equal(7_000_000, rates[5]);

        // Now a stall past the budget.
        rates.Push(60_000, 8_000_000);
        Assert.Equal(1, rates.Count);
        Assert.Equal(8_000_000, rates.Current);
    }

    /// <summary>
    /// A clock that went backwards means a different run of the job, and drawing across
    /// it would join two unrelated series into one line.
    /// </summary>
    [Fact]
    public void ABackwardClockStartsAgain()
    {
        var rates = new RateHistory();
        rates.Push(30_000, 5_000_000);
        rates.Push(31_000, 5_000_000);
        rates.Push(400, 9_000_000);

        Assert.Equal(1, rates.Count);
        Assert.Equal(9_000_000, rates.Current);
    }

    [Fact]
    public void TheRingHoldsTwoMinutesAndDropsTheOldest()
    {
        var rates = new RateHistory();
        for (var s = 0; s < RateHistory.Capacity + 40; s++)
        {
            rates.Push(s * 1_000, 1_000 + s);
        }

        Assert.Equal(RateHistory.Capacity, rates.Count);
        Assert.Equal(1_000 + RateHistory.Capacity + 39, rates.Current);
        Assert.Equal(1_000 + 40, rates[0]);
    }

    /// <summary>
    /// The VU-meter rule: up instantly so a spike is never clipped, down gently so a
    /// spiky series does not re-scale the whole chart on every sample.
    /// </summary>
    [Fact]
    public void TheScaleRisesInstantlyAndFallsGently()
    {
        var rates = new RateHistory();
        rates.Push(0, 1_000_000);
        rates.Push(1_000, 1_000_000);
        Assert.Equal(1_000_000, rates.DisplayMax, 0);

        rates.Push(2_000, 10_000_000);
        Assert.Equal(10_000_000, rates.DisplayMax, 0);

        // The spike scrolls nowhere yet, so the peak holds the scale up.
        rates.Push(3_000, 1_000_000);
        Assert.Equal(10_000_000, rates.DisplayMax, 0);
    }

    [Fact]
    public void TheScaleEasesDownOnceThePeakLeavesTheWindowAndSnapsUnderReducedMotion()
    {
        RateHistory Filled(bool smooth)
        {
            var h = new RateHistory { SmoothScale = smooth };
            h.Push(0, 10_000_000);
            for (var s = 1; s <= RateHistory.Capacity + 5; s++)
            {
                h.Push(s * 1_000, 1_000_000);
            }

            return h;
        }

        var smoothed = Filled(smooth: true);
        var snapped = Filled(smooth: false);

        Assert.Equal(1_000_000, snapped.DisplayMax, 0);
        Assert.True(smoothed.DisplayMax > snapped.DisplayMax,
            $"eased scale {smoothed.DisplayMax} should still be above the snapped {snapped.DisplayMax}");
        Assert.True(smoothed.DisplayMax < 10_000_000, "and should be on its way down");
    }

    /// <summary>
    /// The trend says nothing for the first fifteen seconds. A comparison over three
    /// samples flaps while the engine's own rate estimate settles, and a figure that
    /// flickers reads as the app being confused rather than the job being uneven.
    /// </summary>
    [Fact]
    public void TheTrendWaitsForEnoughHistory()
    {
        var rates = new RateHistory();
        for (var s = 0; s < 14; s++)
        {
            rates.Push(s * 1_000, 5_000_000);
        }

        Assert.Null(rates.Trend);
        Assert.Equal(string.Empty, rates.TrendText);

        rates.Push(14_000, 5_000_000);
        Assert.NotNull(rates.Trend);
    }

    /// <summary>
    /// The median and not the mean, because one stalled second at zero drags a mean
    /// down and would report a slowdown that did not happen.
    /// </summary>
    [Fact]
    public void OneStalledSecondDoesNotFakeASlowdown()
    {
        var rates = new RateHistory();
        for (var s = 0; s < 30; s++)
        {
            rates.Push(s * 1_000, s == 7 ? 0 : 5_000_000);
        }

        Assert.Equal(0, rates.Trend!.Value, 6);
        Assert.Equal(Strings.ProgressRateSteady, rates.TrendText);
    }

    [Fact]
    public void TheTrendNamesTheDirection()
    {
        var slowing = new RateHistory();
        for (var s = 0; s < 25; s++)
        {
            slowing.Push(s * 1_000, 8_000_000);
        }

        slowing.Push(25_000, 4_000_000);
        Assert.Contains("slower", slowing.TrendText);

        var speeding = new RateHistory();
        for (var s = 0; s < 25; s++)
        {
            speeding.Push(s * 1_000, 4_000_000);
        }

        speeding.Push(25_000, 8_000_000);
        Assert.Contains("faster", speeding.TrendText);
    }

    /// <summary>
    /// A big speed-up must not be clamped to "100% faster". Fmt.Percent clamps its
    /// argument to 0..1, so the wrong formatter here would understate a five times
    /// jump by a factor of four.
    /// </summary>
    [Fact]
    public void ALargeSpeedUpIsNotClampedToOneHundredPerCent()
    {
        var rates = new RateHistory();
        for (var s = 0; s < 25; s++)
        {
            rates.Push(s * 1_000, 1_000_000);
        }

        rates.Push(25_000, 6_000_000);
        Assert.Equal("500% faster than the last minute", rates.TrendText);
    }

    [Fact]
    public void TheVisibleWindowIsTheMostRecentSamples()
    {
        var rates = new RateHistory();
        for (var s = 0; s < 50; s++)
        {
            rates.Push(s * 1_000, s);
        }

        var window = rates.Visible(10);
        Assert.Equal(10, window.Count);
        Assert.Equal(40, window[0]);
        Assert.Equal(49, window[^1]);
        Assert.Equal(50, rates.Visible(500).Count);
    }

    [Fact]
    public void ResetThrowsTheHistoryAway()
    {
        var rates = new RateHistory();
        rates.Push(0, 1_000_000);
        rates.Push(1_000, 1_000_000);
        rates.Reset();

        Assert.Equal(0, rates.Count);
        Assert.False(rates.HasShape);
        Assert.Equal(0, rates.Current);
    }

    // ---- (c) the per-file block strip ----

    /// <summary>
    /// Two files, the second one damaged in its last two blocks. The strips must put
    /// the damage in the SECOND row and leave the first clean, which is the connection
    /// this chart exists to make.
    /// </summary>
    [Fact]
    public void AStripIsTheFilesOwnSliceOfTheSetStrip()
    {
        var states = new BlockState[10];
        for (var i = 0; i < 10; i++)
        {
            states[i] = BlockState.Present;
        }

        states[8] = BlockState.Damaged;
        states[9] = BlockState.Damaged;

        var files = new List<SurveyFile>
        {
            new() { Name = "a.bin", BlocksTotal = 6, BlocksOk = 6, Status = FileStatus.Complete },
            new() { Name = "b.bin", BlocksTotal = 4, BlocksOk = 2, Status = FileStatus.Damaged },
        };

        var strips = FileStripModel.Build(states, files);

        Assert.NotNull(strips[0]);
        Assert.NotNull(strips[1]);
        Assert.Equal(0, strips[0]!.Bad);
        Assert.Equal(2, strips[1]!.Bad);
        Assert.Equal(6, strips[0]!.Blocks);
        Assert.Equal(4, strips[1]!.Blocks);
        Assert.All(strips[0]!.Cells, c => Assert.Null(c.BadMark));
        Assert.Contains(strips[1]!.Cells, c => c.BadMark == BlockState.Damaged);
    }

    /// <summary>
    /// The offsets are a running sum of blocks_total, so they mean nothing if that sum
    /// is not the strip. Refusing is the only safe answer: a plausible strip beside
    /// the wrong name reads as information.
    /// </summary>
    [Fact]
    public void MismatchedTotalsRefuseRatherThanSlideTheOffsets()
    {
        var states = new BlockState[10];
        var files = new List<SurveyFile>
        {
            new() { Name = "a.bin", BlocksTotal = 6 },
            new() { Name = "b.bin", BlocksTotal = 9 }, // 15, not 10
        };

        Assert.All(FileStripModel.Build(states, files), Assert.Null);
    }

    /// <summary>An extra file owns no source blocks and gets no strip, not an empty one.</summary>
    [Fact]
    public void AnExtraFileGetsNoStripAndDoesNotMoveTheOffsets()
    {
        var states = new BlockState[8];
        for (var i = 0; i < 8; i++)
        {
            states[i] = BlockState.Present;
        }

        states[7] = BlockState.Missing;

        var files = new List<SurveyFile>
        {
            new() { Name = "a.bin", BlocksTotal = 4, BlocksOk = 4 },
            new() { Name = "spare.txt", BlocksTotal = 0, Status = FileStatus.Extra },
            new() { Name = "b.bin", BlocksTotal = 4, BlocksOk = 3 },
        };

        var strips = FileStripModel.Build(states, files);
        Assert.Null(strips[1]);
        Assert.Equal(0, strips[0]!.Bad);
        Assert.Equal(1, strips[2]!.Bad);
    }

    /// <summary>
    /// A strip whose picture has not moved comes back as the SAME INSTANCE, which is
    /// what stops a settled table of many rows repainting ten times a second - the
    /// control's dependency property sees no change and does not redraw.
    /// </summary>
    [Fact]
    public void AnUnchangedStripIsTheSameInstance()
    {
        var states = Enumerable.Repeat(BlockState.Present, 8).ToArray();
        var files = new List<SurveyFile>
        {
            new() { Name = "a.bin", BlocksTotal = 4, BlocksOk = 4 },
            new() { Name = "b.bin", BlocksTotal = 4, BlocksOk = 4 },
        };

        var first = FileStripModel.Build(states, files);
        var again = FileStripModel.Build(states, files, first);
        Assert.Same(first[0], again[0]);
        Assert.Same(first[1], again[1]);

        // And a strip whose picture DID move is a new instance, or nothing would ever
        // repaint.
        var moved = states.ToArray();
        moved[5] = BlockState.Damaged;
        var third = FileStripModel.Build(
            moved,
            [files[0], files[1] with { BlocksOk = 3 }],
            again);
        Assert.Same(again[0], third[0]);
        Assert.NotSame(again[1], third[1]);
    }

    /// <summary>
    /// A member with more blocks than the cell budget is merged, and a member with
    /// fewer is NOT inflated: the budget is a ceiling, not a target.
    /// </summary>
    [Fact]
    public void TheCellBudgetIsACeilingAndNotATarget()
    {
        var small = FileStripModel.Build(
            Enumerable.Repeat(BlockState.Present, 8).ToArray(),
            [new SurveyFile { Name = "a", BlocksTotal = 8, BlocksOk = 8 }]);
        Assert.Equal(8, small[0]!.Cells.Count);

        var big = FileStripModel.Build(
            Enumerable.Repeat(BlockState.Present, 5_000).ToArray(),
            [new SurveyFile { Name = "a", BlocksTotal = 5_000, BlocksOk = 5_000 }]);
        Assert.Equal(FileStripModel.TargetCells, big[0]!.Cells.Count);
    }

    /// <summary>
    /// A lone damaged block in a merged member must still leave a tick. This is the
    /// same failure the big map's rule exists to prevent, at a sixtieth of the width,
    /// where it is much easier to lose.
    /// </summary>
    [Fact]
    public void OneDamagedBlockInFiveThousandStillTicks()
    {
        var states = Enumerable.Repeat(BlockState.Present, 5_000).ToArray();
        states[2_500] = BlockState.Damaged;

        var strip = FileStripModel.Build(
            states,
            [new SurveyFile { Name = "a", BlocksTotal = 5_000, BlocksOk = 4_999 }])[0]!;

        Assert.Equal(1, strip.Bad);
        Assert.Single(strip.Cells, c => c.BadMark == BlockState.Damaged);
    }

    [Fact]
    public void TheStripSummaryIsTheRowsCensusInWords()
    {
        var strip = FileStripModel.Build(
            Enumerable.Repeat(BlockState.Present, 32).ToArray(),
            [new SurveyFile { Name = "a", BlocksTotal = 32, BlocksOk = 29 }])[0]!;

        Assert.Equal("29 of 32 blocks present", strip.AccessibleSummary());
    }

    [Fact]
    public void NoStatesMeansNoStrips() =>
        Assert.All(
            FileStripModel.Build([], [new SurveyFile { Name = "a", BlocksTotal = 4 }]),
            Assert.Null);

    // ---- the three charts against the mock's own scenarios ----

    /// <summary>
    /// The real wiring, over every scenario in the catalogue: a strip per member, the
    /// damage in the right row, and the census agreeing with the row's own figure.
    /// </summary>
    /// <remarks>
    /// The unit cases above build states by hand; this one runs the mock's own survey
    /// builder, which is what the screenshots and the demo are driven from. A
    /// disagreement between the two is the interesting kind of failure - it means the
    /// derivation and the fixture read the block order differently.
    /// </remarks>
    [Theory]
    [InlineData("clean")]
    [InlineData("damaged")]
    [InlineData("misnamed")]
    [InlineData("unrepairable")]
    [InlineData("unicode")]
    [InlineData("10k")]
    public void EveryScenarioCutsAStripPerMember(string scenario)
    {
        var set = MockScenarios.ByKey(scenario);
        var survey = MockSurvey.Build(set, fraction: 1, repairing: false, settled: true);
        var map = new BlockMapModel();
        map.Update(survey, 400);

        var strips = FileStripModel.Build(map.States, survey.Files);

        for (var i = 0; i < survey.Files.Count; i++)
        {
            var file = survey.Files[i];
            if (file.BlocksTotal == 0)
            {
                Assert.Null(strips[i]);
                continue;
            }

            var strip = strips[i];
            Assert.NotNull(strip);
            Assert.Equal(file.BlocksTotal, strip!.Blocks);
            Assert.Equal(file.BlocksOk, strip.Ok);

            // A row the survey calls complete cannot carry a bad mark, and a row it
            // calls damaged must. Either way round is a strip drawn over the wrong
            // file's blocks, which is the defect the reconciliation guard is for.
            if (file.Status == FileStatus.Complete)
            {
                Assert.Equal(0, strip.Bad);
            }

            if (file.Status is FileStatus.Damaged or FileStatus.Missing)
            {
                Assert.True(strip.Bad > 0,
                    $"{scenario}: {file.Name} is {file.Status} and its strip has no bad block");
            }
        }
    }

    /// <summary>
    /// Mid-verify, with the cursor part way through, the strips still line up: this is
    /// the state the map is drawn in most of the time and the one where the pending
    /// tail makes an off-by-one easy to miss.
    /// </summary>
    [Fact]
    public void StripsLineUpMidVerify()
    {
        var set = MockScenarios.ByKey("damaged");
        var survey = MockSurvey.Build(set, fraction: 0.45, repairing: false, settled: false);
        var map = new BlockMapModel();
        map.Update(survey, 400);

        var strips = FileStripModel.Build(map.States, survey.Files);
        var members = survey.Files.Count(f => f.BlocksTotal > 0);

        Assert.Equal(members, strips.Count(s => s is not null));
        for (var i = 0; i < survey.Files.Count; i++)
        {
            if (strips[i] is { } strip)
            {
                Assert.Equal(survey.Files[i].BlocksTotal, strip.Blocks);
            }
        }
    }

    /// <summary>
    /// The whole of (a) and (b) through their own view models rather than through the
    /// models directly, because the wiring is where these two have to be right: a
    /// preview recompute must move the bar, and a snapshot must reach the ring buffer.
    /// </summary>
    [Fact]
    public void TheCreateScreenSCostBarFollowsTheRecoverySlider()
    {
        // A stat lambda rather than the real filesystem, which is what makes this
        // runnable on any host: CreateViewModel takes one for exactly this.
        var core = new MockCore();
        var vm = new CreateViewModel(
            core, _ => (2L * 1024 * 1024 * 1024, DateTimeOffset.UnixEpoch, false));
        vm.Add(["/set/a.bin"]);

        vm.ApplyChip(5);
        Assert.True(vm.Cost.HasPlan);
        var small = vm.Cost.Par2Share;

        vm.ApplyChip(20);
        Assert.True(vm.Cost.Par2Share > small,
            $"the cost bar did not move: {small} -> {vm.Cost.Par2Share}");
    }

    [Fact]
    public void TheProgressSheetSRateHistoryFillsFromSnapshots()
    {
        var core = new MockCore();
        var vm = new ProgressViewModel(core);
        var id = core.Submit(JobSpec.ForVerify(new VerifySpec { Par2 = "/set/damaged.par2" }));
        vm.Open(id);

        Assert.False(vm.ShowRateTrend);

        for (var s = 0; s < 20; s++)
        {
            vm.Apply(new QueueSnapshot
            {
                Jobs =
                [
                    new JobSnapshot
                    {
                        Id = id,
                        Kind = JobKind.Verify,
                        State = JobState.Running,
                        ElapsedMs = s * 1_000,
                        RateBytesPerS = 400_000_000,
                        Progress = s / 40.0,
                    },
                ],
            });
        }

        Assert.Equal(20, vm.Rates.Count);
        Assert.True(vm.ShowRateTrend);

        // A FINISHED job must not extend the chart. Its last snapshot arrives on every
        // poll, so pushing unconditionally would grow a flat tail that claims the job
        // is still running at the rate it stopped at.
        for (var i = 0; i < 5; i++)
        {
            vm.Apply(new QueueSnapshot
            {
                Jobs =
                [
                    new JobSnapshot
                    {
                        Id = id,
                        Kind = JobKind.Verify,
                        State = JobState.Done,
                        ElapsedMs = 30_000,
                        RateBytesPerS = 400_000_000,
                        Progress = 1,
                    },
                ],
            });
        }

        Assert.Equal(20, vm.Rates.Count);

        // And a second job in the same sheet starts with a clean chart rather than
        // inheriting the shape of the first.
        vm.Open(id + 1);
        Assert.Equal(0, vm.Rates.Count);
    }
}
