using Parfast.Core.Contracts;
using Parfast.Core.Mock;
using Parfast.ViewModels;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// The block map's merge rule, pinned with the numbers that chose it.
/// </summary>
/// <remarks>
/// A PORT of <c>apps/parfast/mac/Tests/ParfastAppTests/BlockMapRuleTests.swift</c>,
/// case for case and number for number, because the rule in
/// <c>apps/parfast/shared/design/blockmap.md</c> is the one thing the two apps
/// must agree on down to the pixel. THE TEST FILE IS THE TABLE: a port that
/// disagrees fails here rather than shipping a second picture of the same data.
/// <para>
/// The two failure modes are opposite and both silent, so both are tested:
/// over-stating damage (a set that is 2% damaged looking a fifth destroyed) and
/// hiding it (one bad block in forty vanishing).
/// </para>
/// </remarks>
public class BlockMapRuleTests
{
    /// <summary>
    /// The mock's ten-thousand-block set: 188 damaged blocks scattered through
    /// four of twenty files, which is what dropped articles look like. Built by
    /// the same arithmetic as the Swift fixture so both sides score the same data.
    /// </summary>
    private static BlockState[] BigSetStates()
    {
        var states = new List<BlockState>(10_000);
        for (var i = 1; i <= 20; i++)
        {
            const int blocks = 500;
            var bad = i is 3 or 7 or 12 or 18 ? 37 + i : 0;
            if (bad == 0)
            {
                states.AddRange(Enumerable.Repeat(BlockState.Present, blocks));
                continue;
            }

            var stride = Math.Max(1, blocks / bad);
            for (var off = 0; off < blocks; off++)
            {
                var isBad = off % stride == 0 && off / stride < bad;
                states.Add(isBad ? BlockState.Damaged : BlockState.Present);
            }
        }

        return states.ToArray();
    }

    private static (int WorstWins, int MajorityGround, int Ticked) Score(
        IReadOnlyList<BlockState> states, int columns)
    {
        int worst = 0, major = 0, ticked = 0;
        for (var c = 0; c < columns; c++)
        {
            var (first, last) = BlockMapRule.Range(c, columns, states.Count);
            if (BlockMapRule.BadMark(states, first, last) is not null)
            {
                worst++;
                ticked++;
            }

            if (BlockMapRule.IsBad(BlockMapRule.Ground(states, first, last)))
            {
                major++;
            }
        }

        return (worst, major, ticked);
    }

    [Fact]
    public void TheMeasurementThatChoseIt()
    {
        var states = BigSetStates();
        Assert.Equal(10_000, states.Length);
        Assert.Equal(188, states.Count(s => s == BlockState.Damaged));

        var s = Score(states, 400);

        // Worst-wins: 78 of 400 cells red, over 19% of the strip, for 1.88% damage.
        Assert.Equal(78, s.WorstWins);
        Assert.True(s.WorstWins / 400.0 > 0.19, $"worst-wins covered {s.WorstWins / 400.0:P1}");

        // Majority alone: the damage is completely invisible.
        Assert.Equal(0, s.MajorityGround);

        // The shipped rule: the ground stays honest about the proportion and every
        // one of those cells still carries a tick.
        Assert.Equal(s.WorstWins, s.Ticked);
    }

    [Fact]
    public void ALoneBadBlockIsNeverHidden()
    {
        var states = Enumerable.Repeat(BlockState.Present, 10_000).ToArray();
        states[4_321] = BlockState.Damaged;

        var s = Score(states, 400);
        Assert.Equal(0, s.MajorityGround);
        Assert.Equal(1, s.Ticked);
    }

    [Fact]
    public void MisnamedIsNotBad()
    {
        Assert.False(BlockMapRule.IsBad(BlockState.Misnamed));
        Assert.True(BlockMapRule.IsBad(BlockState.Damaged));
        Assert.True(BlockMapRule.IsBad(BlockState.Missing));
        Assert.False(BlockMapRule.IsBad(BlockState.Present));
        Assert.False(BlockMapRule.IsBad(BlockState.Pending));
        Assert.False(BlockMapRule.IsBad(BlockState.Hashing));

        // A cell that is all misnamed gets the amber ground and NO tick: the data
        // is on the disk under another name and costs no recovery blocks.
        var states = Enumerable.Repeat(BlockState.Misnamed, 40).ToArray();
        Assert.Null(BlockMapRule.BadMark(states, 0, 39));
        Assert.Equal(BlockState.Misnamed, BlockMapRule.Ground(states, 0, 39));
    }

    [Fact]
    public void GroundBreaksATieTowardsWhatMatters()
    {
        var states = new BlockState[10];
        for (var i = 0; i < 5; i++)
        {
            states[i] = BlockState.Present;
        }

        for (var i = 5; i < 10; i++)
        {
            states[i] = BlockState.Damaged;
        }

        Assert.Equal(BlockState.Damaged, BlockMapRule.Ground(states, 0, 9));
    }

    [Fact]
    public void ASingleBlockCellIsItsOwnState()
    {
        var states = new[]
        {
            BlockState.Present, BlockState.Damaged, BlockState.Missing,
            BlockState.Misnamed, BlockState.Hashing, BlockState.Pending,
        };

        for (var i = 0; i < states.Length; i++)
        {
            var (first, last) = BlockMapRule.Range(i, states.Length, states.Length);
            Assert.Equal(i, first);
            Assert.Equal(i, last);
            Assert.Equal(states[i], BlockMapRule.Ground(states, first, last));
        }
    }

    [Fact]
    public void RangesTileTheWholeStripWithNoGapOrOverlap()
    {
        foreach (var blocks in new[] { 1, 7, 40, 400, 4_000, 10_000, 32_768 })
        {
            foreach (var columns in new[] { 1, 3, 17, 200, 400, 1_280 })
            {
                var covered = new List<int>();
                for (var c = 0; c < Math.Min(columns, blocks); c++)
                {
                    var (first, last) = BlockMapRule.Range(c, Math.Min(columns, blocks), blocks);
                    for (var i = first; i <= last; i++)
                    {
                        covered.Add(i);
                    }
                }

                Assert.Equal(Enumerable.Range(0, blocks), covered);
            }
        }
    }

    [Fact]
    public void TheMarkFloorIsAtLeastTwoDevicePixelsAtOneX() =>
        Assert.True(BlockMapRule.MinimumMarkWidth >= 2);

    [Fact]
    public void TheModelAppliesTheRuleAndReportsTheCensusSeparately()
    {
        // The picture is for proportion and presence; the numbers are for numbers
        // (blockmap.md, rule 3). So the census must be exact even where the ground
        // says "present".
        var survey = new Survey
        {
            BlockRuns = MockSurvey.Encode(BigSetStates()),
            SourceBlocks = 10_000,
        };
        var map = new BlockMapModel();
        map.Update(survey, 400);

        Assert.True(map.Merged);
        Assert.Equal(188, map.Damaged);
        Assert.Equal(9_812, map.Present);
        Assert.Equal(78, map.Cells.Count(c => c.HasBad));
        Assert.Equal(0, map.Cells.Count(c => BlockMapRule.IsBad(c.Ground)));
        Assert.Contains("188", map.AccessibleSummary(), StringComparison.Ordinal);
        Assert.Contains("25", map.MergedNote, StringComparison.Ordinal);
    }
}
