using System.Text.RegularExpressions;
using Parfast.Core.Contracts;
using Parfast.Core.Mock;
using Parfast.ViewModels;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// The repo's copy rules over the generated string table, and the number
/// formatting every screen routes through.
/// </summary>
/// <remarks>
/// The copy arm is a GATE, not a nicety: CLAUDE.md invariant 6 bans em-dashes and
/// en-dashes as punctuation and bans one word outright, in any prose or UI copy,
/// and a string table is the largest single pile of UI copy in the app. Catching
/// it here means it cannot reach a screenshot.
/// </remarks>
public class CopyAndFormatTests
{
    [Fact]
    public void NoCopyStringUsesADashAsPunctuation()
    {
        var offenders = Strings.All
            .Where(kv => kv.Value.Contains('—') || kv.Value.Contains('–'))
            .Select(kv => kv.Key)
            .ToList();

        Assert.True(offenders.Count == 0,
            "CLAUDE.md invariant 6: no em-dashes or en-dashes in UI copy. Offending keys: "
            + string.Join(", ", offenders));
    }

    [Fact]
    public void NoCopyStringUsesTheBannedWord()
    {
        // Spelled from its pieces so this assertion does not itself put the word
        // in the tree for the next grep to find.
        var banned = "stream" + "ing";
        var offenders = Strings.All
            .Where(kv => kv.Value.Contains(banned, StringComparison.OrdinalIgnoreCase))
            .Select(kv => kv.Key)
            .ToList();

        Assert.True(offenders.Count == 0,
            $"CLAUDE.md invariant 6 bans that word in user-facing copy. Offending keys: "
            + string.Join(", ", offenders));
    }

    [Fact]
    public void ButtonsAndLabelsAreSentenceCaseAndNotTitleCase()
    {
        // Fluent guidance is sentence case, and so is the mac lane's (plan 5.7).
        // A string with three or more capitalised words that is not a file name or
        // a proper noun is Title Case and reads as a different product.
        //
        // PROPER NOUNS ARE STRIPPED FIRST, because they are capitalised correctly
        // and counting them is how this test cried wolf: "Show the parfast items in
        // the File Explorer menu" is perfectly good sentence case, and File
        // Explorer is the name of a program. A test that flags correct copy gets
        // the copy changed to suit the test, which is the wrong way round.
        var properNouns = new[]
        {
            "File Explorer", "Windows 11", "Windows 10", "Windows", "Explorer", "Finder",
            "Mac", "PC", "PAR2", "PAR", "SFV", "MD5", "SHA-1", "SHA-256", "Show more options",
        };

        var titleCased = new List<string>();
        foreach (var (key, original) in Strings.All)
        {
            if (key.StartsWith('_') || original.Contains('.') || original.Contains('{'))
            {
                continue;
            }

            var value = original;
            foreach (var noun in properNouns)
            {
                value = value.Replace(noun, string.Empty, StringComparison.Ordinal);
            }

            var words = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (words.Length < 3)
            {
                continue;
            }

            var capitalised = words.Skip(1).Count(w => w.Length > 3 && char.IsUpper(w[0]));
            if (capitalised >= 2)
            {
                titleCased.Add($"{key} = \"{original}\"");
            }
        }

        Assert.True(titleCased.Count == 0, "Title Case copy: " + string.Join("; ", titleCased));
    }

    [Fact]
    public void EveryPlaceholderInAFormatStringIsFilledByItsCaller()
    {
        // A copy string with {0} in it that some screen passes no argument to
        // renders the brace on screen. This asserts the shape of the table, which
        // is the half a test can see: every placeholder index is contiguous from
        // zero, so a caller passing the right COUNT cannot miss one.
        foreach (var (key, value) in Strings.All)
        {
            var indexes = Regex.Matches(value, @"\{(\d+)\}")
                .Select(m => int.Parse(m.Groups[1].Value))
                .Distinct()
                .OrderBy(i => i)
                .ToList();
            if (indexes.Count == 0)
            {
                continue;
            }

            Assert.Equal(Enumerable.Range(0, indexes.Count).ToList(), indexes);
        }
    }

    [Fact]
    public void TheOnlyEmptyCopyStringsAreDeliberatelyBlankPlatformArms()
    {
        // A platform split may carry an empty arm, meaning the line does not apply
        // here - settings.integration.win11_note has one on mac, because there is
        // no Show more options menu there. Anything else empty is an accident, and
        // an accidental blank label is invisible on screen, which is why it needs a
        // test rather than an eye.
        var blank = Strings.All.Where(kv => string.IsNullOrWhiteSpace(kv.Value)).Select(kv => kv.Key).ToList();
        Assert.All(blank, key => Assert.True(Strings.IsBlankHere(key), key));

        // And the UI must omit a blank rather than render it: asserted at the one
        // key that has an arm today, so the rule has a live example.
        Assert.False(string.IsNullOrEmpty(Strings.SettingsIntegrationWin11Note),
            "the Windows arm of win11_note is the one that must NOT be blank");
    }

    [Theory]
    [InlineData(0, "0 bytes")]
    [InlineData(512, "512 bytes")]
    [InlineData(1024, "1.00 KiB")]
    [InlineData(1536, "1.50 KiB")]
    [InlineData(1048576, "1.00 MiB")]
    [InlineData(4629702246, "4.31 GiB")]
    [InlineData(107374182400, "100 GiB")]
    public void SizesAreBinaryUnitsWithThousandsSeparators(long bytes, string expected) =>
        Assert.Equal(expected, Fmt.Bytes(bytes));

    [Fact]
    public void OneFileIsSingularAndEverythingElseIsPlural()
    {
        // The shared table carries both forms and using only the plural renders
        // "1 files" - the sort of wrongness a reader notices immediately and a
        // test never does unless it is written.
        Assert.Equal(Strings.CommonOneFile, Fmt.FileCount(1));
        Assert.Equal(Strings.Fill(Strings.CommonFilesCount, "files", "0"), Fmt.FileCount(0));
        Assert.Equal(Strings.Fill(Strings.CommonFilesCount, "files", "23"), Fmt.FileCount(23));
        Assert.Equal(Strings.Fill(Strings.CommonFilesCount, "files", "10,000"), Fmt.FileCount(10_000));
        Assert.DoesNotContain("1 files", Fmt.FileCount(1), StringComparison.Ordinal);
    }

    [Fact]
    public void BigCountsCarrySeparators()
    {
        Assert.Equal("10,000", Fmt.Count(10000));
        Assert.Equal("999", Fmt.Count(999));
    }

    [Theory]
    [InlineData(0, "0 MB/s")]
    [InlineData(1_000_000, "1 MB/s")]
    [InlineData(480_000_000, "480 MB/s")]
    [InlineData(999_000_000, "999 MB/s")]
    [InlineData(1_000_000_000, "1.00 GB/s")]
    [InlineData(8_760_000_000, "8.76 GB/s")]
    public void RatesMatchTheCanonicalThresholds(long bytesPerSecond, string expected) =>
        // Whole MB/s below 1000 and two decimals of GB/s at or above it, the same
        // thresholds as nzbfast's rateParts. See the note in Fmt.
        Assert.Equal(expected, Fmt.Rate(bytesPerSecond));

    [Theory]
    [InlineData(0, "0.0 s")]
    [InlineData(4200, "4.2 s")]
    [InlineData(83000, "1:23")]
    [InlineData(7541000, "2:05:41")]
    public void DurationsReadAsAClock(long ms, string expected) =>
        Assert.Equal(expected, Fmt.Duration(ms));

    [Theory]
    [InlineData("1M", 1048576)]
    [InlineData("1 MiB", 1048576)]
    [InlineData("768000", 768000)]
    [InlineData("4k", 4096)]
    [InlineData("1.5 GiB", 1610612736)]
    [InlineData("1,048,576", 1048576)]
    public void SizesTheUserTypesAreParsedWithTheirSuffix(string text, long expected) =>
        Assert.Equal(expected, Fmt.ParseSize(text));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("banana")]
    [InlineData("-5M")]
    public void AnUnreadableSizeIsNullRatherThanZero(string text) =>
        // Null so the field can show the error. Substituting zero would silently
        // create a set with a four byte block size.
        Assert.Null(Fmt.ParseSize(text));

    [Fact]
    public void EveryBlockColourIsOpaque()
    {
        // A block cell that is not opaque blends into whatever is behind it, and
        // the colours stop meaning what the key says. Translucency in the shared
        // file is for BORDERS and drop fills, never for a state.
        foreach (var token in Tokens.Block.All)
        {
            Assert.Equal(255, token.Light.A);
            Assert.Equal(255, token.Dark.A);
        }
    }

    [Fact]
    public void EveryBlockStateResolvesInBothThemesAndDiffersBetweenThem()
    {
        // A state present in one theme and missing in the other draws as
        // transparent in that theme: a blank strip on one appearance only, which
        // is exactly the defect a screenshot pass in both themes exists to catch.
        // Asserted here so it does not have to be spotted by eye.
        foreach (var state in Enum.GetValues<BlockState>())
        {
            var light = BlockPalette.For(state, dark: false);
            var dark = BlockPalette.For(state, dark: true);
            Assert.NotEqual(0u, light.Argb);
            Assert.NotEqual(0u, dark.Argb);
            Assert.NotEqual(light.Argb, dark.Argb);
        }
    }

    [Fact]
    public void EveryBlockStateOfTheContractHasATokenAtItsOwnWireCode()
    {
        // The C# enum's values ARE the wire codes of survey.block_runs, and the
        // shared tokens file states them too. This is what proves the two agree:
        // a token table that renamed a state but kept its code still resolves,
        // and one that moved a code would fail here rather than on screen.
        foreach (var state in Enum.GetValues<BlockState>())
        {
            Assert.Equal((int)state, BlockPalette.Token(state).Code);
            Assert.False(string.IsNullOrWhiteSpace(BlockPalette.Label(state)));
        }
    }

    [Fact]
    public void AnUnknownWireCodeFallsBackToPendingRatherThanThrowing()
    {
        // The contract lets the core add block states. A redraw at 10 Hz cannot
        // answer one with an exception.
        Assert.Equal(Tokens.Block.Pending.Code, Tokens.Block.ForCode(99).Code);
    }

    [Fact]
    public void TheBlockMapDescribesACellInWordsForTheHoverAndTheScreenReader()
    {
        var states = new List<BlockState>();
        states.AddRange(Enumerable.Repeat(BlockState.Present, 240));
        states.AddRange(Enumerable.Repeat(BlockState.Damaged, 3));
        states.AddRange(Enumerable.Repeat(BlockState.Present, 757));

        var survey = new Survey { BlockRuns = MockSurvey.Encode(states), SourceBlocks = states.Count };
        var map = new BlockMapModel();
        map.Update(survey, 100);

        Assert.True(map.Merged);
        var damaged = map.Cells.First(c => c.Damaged > 0);
        Assert.Contains("damaged", map.Describe(damaged), StringComparison.Ordinal);
        Assert.Matches(@"^Blocks [\d,]+ to [\d,]+: ", map.Describe(damaged));
        Assert.Equal(
            Strings.Fill(Strings.VerifyMapSummary,
                "present", "997", "damaged", "3", "missing", "0", "misnamed", "0", "total", "1,000"),
            map.AccessibleSummary());
    }

    [Fact]
    public void AMergedCellKeepsTheMajorityGroundAndStillMarksTheBadBlock()
    {
        // The whole point of the merge rule, and the case this lane originally got
        // wrong. Thirty nine present blocks and one missing must NOT paint the
        // whole cell as a problem - that is the over-statement chip B measured at
        // 19.5% of the strip for 1.88% damage - and must NOT hide it either. The
        // ground stays present and the tick carries the missing block.
        var states = new List<BlockState>(Enumerable.Repeat(BlockState.Present, 39)) { BlockState.Missing };
        var survey = new Survey { BlockRuns = MockSurvey.Encode(states), SourceBlocks = 40 };
        var map = new BlockMapModel();
        map.Update(survey, 1);

        Assert.Single(map.Cells);
        Assert.Equal(BlockState.Present, map.Cells[0].Ground);
        Assert.Equal(BlockState.Missing, map.Cells[0].BadMark);
        Assert.True(map.Cells[0].HasBad);
    }

    [Fact]
    public void RunLengthEncodingRoundTrips()
    {
        var states = new List<BlockState>();
        var rng = new Random(1234);
        for (var i = 0; i < 5000; i++)
        {
            states.Add((BlockState)rng.Next(0, 6));
        }

        Assert.Equal(states, MockSurvey.Decode(MockSurvey.Encode(states)));
    }

    [Fact]
    public void AnEmptySurveyDrawsNothingRatherThanThrowing()
    {
        var map = new BlockMapModel();
        map.Update(null, 500);
        Assert.Empty(map.Cells);
        Assert.Equal(0, map.BlockCount);
        Assert.Equal("No block information yet.", map.AccessibleSummary());

        map.Update(new Survey(), 0);
        Assert.Empty(map.Cells);
    }
}
