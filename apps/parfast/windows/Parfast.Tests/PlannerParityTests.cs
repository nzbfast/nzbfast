using System.Globalization;
using Parfast.Core;
using Parfast.Core.Contracts;
using Parfast.Core.Mock;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// The mock planner against the REAL one, field by field, over real files.
/// </summary>
/// <remarks>
/// <see cref="PlannerTests"/> pins the mock's arithmetic to numbers measured off the
/// engine and written down; this pins it to the engine ITSELF, so a rule that changes
/// there shows up here as a diff rather than as a stale constant nobody re-measured.
/// <para>
/// WHY BOTH. These tests are SKIPPED when the cdylib has not been built, which is most
/// of the time on a Windows dev box and in any CI job that does not build Rust - a suite
/// that only had this one would be a suite that silently proves nothing. And
/// <see cref="PlannerTests"/> on its own is what let two fields disagree for a fortnight:
/// <c>source_bytes</c> and <c>source_files</c> were unset and <c>padding_pct</c> divided
/// by the source, and no assertion anywhere named them. So the value tests say what the
/// answers ARE and this one says they are still the engine's.
/// </para>
/// <para>
/// Build the library with
/// <c>cargo build --manifest-path apps/parfast/Cargo.toml --release -p parfast-ffi</c>.
/// Nothing else is needed on a dev Mac or on the Windows runner: this project copies
/// <c>target/release/parfast_ffi.dll</c> (or the <c>.dylib</c>) into the test output
/// through a conditional item, and <c>parfast-gui</c>'s <c>cdylib</c> step builds
/// exactly that path, so the P/Invoke resolves and this test DOES run in CI - measured
/// on run 34723537097, 197 passed with the real engine. Its mac twin does not, for a
/// reason written up in
/// <c>the maintainer notes</c>.
/// </para>
/// <para>
/// It is NOT written to fail when the library is absent, and that is deliberate rather
/// than lax: the <c>cdylib</c> step is gated on the FFI tree while <c>dotnet test</c> is
/// gated on the app tree, so a push touching only the app has no library and a failing
/// arm here would redden it. xunit 2.9 has no dynamic skip either, so the early return
/// below is the house pattern (<see cref="FfiIntegrationTests"/> uses it too) and the
/// message is what a reader greps for. The consequence to know: a change that stops the
/// library reaching the output directory turns this test into a silent pass, so if you
/// touch that item or that step, check the log says 197 and not 196.
/// </para>
/// </remarks>
[Collection("ffi")]
public sealed class PlannerParityTests : IDisposable
{
    private readonly string _dir;

    public PlannerParityTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "parfast-parity-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // A temp directory that will not delete is not a test failure.
        }
    }

    /// <summary>
    /// Every field of PlanPreview and PlannedFile, over nine specs that between them
    /// reach all four volume schemes, all three recovery spellings, both block spellings
    /// and both volume namings.
    /// </summary>
    [Fact]
    public void EveryPlanPreviewFieldAgreesWithTheEngine()
    {
        var core = TryOpen(out var why);
        if (core is null)
        {
            Console.WriteLine(
                "parfast_ffi is not beside the test assembly, so the planner parity test did not run. "
                + "Build it with: cargo build --manifest-path apps/parfast/Cargo.toml --release "
                + $"-p parfast-ffi   ({why})");
            return;
        }

        using (core)
        {
            // One line per field per case, compared as two LISTS, so a failure names the
            // case and the field rather than stopping at the first number that moved.
            var fromEngine = new List<string>();
            var fromMock = new List<string>();
            foreach (var (tag, sizes, shape) in Cases())
            {
                var sources = Write(sizes);
                var spec = shape(new CreateSpec
                {
                    Sources = sources.Select(s => new SourceSpec { Path = s.Path }).ToList(),
                    Output = Path.Combine(_dir, "set.par2"),
                    Volumes = VolumeSpec.Pow2(),
                });

                Describe(fromEngine, tag, core.PlanPreview(spec));
                Describe(fromMock, tag, MockPlanner.Plan(spec, sources));
            }

            Assert.Equal(fromEngine, fromMock);
        }
    }

    /// <summary>Every field of one preview, as comparable lines.</summary>
    private static void Describe(List<string> into, string tag, PlanPreview p)
    {
        void Add(string field, object value) => into.Add($"{tag}: {field} = {value}");

        Add("block_size", p.BlockSize);
        Add("block_count", p.BlockCount);
        Add("padding_bytes", p.PaddingBytes);
        Add("padding_pct", p.PaddingPct.ToString("F9", CultureInfo.InvariantCulture));
        Add("efficiency_pct", p.EfficiencyPct.ToString("F9", CultureInfo.InvariantCulture));
        Add("recovery_blocks", p.RecoveryBlocks);
        Add("recovery_percent", p.RecoveryPercent.ToString("F9", CultureInfo.InvariantCulture));
        Add("recovery_bytes", p.RecoveryBytes);
        Add("total_bytes", p.TotalBytes);
        Add("source_bytes", p.SourceBytes);
        Add("source_files", p.SourceFiles);
        Add("files.count", p.Files.Count);
        for (var i = 0; i < p.Files.Count; i++)
        {
            var f = p.Files[i];
            Add($"files[{i}].name", f.Name);
            Add($"files[{i}].blocks", f.Blocks);
            Add($"files[{i}].size", f.Size);
            Add($"files[{i}].efficiency_pct", f.EfficiencyPct.ToString("F9", CultureInfo.InvariantCulture));
        }

        // The command line is compared SWITCH FOR SWITCH and not as one string: both
        // sides end with the same absolute member paths by construction, and the leading
        // switches are the part either side can get wrong.
        Add("command switches", string.Join(" ", Switches(p.Command)));
    }

    /// <summary>The leading switches of a parfast line, up to the first bare argument.</summary>
    private static List<string> Switches(string command) =>
        command.Split(' ').Skip(2).TakeWhile(p => p.StartsWith('-')).ToList();

    private static IEnumerable<(string, long[], Func<CreateSpec, CreateSpec>)> Cases()
    {
        const long mib = 1048576;
        yield return ("two small members at an explicit block size", [5_000, 5_000],
            s => s with { Block = BlockSpec.BySize(4_096) });
        yield return ("the grid search, which is not a division", [40_000, 17_000],
            s => s with { Block = BlockSpec.ByCount(64) });
        yield return ("neither block arm: the reference's default count", [10 * mib],
            s => s with { Recovery = RecoverySpec.ByCount(4) });
        yield return ("no recovery arm: the reference's default percentage", [10 * mib],
            s => s with { Block = BlockSpec.BySize(mib) });
        yield return ("a percentage that floors at one slice", [32_768],
            s => s with { Block = BlockSpec.BySize(1_024), Recovery = RecoverySpec.ByPercent(1) });
        yield return ("a recovery size no unit divides", [1000 * mib],
            s => s with { Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.BySize((100 * mib) + 1) });
        yield return ("scheme none, which is an index and one volume", [100 * mib],
            s => s with
            {
                Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.ByCount(10),
                Volumes = VolumeSpec.None(),
            });
        yield return ("uniform by files, evenly split", [1000 * mib],
            s => s with
            {
                Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.ByCount(100),
                Volumes = VolumeSpec.UniformFiles(7),
            });
        yield return ("uniform by volume size, which pays the packet head", [1000 * mib],
            s => s with
            {
                Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.ByCount(100),
                Volumes = VolumeSpec.UniformFileSize(10 * mib),
            });
        yield return ("bare uniform, which keeps the exponential count", [100 * mib],
            s => s with
            {
                Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.ByCount(20),
                Volumes = new VolumeSpec { Scheme = VolumeScheme.Uniform },
            });
        yield return ("a pow2 ceiling in blocks", [1000 * mib],
            s => s with
            {
                Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.ByCount(100),
                Volumes = VolumeSpec.Pow2LimitBlocks(8),
            });
        yield return ("a pow2 ceiling in bytes", [1000 * mib],
            s => s with
            {
                Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.ByCount(100),
                Volumes = VolumeSpec.Pow2LimitSize(10 * mib),
            });
        yield return ("the spec's own volume naming, offset", [100 * mib],
            s => s with
            {
                Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.ByCount(13),
                StdNaming = true, FirstRecoveryBlock = 95,
            });
        yield return ("a block size over the slice ceiling", [1024 * mib],
            s => s with { Block = BlockSpec.BySize(4_096), Recovery = RecoverySpec.ByCount(2) });
        yield return ("a block count no block size can reach", [mib, mib, mib],
            s => s with { Block = BlockSpec.ByCount(2), Recovery = RecoverySpec.ByCount(1) });
        yield return ("a volume count above the CLI's cap", [1000 * mib],
            s => s with
            {
                Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.ByCount(100),
                Volumes = VolumeSpec.UniformFiles(99),
            });
        yield return ("a fractional recovery percentage", [100 * mib],
            s => s with { Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.ByPercent(7.5) });
        yield return ("an explicit zero recovery", [10 * mib],
            s => s with { Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.ByPercent(0) });
        yield return ("a pow2 ceiling at the largest source, which floors", [(20 * mib) + (mib / 2), 8 * mib],
            s => s with
            {
                Block = BlockSpec.BySize(mib), Recovery = RecoverySpec.ByCount(100),
                Volumes = VolumeSpec.Pow2LargestSource(),
            });
    }

    /// <summary>
    /// Real files of the asked-for sizes: the engine stats every member, and a sparse
    /// file is the cheapest way to give it a gigabyte to measure.
    /// </summary>
    private List<PlannedSource> Write(long[] sizes)
    {
        var dir = Path.Combine(_dir, Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        var sources = new List<PlannedSource>(sizes.Length);
        for (var i = 0; i < sizes.Length; i++)
        {
            var path = Path.Combine(dir, $"part{i + 1:D2}.bin");
            using (var f = File.Create(path))
            {
                f.SetLength(sizes[i]);
            }

            sources.Add(new PlannedSource(path, sizes[i]));
        }

        return sources;
    }

    private static FfiCore? TryOpen(out string? why)
    {
        try
        {
            var core = FfiCore.TryCreate(null, out var error);
            why = error;
            return core;
        }
        catch (DllNotFoundException e)
        {
            why = e.Message;
            return null;
        }
    }
}
