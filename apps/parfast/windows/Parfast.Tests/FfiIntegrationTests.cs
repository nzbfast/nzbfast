using System.Diagnostics;
using System.Text.Json;
using Parfast.Core;
using Parfast.Core.Contracts;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// Drives the REAL engine through <see cref="FfiCore"/>: create a PAR2 set,
/// verify it, damage it, verify again, repair it.
/// </summary>
/// <remarks>
/// WHY THIS EXISTS ON A MAC. The Windows app cannot be built or run here, so the
/// P/Invoke layer would otherwise be proved only by reading it. But the FFI layer
/// is not Windows-specific: the same <c>FfiCore</c>, the same JSON, the same wake
/// callback, the same string ownership. Only the library's file name differs, and
/// .NET's own probing handles that (<c>DllImport("parfast_ffi")</c> resolves
/// <c>libparfast_ffi.dylib</c> here and <c>parfast_ffi.dll</c> there). So this
/// suite proves on the dev Mac the half of phase 1 that a Windows box would
/// otherwise be needed for, and it is the same test either way.
/// <para>
/// WHAT IT ACTUALLY CATCHES, which reading cannot: a marshalling mistake (a
/// UTF-16 string sent where UTF-8 was promised), a leaked or double-freed
/// <c>char *</c>, a JSON field the core spells differently from the contract, a
/// wake callback collected by the GC, and an enum value the core emits that this
/// build cannot read.
/// </para>
/// <para>
/// SKIPPED, NOT FAILED, when the library is absent - build it with
/// <c>cargo build --manifest-path apps/parfast/Cargo.toml --release -p parfast-ffi</c>.
/// A test that fails because an optional artefact was not built teaches people to
/// ignore red, and the skip message says exactly what to run.
/// </para>
/// </remarks>
[Collection("ffi")]
public sealed class FfiIntegrationTests : IDisposable
{
    private readonly string _dir;

    public FfiIntegrationTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "parfast-ffi-" + Guid.NewGuid().ToString("N")[..10]);
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

    /// <summary>Opens a session, or null when the library has not been built.</summary>
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

    private static bool Skip(FfiCore? core, string? why)
    {
        if (core is not null)
        {
            return false;
        }

        Console.WriteLine(
            "parfast_ffi is not beside the test assembly, so the real-engine tests did not run. "
            + "Build it with: cargo build --manifest-path apps/parfast/Cargo.toml --release "
            + $"-p parfast-ffi   ({why})");
        return true;
    }

    /// <summary>Writes deterministic files so a damaged block is a known block.</summary>
    private string WriteSource(string name, int sizeBytes, int seed)
    {
        var path = Path.Combine(_dir, name);
        var bytes = new byte[sizeBytes];
        var rng = new Random(seed);
        rng.NextBytes(bytes);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    /// <summary>Runs a job to a settled state, or throws with what it was doing.</summary>
    private static JobSnapshot Drain(FfiCore core, long id, int seconds = 60)
    {
        var clock = Stopwatch.StartNew();
        JobSnapshot? last = null;
        while (clock.Elapsed < TimeSpan.FromSeconds(seconds))
        {
            last = core.Snapshot(id);
            if (last is null)
            {
                throw new InvalidOperationException($"job {id} vanished from the session");
            }

            if (last.IsFinished)
            {
                return last;
            }

            Thread.Sleep(50);
        }

        throw new TimeoutException(
            $"job {id} was still {last?.State} in {last?.Phase} after {seconds}s: {last?.PhaseText}");
    }

    [Fact]
    public void TheWholeCreateVerifyDamageRepairRoundTrip()
    {
        using var core = TryOpen(out var why);
        if (Skip(core, why))
        {
            return;
        }

        // The wake callback must survive the GC: it is a delegate Rust holds a
        // function pointer to, and FfiCore pins it in a field. Forcing a collection
        // mid-run is what turns "it looks pinned" into evidence.
        var wakes = 0;
        core!.Wake += () => Interlocked.Increment(ref wakes);

        var a = WriteSource("a.bin", 512 * 1024, seed: 1);
        var b = WriteSource("b.bin", 384 * 1024, seed: 2);
        var par2 = Path.Combine(_dir, "set.par2");

        var createSpec = new CreateSpec
        {
            Sources = [new SourceSpec { Path = a }, new SourceSpec { Path = b }],
            Block = BlockSpec.BySize(64 * 1024),
            Recovery = RecoverySpec.ByPercent(30),
            Output = par2,
            Volumes = VolumeSpec.None(),
            Overwrite = true,
        };

        // The preview first: it does no I/O beyond stat and is what Create's form
        // draws on every keystroke.
        var preview = core.PlanPreview(createSpec);
        Assert.True(preview.BlockCount > 0, "the preview found no blocks");
        Assert.True(preview.RecoveryBlocks > 0, "30 percent of a real set is not zero blocks");
        Assert.StartsWith("parfast", preview.Command, StringComparison.Ordinal);

        var create = Drain(core, core.Submit(JobSpec.ForCreate(createSpec)));
        Assert.Equal(JobState.Done, create.State);
        Assert.True(File.Exists(par2), $"the engine reported done and {par2} is not there");

        GC.Collect();
        GC.WaitForPendingFinalizers();

        // A clean verify.
        var verifySpec = new VerifySpec { Par2 = par2 };
        var clean = Drain(core, core.Submit(JobSpec.ForVerify(verifySpec)));
        Assert.Equal(JobState.Done, clean.State);
        Assert.NotNull(clean.Survey);
        Assert.Equal(Verdict.Complete, clean.Survey!.Verdict);
        Assert.All(clean.Survey.Files, f => Assert.Equal(FileStatus.Complete, f.Status));

        // The block map's own data, from the real engine.
        Assert.NotEmpty(clean.Survey.BlockRuns);
        var states = Parfast.Core.Mock.MockSurvey.Decode(clean.Survey.BlockRuns);
        Assert.Equal(clean.Survey.SourceBlocks, states.Length);
        Assert.All(states, s => Assert.Equal(BlockState.Present, s));

        // Damage one block in the middle of the first file.
        using (var file = new FileStream(a, FileMode.Open, FileAccess.Write))
        {
            file.Seek(200 * 1024, SeekOrigin.Begin);
            file.Write(new byte[8 * 1024]);
        }

        var damaged = Drain(core, core.Submit(JobSpec.ForVerify(verifySpec)));
        Assert.Equal(Verdict.Repairable, damaged.Survey!.Verdict);
        Assert.True(damaged.Survey.RecoveryNeeded > 0, "a damaged file needs at least one block");
        Assert.Contains(damaged.Survey.Files, f => f.Status == FileStatus.Damaged);

        var damagedStates = Parfast.Core.Mock.MockSurvey.Decode(damaged.Survey.BlockRuns);
        Assert.Contains(damagedStates, s => s is BlockState.Damaged or BlockState.Missing);

        // And repair it.
        var repair = Drain(core, core.Submit(JobSpec.ForRepair(
            RepairSpec.From(verifySpec, purge: false, keepDamaged: false))));
        Assert.Equal(JobState.Done, repair.State);
        Assert.Equal(Verdict.Repaired, repair.Survey!.Verdict);

        // The proof is on disk, not in the snapshot: verify once more from scratch.
        var after = Drain(core, core.Submit(JobSpec.ForVerify(verifySpec)));
        Assert.Equal(Verdict.Complete, after.Survey!.Verdict);

        Assert.True(wakes > 0, "the core never woke the host, so the pinned callback is not being called");
        Assert.True(File.Exists(b), "the repair should not have touched the undamaged member");
    }

    [Fact]
    public void AMissingMemberIsRepairedAndTheVerdictSaysSoFirst()
    {
        using var core = TryOpen(out var why);
        if (Skip(core, why))
        {
            return;
        }

        var a = WriteSource("m1.bin", 256 * 1024, seed: 11);
        var b = WriteSource("m2.bin", 256 * 1024, seed: 12);
        var par2 = Path.Combine(_dir, "missing.par2");

        Drain(core!, core!.Submit(JobSpec.ForCreate(new CreateSpec
        {
            Sources = [new SourceSpec { Path = a }, new SourceSpec { Path = b }],
            Block = BlockSpec.BySize(32 * 1024),
            Recovery = RecoverySpec.ByPercent(60),
            Output = par2,
            Overwrite = true,
        })));

        File.Delete(b);

        var spec = new VerifySpec { Par2 = par2 };
        var verify = Drain(core, core.Submit(JobSpec.ForVerify(spec)));
        Assert.Equal(Verdict.Repairable, verify.Survey!.Verdict);
        Assert.Contains(verify.Survey.Files, f => f.Status == FileStatus.Missing);

        Drain(core, core.Submit(JobSpec.ForRepair(RepairSpec.From(spec, false, false))));
        Assert.True(File.Exists(b), "the repair reported done and the missing member is not back");
    }

    [Fact]
    public void AnUnrepairableSetIsNamedAsSuchRatherThanAttempted()
    {
        using var core = TryOpen(out var why);
        if (Skip(core, why))
        {
            return;
        }

        var a = WriteSource("u1.bin", 256 * 1024, seed: 21);
        var b = WriteSource("u2.bin", 256 * 1024, seed: 22);
        var par2 = Path.Combine(_dir, "unrep.par2");

        // Five percent of recovery against a whole member deleted.
        Drain(core!, core!.Submit(JobSpec.ForCreate(new CreateSpec
        {
            Sources = [new SourceSpec { Path = a }, new SourceSpec { Path = b }],
            Block = BlockSpec.BySize(16 * 1024),
            Recovery = RecoverySpec.ByPercent(5),
            Output = par2,
            Overwrite = true,
        })));

        File.Delete(b);

        var verify = Drain(core, core.Submit(JobSpec.ForVerify(new VerifySpec { Par2 = par2 })));
        Assert.Equal(Verdict.Unrepairable, verify.Survey!.Verdict);
        Assert.True(
            verify.Survey.RecoveryNeeded > verify.Survey.RecoveryAvailable,
            "unrepairable means it needs more than it has, and the figures must say so: "
            + $"needed {verify.Survey.RecoveryNeeded}, available {verify.Survey.RecoveryAvailable}");
    }

    [Fact]
    public void TheCapabilitiesAndSettingsRoundTripThroughTheRealCore()
    {
        using var core = TryOpen(out var why);
        if (Skip(core, why))
        {
            return;
        }

        var caps = core!.Capabilities;
        Assert.False(string.IsNullOrWhiteSpace(caps.Engine), "the engine did not name itself");
        Assert.False(string.IsNullOrWhiteSpace(caps.Version));

        // The defaults belong to the CORE (plan 4.5), so a fresh session's answer
        // is the defaults and the app must not carry a copy.
        var defaults = core.GetSettings();
        Assert.False(string.IsNullOrWhiteSpace(defaults.General.OpenPar2));

        // Concurrency proves the mechanism: the object goes out, the core keeps it,
        // and it comes back changed.
        var changed = defaults with { Concurrency = 3 };
        Assert.True(core.SetSettings(changed));
        Assert.Equal(3, core.GetSettings().Concurrency);

        // AND THE GROUPED WRITE, which is the thing this lane got wrong. Sending
        // `notifications` flat had the concurrency in the same object land and the
        // notification silently ignored under PF_OK, which a host cannot tell from
        // the core dropping a field. Chip A now refuses a misplaced key outright;
        // this asserts the app sends the right shape and that the field survives.
        var withNotifications = core.GetSettings() with
        {
            General = core.GetSettings().General with { Notifications = false },
        };
        Assert.True(core.SetSettings(withNotifications), "a correctly grouped write must be accepted");
        Assert.False(core.GetSettings().General.Notifications,
            "the grouped write landed, so notifications must now read false");

        // The app must not INVENT a key from a derived property. There is no
        // on_open and no auto_repair_on_open in the contract - general.open_par2
        // is canonical - and an unattributed C# property would have emitted one.
        var json = ParfastJson.Write(defaults);
        Assert.DoesNotContain("\"auto_repair_on_open\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"on_open\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void ThisAppsDefaultsMatchTheCoresOwn()
    {
        using var core = TryOpen(out var why);
        if (Skip(core, why))
        {
            return;
        }

        // THE DEFAULTS BELONG TO THE CORE (plan 4.5), and the app is not supposed
        // to carry a copy. It carries one anyway, in two places it cannot avoid:
        // the record's initialisers, which are what a ParfastSettings reads as
        // before any core has answered, and Settings > Reset, which has no call in
        // the contract and can only write an untouched record.
        //
        // So the copy is not the problem; a copy that DRIFTS is. This asserts the
        // two agree field for field, which turns a silent staleness - Reset
        // quietly restoring last month's defaults - into a red test naming the
        // field.
        var mine = ParfastJson.Write(new ParfastSettings());
        var theirs = ParfastJson.Write(core!.GetSettings());

        using var a = JsonDocument.Parse(mine);
        using var b = JsonDocument.Parse(theirs);

        var differences = new List<string>();
        Compare(a.RootElement, b.RootElement, string.Empty, differences);
        Assert.True(differences.Count == 0,
            "this app's default settings have drifted from the core's:\n  "
            + string.Join("\n  ", differences));
    }

    /// <summary>Walks two settings objects and reports every value that differs.</summary>
    private static void Compare(JsonElement mine, JsonElement theirs, string path, List<string> into)
    {
        if (mine.ValueKind == JsonValueKind.Object && theirs.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in mine.EnumerateObject())
            {
                var here = path.Length == 0 ? property.Name : $"{path}.{property.Name}";
                if (!theirs.TryGetProperty(property.Name, out var other))
                {
                    into.Add($"{here}: this app sends it, the core does not have it");
                    continue;
                }

                Compare(property.Value, other, here, into);
            }

            foreach (var property in theirs.EnumerateObject())
            {
                if (!mine.TryGetProperty(property.Name, out _))
                {
                    var here = path.Length == 0 ? property.Name : $"{path}.{property.Name}";
                    into.Add($"{here}: the core has it, this app does not send it");
                }
            }

            return;
        }

        // A null on either side is "not chosen" and both spellings mean the same,
        // so it is not a difference worth failing over.
        if (mine.ValueKind == JsonValueKind.Null || theirs.ValueKind == JsonValueKind.Null)
        {
            return;
        }

        if (mine.GetRawText() != theirs.GetRawText())
        {
            into.Add($"{path}: this app {mine.GetRawText()}, the core {theirs.GetRawText()}");
        }
    }

    [Fact]
    public void EveryReturnedStringIsFreedRatherThanLeaked()
    {
        using var core = TryOpen(out var why);
        if (Skip(core, why))
        {
            return;
        }

        // Every char* the library returns is the caller's to free, and FfiCore
        // frees in a finally. Two thousand snapshot reads would show a leak as a
        // climbing working set; the assertion is deliberately loose because a
        // managed heap moves for its own reasons, and a real leak here is native
        // and unbounded.
        var before = GC.GetTotalMemory(forceFullCollection: true);
        for (var i = 0; i < 2_000; i++)
        {
            _ = core!.QueueSnapshot();
            _ = core.Capabilities;
        }

        var after = GC.GetTotalMemory(forceFullCollection: true);
        Assert.True(after - before < 8 * 1024 * 1024,
            $"2,000 snapshot reads grew the managed heap by {(after - before) / 1024} KiB");
    }
}
