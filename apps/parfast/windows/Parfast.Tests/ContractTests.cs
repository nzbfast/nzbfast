using System.Text.Json;
using Parfast.Core;
using Parfast.Core.Contracts;
using Xunit;

namespace Parfast.Tests;

/// <summary>
/// The FFI wire shapes of research/PLAN-PARFAST-GUI-2026-09-12.md section 4.5,
/// asserted byte for byte where the plan spells them out.
/// </summary>
/// <remarks>
/// THIS IS THE ARTEFACT CHIP A CAN CHECK AGAINST. The contract says the core may
/// ADD fields and enum values and never rename or remove one, and this file is
/// what turns that promise into something with a number on it: if the session
/// crate's serde output differs from what is asserted here, one of the two is
/// wrong and the diff says which field.
/// <para>
/// The enum arms are tested in BOTH directions, and the unknown-value arm is the
/// one that earns its place: a core that grows a new phase must not throw inside
/// a UI poll running ten times a second.
/// </para>
/// </remarks>
public class ContractTests
{
    private static JsonDocument Parse(string json) => JsonDocument.Parse(json);

    [Fact]
    public void ACreateSpecSerialisesToTheShapeInSection45()
    {
        var spec = JobSpec.ForCreate(new CreateSpec
        {
            Sources =
            [
                new SourceSpec { Path = "/abs/a.bin" },
                new SourceSpec { Path = "/abs/dir", Recursive = true },
            ],
            PathMode = PathMode.Relative,
            BasePath = "/abs",
            Block = BlockSpec.BySize(1048576),
            Recovery = RecoverySpec.ByPercent(10.0),
            Output = "/abs/name.par2",
            Volumes = VolumeSpec.UniformFiles(7),
            FirstRecoveryBlock = 0,
            Comment = string.Empty,
            Overwrite = false,
            StdNaming = false,
            Unicode = UnicodePolicy.Auto,
        });

        using var doc = Parse(ParfastJson.Write(spec));
        var root = doc.RootElement;

        Assert.Equal("create", root.GetProperty("kind").GetString());
        var create = root.GetProperty("create");

        var sources = create.GetProperty("sources");
        Assert.Equal(2, sources.GetArrayLength());
        Assert.Equal("/abs/a.bin", sources[0].GetProperty("path").GetString());
        // The first source has no "recursive" key at all, not a null: the contract
        // spells the optional arms by their PRESENCE.
        Assert.False(sources[0].TryGetProperty("recursive", out _));
        Assert.True(sources[1].GetProperty("recursive").GetBoolean());

        Assert.Equal("relative", create.GetProperty("path_mode").GetString());
        Assert.Equal("/abs", create.GetProperty("base_path").GetString());
        Assert.Equal(1048576, create.GetProperty("block").GetProperty("size").GetInt64());
        Assert.False(create.GetProperty("block").TryGetProperty("count", out _));
        Assert.Equal(10.0, create.GetProperty("recovery").GetProperty("percent").GetDouble());
        Assert.Equal("/abs/name.par2", create.GetProperty("output").GetString());
        Assert.Equal("uniform", create.GetProperty("volumes").GetProperty("scheme").GetString());
        Assert.Equal(7, create.GetProperty("volumes").GetProperty("files").GetInt32());
        Assert.Equal(0, create.GetProperty("first_recovery_block").GetInt32());
        Assert.Equal("auto", create.GetProperty("unicode").GetString());
        Assert.False(create.GetProperty("std_naming").GetBoolean());
    }

    [Fact]
    public void TheThreeBlockAndRecoveryArmsEachEmitExactlyOneKey()
    {
        Assert.Equal("{\"size\":1048576}", ParfastJson.Write(BlockSpec.BySize(1048576)));
        Assert.Equal("{\"count\":2000}", ParfastJson.Write(BlockSpec.ByCount(2000)));
        Assert.Equal("{\"percent\":10}", ParfastJson.Write(RecoverySpec.ByPercent(10)));
        Assert.Equal("{\"count\":100}", ParfastJson.Write(RecoverySpec.ByCount(100)));
        Assert.Equal("{\"size\":104857600}", ParfastJson.Write(RecoverySpec.BySize(104857600)));
    }

    [Fact]
    public void EveryVolumeSchemeMatchesItsSpelledOutForm()
    {
        Assert.Equal("{\"scheme\":\"none\"}", ParfastJson.Write(VolumeSpec.None()));
        Assert.Equal("{\"scheme\":\"pow2\"}", ParfastJson.Write(VolumeSpec.Pow2()));
        Assert.Equal("{\"scheme\":\"uniform\",\"files\":7}", ParfastJson.Write(VolumeSpec.UniformFiles(7)));
        Assert.Equal("{\"scheme\":\"uniform\",\"blocks_per_file\":100}",
            ParfastJson.Write(VolumeSpec.UniformBlocksPerFile(100)));
        Assert.Equal("{\"scheme\":\"uniform\",\"file_size\":10485760}",
            ParfastJson.Write(VolumeSpec.UniformFileSize(10485760)));
        Assert.Equal("{\"scheme\":\"pow2_limit\",\"limit\":\"largest_source\"}",
            ParfastJson.Write(VolumeSpec.Pow2LargestSource()));
        Assert.Equal("{\"scheme\":\"pow2_limit\",\"limit\":{\"blocks\":512}}",
            ParfastJson.Write(VolumeSpec.Pow2LimitBlocks(512)));
        Assert.Equal("{\"scheme\":\"pow2_limit\",\"limit\":{\"size\":10485760}}",
            ParfastJson.Write(VolumeSpec.Pow2LimitSize(10485760)));
    }

    [Fact]
    public void AVerifyAndARepairSpecCarryTheirOwnKeys()
    {
        var verify = JobSpec.ForVerify(new VerifySpec
        {
            Par2 = "/abs/x.par2",
            ExtraDirs = ["/abs/other"],
        });

        using var vdoc = Parse(ParfastJson.Write(verify));
        var v = vdoc.RootElement.GetProperty("verify");
        Assert.Equal("verify", vdoc.RootElement.GetProperty("kind").GetString());
        Assert.Equal("/abs/x.par2", v.GetProperty("par2").GetString());
        Assert.Equal("/abs/other", v.GetProperty("extra_dirs")[0].GetString());
        var options = v.GetProperty("options");
        Assert.False(options.GetProperty("rename_only").GetBoolean());
        Assert.False(options.GetProperty("data_skipping").GetBoolean());
        Assert.Equal(64, options.GetProperty("skip_leaway").GetInt32());

        var repair = JobSpec.ForRepair(RepairSpec.From(
            verify.Verify!, purge: true, keepDamaged: false));
        using var rdoc = Parse(ParfastJson.Write(repair));
        var r = rdoc.RootElement.GetProperty("repair");
        Assert.Equal("repair", rdoc.RootElement.GetProperty("kind").GetString());
        Assert.True(r.GetProperty("purge").GetBoolean());
        Assert.False(r.GetProperty("keep_damaged").GetBoolean());
        // Repair carries the same fields as verify, per the contract.
        Assert.Equal("/abs/x.par2", r.GetProperty("par2").GetString());
        Assert.Equal("/abs/other", r.GetProperty("extra_dirs")[0].GetString());
    }

    [Fact]
    public void TheTwoChecksumSpecsMatch()
    {
        using var create = Parse(ParfastJson.Write(JobSpec.ForChecksumCreate(new ChecksumCreateSpec
        {
            Sources = [new SourceSpec { Path = "/abs/a.bin" }],
            Format = ChecksumFormat.Sha256,
            Output = "/abs/x.sha256",
            Relative = true,
        })));
        Assert.Equal("checksum_create", create.RootElement.GetProperty("kind").GetString());
        var cc = create.RootElement.GetProperty("checksum_create");
        Assert.Equal("sha256", cc.GetProperty("format").GetString());
        Assert.True(cc.GetProperty("relative").GetBoolean());

        using var verify = Parse(ParfastJson.Write(
            JobSpec.ForChecksumVerify(new ChecksumVerifySpec { File = "/abs/x.sfv" })));
        Assert.Equal("checksum_verify", verify.RootElement.GetProperty("kind").GetString());
        Assert.Equal("/abs/x.sfv",
            verify.RootElement.GetProperty("checksum_verify").GetProperty("file").GetString());
    }

    [Fact]
    public void TheSnapshotFromSection45ReadsBack()
    {
        // Lifted from the plan, verbatim apart from whitespace: if this ever
        // stops deserialising, the app can no longer read the document the
        // contract promises.
        const string json = """
            {"id":7,"kind":"verify","state":"running",
             "phase":"hashing","phase_text":"Hashing 7 of 23 files","progress":0.43,
             "elapsed_ms":1234,"eta_ms":2345,"rate_bytes_per_s":123456789,
             "low_priority":false,"added_at":"2026-09-12T03:00:00Z",
             "log_tail":["one","two"],
             "survey":{"set_name":"x.par2","folder":"/abs","block_size":1048576,
               "source_blocks":1000,"recovery_available":100,"recovery_needed":12,
               "verdict":"repairable",
               "files":[{"name":"a.bin","size":123,"status":"damaged","blocks_ok":10,
                         "blocks_total":12,"found_as":null,"progress":0.3}],
               "block_runs":[[1,240],[2,3],[1,757]]},
             "result":{"repaired_files":3,"purged":false,
                       "written":[{"name":"x.vol00+01.par2","size":1}],
                       "checksum":{"ok":10,"mismatch":1,"missing":0}},
             "error":null}
            """;

        var snapshot = ParfastJson.Read<JobSnapshot>(json);
        Assert.NotNull(snapshot);
        Assert.Equal(7, snapshot!.Id);
        Assert.Equal(JobKind.Verify, snapshot.Kind);
        Assert.Equal(JobState.Running, snapshot.State);
        Assert.Equal(JobPhase.Hashing, snapshot.Phase);
        Assert.Equal("Hashing 7 of 23 files", snapshot.PhaseText);
        Assert.Equal(0.43, snapshot.Progress, 6);
        Assert.Equal(2345, snapshot.EtaMs);
        Assert.Equal(123456789, snapshot.RateBytesPerS);
        Assert.Equal(2, snapshot.LogTail.Count);
        Assert.Null(snapshot.Error);

        var survey = snapshot.Survey!;
        Assert.Equal(Verdict.Repairable, survey.Verdict);
        Assert.Equal(1000, survey.SourceBlocks);
        Assert.Equal(12, survey.RecoveryNeeded);
        Assert.Equal(FileStatus.Damaged, survey.Files[0].Status);
        Assert.Null(survey.Files[0].FoundAs);
        Assert.Equal(3, survey.BlockRuns.Count);
        Assert.Equal([1, 240], survey.BlockRuns[0]);

        Assert.Equal(3, snapshot.Result!.RepairedFiles);
        Assert.Equal("x.vol00+01.par2", snapshot.Result.Written[0].Name);
        Assert.Equal(10, snapshot.Result.Checksum!.Ok);
    }

    [Fact]
    public void TheQueueSnapshotShapeReadsBack()
    {
        const string json = """
            {"paused":false,"concurrency":1,"post_action":"none","jobs":[]}
            """;
        var queue = ParfastJson.Read<QueueSnapshot>(json);
        Assert.NotNull(queue);
        Assert.False(queue!.Paused);
        Assert.Equal(1, queue.Concurrency);
        Assert.Equal(PostQueueAction.None, queue.PostAction);
        Assert.Empty(queue.Jobs);
    }

    [Fact]
    public void ThePlanPreviewShapeReadsBack()
    {
        const string json = """
            {"block_size":1048576,"block_count":2000,"padding_bytes":12345,"padding_pct":0.02,
             "efficiency_pct":99.98,"recovery_blocks":200,"recovery_percent":10.0,
             "recovery_bytes":209715200,"total_bytes":210000000,
             "files":[{"name":"x.par2","size":40000,"blocks":0,"efficiency_pct":0},
                      {"name":"x.vol000+001.par2","size":1090000,"blocks":1,"efficiency_pct":96.2}],
             "command":"parfast c -s1048576 -r10 -n7 -B /abs /abs/x.par2 a.bin b.bin",
             "warnings":["block count exceeds 32768; increase the block size"]}
            """;
        var preview = ParfastJson.Read<PlanPreview>(json);
        Assert.NotNull(preview);
        Assert.Equal(2000, preview!.BlockCount);
        Assert.Equal(2, preview.Files.Count);
        Assert.Equal(96.2, preview.Files[1].EfficiencyPct, 3);
        Assert.StartsWith("parfast c ", preview.Command, StringComparison.Ordinal);
        Assert.Single(preview.Warnings);
    }

    [Fact]
    public void TheCapabilitiesShapeReadsBack()
    {
        const string json = """
            {"version":"1.5.0","engine":"nzbkit 1.5.0","cpu":"Apple M3 Ultra","kernel":"neon-pmull",
             "std_naming":true,"unicode_policy":true,"data_skipping":true,
             "fast_solver":false,"pause":true,"low_priority":true}
            """;
        var caps = ParfastJson.Read<Capabilities>(json);
        Assert.NotNull(caps);
        Assert.Equal("neon-pmull", caps!.Kernel);
        Assert.True(caps.StdNaming);
        Assert.False(caps.FastSolver);
    }

    [Fact]
    public void AnUnknownEnumValueBecomesUnknownRatherThanThrowing()
    {
        // The contract lets chip A add enum values. A UI polling at 10 Hz cannot
        // answer that with an exception per tick.
        var snapshot = ParfastJson.Read<JobSnapshot>(
            """{"id":1,"kind":"transmute","state":"levitating","phase":"pondering"}""");
        Assert.NotNull(snapshot);
        Assert.Equal(JobKind.Unknown, snapshot!.Kind);
        Assert.Equal(JobState.Unknown, snapshot.State);
        Assert.Equal(JobPhase.Unknown, snapshot.Phase);
    }

    [Fact]
    public void MalformedJsonIsAnErrorStringAndNotAnException()
    {
        var snapshot = ParfastJson.TryRead<JobSnapshot>("{\"id\":1,", out var error);
        Assert.Null(snapshot);
        Assert.NotNull(error);

        Assert.Null(ParfastJson.TryRead<JobSnapshot>(string.Empty, out var empty));
        Assert.Equal("empty response", empty);
    }

    [Fact]
    public void EveryEnumRoundTripsThroughItsWireSpelling()
    {
        AssertRoundTrip<JobKind>();
        AssertRoundTrip<JobState>();
        AssertRoundTrip<JobPhase>();
        AssertRoundTrip<FileStatus>();
        AssertRoundTrip<Verdict>();
        AssertRoundTrip<PathMode>();
        AssertRoundTrip<VolumeScheme>();
        AssertRoundTrip<UnicodePolicy>();
        AssertRoundTrip<ChecksumFormat>();
        AssertRoundTrip<PostQueueAction>();
    }

    private static void AssertRoundTrip<T>() where T : struct, Enum
    {
        foreach (var value in Enum.GetValues<T>())
        {
            var wire = SnakeCaseEnumConverter<T>.WireName(value);
            Assert.Equal(wire.ToLowerInvariant(), wire);
            var json = JsonSerializer.Serialize(value, ParfastJson.Options);
            Assert.Equal($"\"{wire}\"", json);
            Assert.Equal(value, JsonSerializer.Deserialize<T>(json, ParfastJson.Options));
        }
    }

    [Fact]
    public void TheSettingsObjectRoundTripsWholeThroughTheCore()
    {
        var core = new Parfast.Core.Mock.MockCore();
        var defaults = core.GetSettings();

        // The contract says a fresh session's pf_settings_get IS the defaults, so
        // neither app carries a copy. This asserts the app asks rather than knows.
        Assert.Equal("verify", defaults.General.OpenPar2);
        Assert.Equal(2000, defaults.Create.BlockCount);

        var changed = defaults with
        {
            General = defaults.General with { OpenPar2 = "verify_repair" },
            Concurrency = 3,
        };
        Assert.True(core.SetSettings(changed));
        var readBack = core.GetSettings();
        Assert.Equal("verify_repair", readBack.General.OpenPar2);
        Assert.True(readBack.AutoRepairOnOpen);
        Assert.Equal(3, readBack.Concurrency);

        // THE SHAPE IS GROUPED, and a flat object is refused by the core. This is
        // what pins that: five groups plus three top-level scalars, and NO
        // top-level member name. A flat write is how this lane lost a field for a
        // day (crates/parfast-ffi/API.md says so by name).
        using var doc = Parse(ParfastJson.Write(readBack));
        var root = doc.RootElement;
        foreach (var group in new[] { "general", "create", "performance", "integration", "advanced" })
        {
            Assert.True(root.TryGetProperty(group, out var g), $"the {group} group is missing");
            Assert.Equal(System.Text.Json.JsonValueKind.Object, g.ValueKind);
        }

        Assert.Equal("verify_repair", root.GetProperty("general").GetProperty("open_par2").GetString());
        Assert.Equal(3, root.GetProperty("concurrency").GetInt32());
        Assert.Equal("none", root.GetProperty("post_queue_action").GetString());

        // A member name at the top level is exactly what the core refuses, so the
        // app must never emit one. Nor a derived key of its own invention.
        foreach (var misplaced in new[]
                 {
                     "notifications", "open_par2", "on_open", "auto_repair_on_open",
                     "purge_after_repair", "block_count", "threads", "shell_menu", "show_command",
                 })
        {
            Assert.False(root.TryGetProperty(misplaced, out _),
                $"\"{misplaced}\" is a group member and must not appear at the top level");
        }
    }
}
