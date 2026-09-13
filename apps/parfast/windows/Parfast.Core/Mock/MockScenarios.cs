using Parfast.Core.Contracts;

namespace Parfast.Core.Mock;

/// <summary>
/// The scripted scenarios of plan section 3.3, one per state the two app
/// lanes have to demonstrate: a clean set, a damaged repairable set, an
/// unrepairable set, a set with misnamed files, unicode names, a
/// ten-thousand-block set for the block map's merge mode, and a long create
/// that can be paused.
/// </summary>
/// <remarks>
/// Picking one: a path whose FILE NAME contains a scenario key selects that
/// scenario, so dropping <c>unrepairable.par2</c> on the mock build shows the
/// unrepairable screen and the demo needs no hidden menu. Anything else gets
/// <see cref="DamagedRepairable"/>, because a set that needs a decision is
/// the more useful default picture and the clean one is one click away.
/// </remarks>
public static class MockScenarios
{
    private const long Mib = 1048576;

    public static MockSet Clean { get; } = new()
    {
        Key = "clean",
        Title = "Clean set, nothing to repair",
        SetName = "ubuntu-24.04-desktop.par2",
        Folder = @"D:\Usenet\complete\ubuntu-24.04-desktop",
        RecoveryAvailable = 100,
        VerifyMs = 5000,
        Files =
        [
            new("ubuntu-24.04-desktop.part01.rar", 500 * Mib, 500, FileStatus.Complete),
            new("ubuntu-24.04-desktop.part02.rar", 500 * Mib, 500, FileStatus.Complete),
            new("ubuntu-24.04-desktop.part03.rar", 500 * Mib, 500, FileStatus.Complete),
            new("ubuntu-24.04-desktop.part04.rar", 500 * Mib, 500, FileStatus.Complete),
            new("ubuntu-24.04-desktop.nfo", 4096, 1, FileStatus.Complete),
        ],
    };

    public static MockSet DamagedRepairable { get; } = new()
    {
        Key = "damaged",
        Title = "Damaged, and repairable",
        SetName = "holiday-photos-2026.par2",
        Folder = @"D:\Usenet\complete\holiday-photos-2026",
        RecoveryAvailable = 40,
        VerifyMs = 7000,
        RepairMs = 5000,
        Files =
        [
            new("holiday-photos-2026.part1.rar", 300 * Mib, 300, FileStatus.Complete),
            new("holiday-photos-2026.part2.rar", 300 * Mib, 300, FileStatus.Damaged, BadBlocks: 9),
            new("holiday-photos-2026.part3.rar", 300 * Mib, 300, FileStatus.Complete),
            new("holiday-photos-2026.part4.rar", 180 * Mib, 180, FileStatus.Damaged, BadBlocks: 3),
            new("holiday-photos-2026.sfv", 2048, 1, FileStatus.Complete),
        ],
    };

    public static MockSet Unrepairable { get; } = new()
    {
        Key = "unrepairable",
        Title = "Not repairable, needs more blocks than exist",
        SetName = "rare-live-set.par2",
        Folder = @"D:\Usenet\incomplete\rare-live-set",
        RecoveryAvailable = 20,
        VerifyMs = 6000,
        Files =
        [
            new("rare-live-set.part1.rar", 240 * Mib, 240, FileStatus.Complete),
            new("rare-live-set.part2.rar", 240 * Mib, 240, FileStatus.Damaged, BadBlocks: 22),
            new("rare-live-set.part3.rar", 240 * Mib, 240, FileStatus.Missing),
            new("rare-live-set.part4.rar", 100 * Mib, 100, FileStatus.Complete),
        ],
    };

    public static MockSet Misnamed { get; } = new()
    {
        Key = "misnamed",
        Title = "Misnamed and moved files, found by content",
        SetName = "abc1234def5678.par2",
        Folder = @"D:\Usenet\complete\abc1234def5678",
        RecoveryAvailable = 60,
        VerifyMs = 6500,
        RepairMs = 1500,
        Files =
        [
            new("Some.Release.2026.1080p.part01.rar", 400 * Mib, 400, FileStatus.Misnamed,
                FoundAs: @"D:\Usenet\complete\abc1234def5678\9f2a1c4b8e.bin"),
            new("Some.Release.2026.1080p.part02.rar", 400 * Mib, 400, FileStatus.Misnamed,
                FoundAs: @"D:\Usenet\complete\abc1234def5678\c81d77a530.bin"),
            new("Some.Release.2026.1080p.part03.rar", 400 * Mib, 400, FileStatus.Complete),
            new("Some.Release.2026.1080p.part04.rar", 260 * Mib, 260, FileStatus.Damaged, BadBlocks: 4),
            new("thumbs.db", 12288, 1, FileStatus.Extra),
        ],
    };

    public static MockSet Unicode { get; } = new()
    {
        Key = "unicode",
        Title = "Unicode file names",
        SetName = "Пример-набора.par2",
        Folder = @"D:\Usenet\complete\Пример-набора",
        // Enough recovery to cover the missing member as well as the damaged
        // one: this scenario exists to prove unicode names survive a whole
        // verify AND repair, so it has to be able to reach the repaired state.
        RecoveryAvailable = 200,
        VerifyMs = 5500,
        RepairMs = 3000,
        Files =
        [
            new("Пример-набора.часть1.rar", 220 * Mib, 220, FileStatus.Complete),
            new("日本語のファイル名.part2.rar", 220 * Mib, 220, FileStatus.Damaged, BadBlocks: 7),
            new("عربي-الملف.part3.rar", 220 * Mib, 220, FileStatus.Complete),
            new("emoji-in-the-name-🎬.part4.rar", 140 * Mib, 140, FileStatus.Missing),
            new("Ελληνικά.nfo", 8192, 1, FileStatus.Complete),
        ],
    };

    /// <summary>
    /// The block map's merge mode: over four thousand cells the map stops
    /// drawing one cell per block and draws proportional segments instead,
    /// so this scenario is the only way to see that code path.
    /// </summary>
    public static MockSet TenThousandBlocks { get; } = new()
    {
        Key = "10k",
        Title = "Ten thousand blocks, merged block map",
        SetName = "bluray-remux-2026.par2",
        Folder = @"E:\Usenet\complete\bluray-remux-2026",
        BlockSize = 4 * Mib,
        RecoveryAvailable = 500,
        VerifyMs = 12000,
        RepairMs = 9000,
        Files = BuildLargeSet(),
    };

    /// <summary>A create long enough to pause, resume and cancel by hand.</summary>
    public static MockSet SlowCreate { get; } = new()
    {
        Key = "slowcreate",
        Title = "A thirty second create",
        SetName = "new-set.par2",
        Folder = @"D:\Work\new-set",
        RecoveryAvailable = 200,
        VerifyMs = 30000,
        RepairMs = 30000,
        Files =
        [
            new("new-set.part1.rar", 700 * Mib, 700, FileStatus.Complete),
            new("new-set.part2.rar", 700 * Mib, 700, FileStatus.Complete),
            new("new-set.part3.rar", 600 * Mib, 600, FileStatus.Complete),
        ],
    };

    /// <summary>A verify that fails outright, for the error path of section 5.2.</summary>
    public static MockSet Broken { get; } = new()
    {
        Key = "broken",
        Title = "A set whose index cannot be read",
        SetName = "truncated.par2",
        Folder = @"D:\Usenet\incomplete\truncated",
        RecoveryAvailable = 0,
        VerifyMs = 1200,
        FailWith = "The index file ends mid packet. It is truncated or not a PAR2 file.",
        Files = [new("truncated.part1.rar", 10 * Mib, 10, FileStatus.Complete)],
    };

    public static IReadOnlyList<MockSet> All { get; } =
    [
        DamagedRepairable, Clean, Unrepairable, Misnamed, Unicode, TenThousandBlocks, SlowCreate, Broken,
    ];

    /// <summary>
    /// Chooses a scenario from a dropped or opened path. Matching on the file
    /// name keeps the demo driveable from Explorer with no build flag.
    /// </summary>
    public static MockSet ForPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return DamagedRepairable;
        }

        var name = PathUtil.FileName(path).ToLowerInvariant();
        foreach (var set in All)
        {
            if (name.Contains(set.Key, StringComparison.Ordinal))
            {
                return set;
            }
        }

        return DamagedRepairable;
    }

    public static MockSet ByKey(string key) =>
        All.FirstOrDefault(s => s.Key == key) ?? DamagedRepairable;

    private static List<MockFile> BuildLargeSet()
    {
        // Forty members of 250 blocks each is 10,000 source blocks. Damage is
        // spread over four of them rather than concentrated, because a
        // merged segment holding one bad block out of forty is the case the
        // merge mode has to render honestly: it must not vanish.
        var files = new List<MockFile>(40);
        for (var i = 1; i <= 40; i++)
        {
            var damaged = i is 7 or 18 or 19 or 33;
            files.Add(new MockFile(
                $"bluray-remux-2026.part{i:D2}.rar",
                250L * 4 * Mib,
                250,
                damaged ? FileStatus.Damaged : FileStatus.Complete,
                BadBlocks: damaged ? (i == 18 ? 61 : 2) : 0));
        }

        return files;
    }
}
