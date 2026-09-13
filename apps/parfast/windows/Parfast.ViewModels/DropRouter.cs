using Parfast.Core;
namespace Parfast.ViewModels;

/// <summary>Where a dropped or opened path belongs.</summary>
public enum DropTarget
{
    Verify,
    ChecksumVerify,
    Create,
}

/// <summary>
/// The global drop routing of plan section 5.1: a .par2 opens Verify &amp;
/// repair, a .sfv / .md5 / .sha1 / .sha256 opens Checksums in verify, and
/// anything else becomes sources for Create.
/// </summary>
/// <remarks>
/// Pure and separate from the shell so it is testable, because a wrong answer
/// here is the most visible bug the app can have: the user's first action is a
/// drop, and routing it to the wrong mode reads as the app not working.
/// <para>
/// A MIXED DROP is decided by the most specific thing in it, not by the first
/// item: dropping a folder and its .par2 together means verify that set, and
/// dropping five files one of which happens to be a .sfv means create a set
/// from all five. That is the reading that matches what the gesture is for.
/// </para>
/// </remarks>
public static class DropRouter
{
    private static readonly string[] ChecksumExtensions = [".sfv", ".md5", ".sha1", ".sha256", ".sha512"];

    public static bool IsPar2(string path) =>
        PathUtil.Extension(path).Equals(".par2", StringComparison.OrdinalIgnoreCase);

    public static bool IsChecksumFile(string path) =>
        ChecksumExtensions.Contains(PathUtil.Extension(path), StringComparer.OrdinalIgnoreCase);

    public static DropTarget Route(IReadOnlyList<string> paths)
    {
        if (paths.Count == 0)
        {
            return DropTarget.Create;
        }

        // A .par2 anywhere in the drop wins: it names a set, which is a
        // stronger statement than a list of files.
        if (paths.Any(IsPar2))
        {
            return DropTarget.Verify;
        }

        // A checksum file wins only when it is the WHOLE drop. Otherwise the
        // drop is a pile of files that happens to include one, and the user
        // means create.
        return paths.All(IsChecksumFile) ? DropTarget.ChecksumVerify : DropTarget.Create;
    }

    /// <summary>The one .par2 to open out of a drop, preferring the index file.</summary>
    public static string? Par2Of(IReadOnlyList<string> paths)
    {
        var par2 = paths.Where(IsPar2).ToList();
        if (par2.Count == 0)
        {
            return null;
        }

        // The INDEX file, not a volume: "x.par2" rather than "x.vol000+100.par2".
        // Opening a volume works in the engine but shows the user a name they
        // did not choose, and the set name is what the header card carries.
        var index = par2.FirstOrDefault(p =>
            !PathUtil.FileNameWithoutExtension(p).Contains(".vol", StringComparison.OrdinalIgnoreCase));
        return index ?? par2.OrderBy(p => p.Length).First();
    }

    public static string? ChecksumFileOf(IReadOnlyList<string> paths) => paths.FirstOrDefault(IsChecksumFile);
}
