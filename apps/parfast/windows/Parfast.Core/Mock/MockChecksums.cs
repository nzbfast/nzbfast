using Parfast.Core.Contracts;

namespace Parfast.Core.Mock;

/// <summary>
/// The checksum half of the mock (plan section 5.4): a per-file table with
/// OK / Does not match / Missing, and the three counts the snapshot carries.
/// </summary>
public static class MockChecksums
{
    public static JobResult Result(MockSet set, bool verifying)
    {
        var entries = new List<ChecksumEntry>(set.Files.Count);
        var ok = 0;
        var mismatch = 0;
        var missing = 0;

        foreach (var file in set.Files)
        {
            var status = verifying
                ? file.Outcome switch
                {
                    FileStatus.Missing => "missing",
                    FileStatus.Damaged => "mismatch",
                    // A misnamed file is missing under the name the checksum
                    // file gives, which is exactly what a .sfv cannot see and
                    // a PAR2 set can. Worth being honest about in the mock:
                    // it is the difference the Checksums screen exists to show.
                    FileStatus.Misnamed => "missing",
                    FileStatus.Extra => "ok",
                    _ => "ok",
                }
                : "ok";

            switch (status)
            {
                case "ok": ok++; break;
                case "mismatch": mismatch++; break;
                default: missing++; break;
            }

            entries.Add(new ChecksumEntry
            {
                Name = file.Name,
                Expected = Crc32Of(file.Name),
                Actual = status == "ok" ? Crc32Of(file.Name) : status == "mismatch" ? Crc32Of(file.Name + "!") : null,
                Status = status,
            });
        }

        return new JobResult
        {
            Checksum = new ChecksumResult
            {
                Ok = ok,
                Mismatch = mismatch,
                Missing = missing,
                Entries = entries,
            },
        };
    }

    /// <summary>
    /// A real CRC32 of the NAME, not of any content: the mock reads no disk, and
    /// a stable eight hex digits per row is what the table needs. Named for what
    /// it is so nobody mistakes it for a file checksum.
    /// </summary>
    private static string Crc32Of(string text)
    {
        uint crc = 0xFFFFFFFF;
        foreach (var b in System.Text.Encoding.UTF8.GetBytes(text))
        {
            crc ^= b;
            for (var i = 0; i < 8; i++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
            }
        }

        return (~crc).ToString("X8");
    }
}
