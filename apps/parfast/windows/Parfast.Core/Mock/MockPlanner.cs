using System.Globalization;
using System.Text;
using Parfast.Core.Contracts;

namespace Parfast.Core.Mock;

/// <summary>
/// The create planner, as the mock implements it: block sizing, padding and
/// efficiency, the recovery allocation, the volume layout for all four
/// schemes, and the equivalent <c>parfast</c> command line.
/// </summary>
/// <remarks>
/// THIS IS A MOCK AND ALSO A SPECIFICATION. When chip A's
/// <c>parfast-session::planner</c> lands, <c>FfiCore</c> answers
/// pf_plan_preview and this class stops being on the screen path, but the
/// unit tests over it in Parfast.Tests are the arithmetic both sides must
/// agree on, which is what makes a disagreement at integration a finding
/// rather than a surprise.
/// <para>
/// The switch letters come from <c>crates/parfast/src/cli.rs</c> read on
/// 12 Sep 2026 (par2cmdline dialect): <c>-s</c> block size, <c>-b</c> block
/// count, <c>-r</c> redundancy percent, <c>-c</c> recovery block count,
/// <c>-f</c> first block, <c>-u</c> uniform, <c>-l</c> limited, <c>-n</c>
/// recovery file count, <c>-R</c> recursive, <c>-B</c> base path. A switch
/// invented here would produce a Copy command button that pastes a line the
/// CLI refuses, which is worse than no button.
/// </para>
/// </remarks>
public static class MockPlanner
{
    /// <summary>PAR2 requires the block size to be a multiple of four.</summary>
    public const long BlockSizeMultiple = 4;

    /// <summary>
    /// The PAR2 spec's input-slice ceiling (<c>par2gen::MAX_INPUT_SLICES</c>), and
    /// the engine ENFORCES it rather than warning: see <see cref="ResolveBlockSize"/>.
    /// </summary>
    public const int MaxInputSlices = 32768;

    /// <summary>
    /// The CLI's cap on recovery files (<c>parfast::help::MAX_RECOVERY_FILES</c>).
    /// THIRTY-ONE, not 32,768 - the mac mock read it as the latter, which is three
    /// orders out and makes the clamp unreachable.
    /// </summary>
    public const int MaxRecoveryFiles = 31;

    /// <summary>A recovery slice on disk carries a packet header of this size.</summary>
    private const int SlicePacketOverhead = 68;

    public static PlanPreview Plan(CreateSpec spec, IReadOnlyList<PlannedSource> sources)
    {
        if (sources.Count == 0)
        {
            return PlanPreview.Empty;
        }

        var totalBytes = sources.Sum(s => s.Size);
        var warnings = new List<string>();

        var blockSize = ResolveBlockSize(spec.Block, totalBytes, sources, warnings);
        var blockCount = sources.Sum(s => CeilDiv(s.Size, blockSize));
        var blockCountInt = (int)Math.Min(blockCount, int.MaxValue);

        var slicedBytes = blockCount * blockSize;
        var padding = slicedBytes - totalBytes;
        // PADDING AS A SHARE OF THE PADDED GRID, NOT OF THE SOURCE, and this was the
        // other way round until 12 Sep 2026. The real planner is `pct(padding_bytes,
        // padded)` and its efficiency is `pct(source_bytes, padded)`, so the two are
        // COMPLEMENTS and sum to a hundred; dividing by the source instead makes them
        // two unrelated numbers on one screen. On the engine's own fixture - two 5,000
        // byte members at a 4,096 block - the padded grid is 16,384 and the padding
        // 6,384, so the engine says 38.96% and this used to say 63.84% for the same
        // set. Nothing pinned it, because PlannerTests pinned the BYTES and left the
        // percentage alone.
        var paddingPct = slicedBytes == 0 ? 0 : (double)padding / slicedBytes * 100.0;
        var efficiency = slicedBytes == 0 ? 0 : (double)totalBytes / slicedBytes * 100.0;

        var recoveryBlocks = ResolveRecoveryBlocks(spec.Recovery, blockCountInt, blockSize);
        var recoveryPercent = blockCountInt == 0 ? 0 : (double)recoveryBlocks / blockCountInt * 100.0;

        // `-r` is an INTEGER percent in the reference's dialect, so a fractional ask
        // is rounded and said out loud rather than quietly taken as something else.
        // The engine warns here too, from `planner::options_for`.
        if (spec.Recovery.Percent is { } askedPct)
        {
            var whole = Math.Round(askedPct, MidpointRounding.AwayFromZero);
            if (Math.Abs(whole - askedPct) > double.Epsilon)
            {
                warnings.Add($"The reference takes whole percents, so {Trim(askedPct)}% was taken as "
                             + $"{Trim(whole)}%. Use a recovery block count for finer control.");
            }
        }

        if (recoveryBlocks == 0)
        {
            warnings.Add("No recovery blocks. The set can detect damage but not repair it.");
        }

        // A SET THE CREATE WOULD REFUSE. PAR2 numbers recovery blocks up to 65,535 and
        // the engine refuses a create that would run past it
        // (<c>par2gen::check_create_inputs</c>), so the pane says it rather than letting
        // a poster find out when the job fails. The engine's own preview grew this
        // warning on 12 September 2026 - it had the refusal and no warning, which is the
        // one shape worse than not checking - and the mac mock already had it.
        if ((long)spec.FirstRecoveryBlock + recoveryBlocks > 65_535)
        {
            warnings.Add("PAR2 numbers recovery blocks up to 65,535, and this set would run past "
                         + "that, so the create would refuse it. Lower the recovery or the first "
                         + "recovery block.");
        }

        var indexSize = IndexSize(sources, blockSize);
        var files = new List<PlannedFile>(8) { new()
        {
            Name = PathUtil.FileName(spec.Output),
            Size = indexSize,
            Blocks = 0,
            EfficiencyPct = 0,
        } };

        var stem = StemOf(spec.Output);
        var layout = VolumeLayout(spec.Volumes, recoveryBlocks, blockSize, sources, warnings);

        // THE COUNT THE LINE SPELLS IS THE ONE THAT WAS ASKED FOR, and the layout is that
        // capped by the slice count - a set of four slices asked for seven volumes writes
        // four and still pastes `-n7`, because `recovery_file_count` does the capping at
        // the other end. Spelling the capped number instead would be a line that builds
        // the same set by a different route, which is a preview describing itself rather
        // than the create.
        var askedVolumes = spec.Volumes.Scheme == VolumeScheme.Uniform
            ? UniformVolumeCount(spec.Volumes, recoveryBlocks, blockSize)
            : layout.Count;

        // The widths are the WHOLE SET's, so the names need the finished layout -
        // which is why this is a function over the list and not over one volume,
        // exactly as `parfast::create::final_volume_names` is.
        var names = VolumeNames(stem, layout, spec.FirstRecoveryBlock, recoveryBlocks, spec.StdNaming);
        for (var i = 0; i < layout.Count; i++)
        {
            var blocks = layout[i];
            var size = VolumeSize(sources, blockSize, blocks);
            files.Add(new PlannedFile
            {
                Name = names[i],
                Size = size,
                Blocks = blocks,
                EfficiencyPct = Efficiency(blocks, blockSize, size),
            });
        }

        return new PlanPreview
        {
            BlockSize = blockSize,
            BlockCount = blockCountInt,
            PaddingBytes = padding,
            PaddingPct = paddingPct,
            EfficiencyPct = efficiency,
            RecoveryBlocks = recoveryBlocks,
            RecoveryPercent = recoveryPercent,

            // THE RECOVERY PAYLOAD, not the bytes the volumes take up, and this
            // line read `files.Sum(f => f.Size) - indexSize` until 12 Sep 2026.
            // The real planner is `recovery.saturating_mul(block_size)` - slices
            // times slice size, and nothing else - so the mock's answer carried
            // every volume's 68-byte packet heads and its repeated copies of the
            // critical block as though they were parity. Measured against the
            // engine over 31 blocks of 1 MiB: 32,505,856 where this reported
            // 32,542,924, and the gap GROWS with the volume count - so the two
            // agreed most closely in the single-volume case a reader would check
            // by hand.
            RecoveryBytes = recoveryBlocks * blockSize,
            TotalBytes = files.Sum(f => f.Size),

            // THE TWO FIELDS API.md MARKS **ADDED**, and they were UNSET here until
            // 12 Sep 2026 - the real planner
            // (apps/parfast/crates/parfast-session/src/planner.rs) fills both and this
            // one answered zero for both. It was invisible while nothing drew them and
            // stopped being invisible the moment the create screen's cost bar did: with
            // source_bytes zero, the bar's whole is the PAR2 set alone, so it drew a
            // hundred per cent recovery over a two gigabyte source and did it
            // confidently. Chip C's own note says this class is a mock AND a
            // specification; a field the specification simply does not mention is the
            // quietest way for the two to disagree.
            SourceBytes = totalBytes,
            SourceFiles = sources.Count,
            Files = files,
            Command = CommandLine(spec, sources, blockSize, recoveryBlocks, askedVolumes),
            Warnings = warnings,
        };
    }

    /// <summary>
    /// Resolves the block size from either arm of the contract's block spec.
    /// </summary>
    /// <remarks>
    /// A requested COUNT is turned into a size, because the size is the quantity
    /// the format actually stores, and it is rounded to the multiple of four the
    /// format requires.
    /// <para>
    /// The count is found by BINARY SEARCH and not by dividing the total, and
    /// that matters. A block never spans a file boundary, so the count is the sum
    /// of per-file ceilings, and dividing the total by the wanted count overshoots
    /// by up to one block per file: 1,537 MiB over three files asked for 10
    /// blocks divides to 153.7 MiB and yields 5 + 5 + 1 = ELEVEN. Overshooting is
    /// not cosmetic, because 32,768 is a hard ceiling in other PAR2 tools and a
    /// set that quietly crosses it is a set they refuse. The count falls
    /// monotonically as the size grows, so the search is for the SMALLEST size
    /// whose count is at or under what was asked, which is also the count closest
    /// to it.
    /// </para>
    /// <para>
    /// A count below the FILE COUNT is unreachable at any block size. The search
    /// returns the largest size it tried and warns, rather than looping or
    /// pretending: the honest screen says the number cannot be had and why.
    /// </para>
    /// </remarks>
    public static long ResolveBlockSize(
        BlockSpec block, long totalBytes, IReadOnlyList<PlannedSource> sources, List<string> warnings)
    {
        if (block.Size is { } size and > 0)
        {
            var rounded = RoundUpTo(size, BlockSizeMultiple);
            if (rounded != size)
            {
                warnings.Add($"The block size was raised to {rounded:N0} bytes, the next multiple of 4.");
            }

            return LegalBlockSize(sources, rounded, warnings);
        }

        var wanted = Math.Max(1, block.Count ?? 2000);
        if (sources.Count == 0)
        {
            return Math.Max(BlockSizeMultiple, RoundUpTo(totalBytes / wanted, BlockSizeMultiple));
        }

        int CountAt(long candidate) => (int)Math.Min(int.MaxValue, sources.Sum(s => CeilDiv(s.Size, candidate)));

        var largest = sources.Max(s => s.Size);
        var lo = BlockSizeMultiple;
        var hi = Math.Max(BlockSizeMultiple, RoundUpTo(largest, BlockSizeMultiple));

        if (CountAt(hi) > wanted)
        {
            // UNREACHABLE AT ANY BLOCK SIZE, because a block never spans a file boundary.
            // The engine's search simply runs out - it steps up by four until the size
            // reaches the payload itself, which is one block per member - so the answer is
            // the whole payload rounded up to a multiple of four, and NOT the largest
            // member, which is where this landed until 12 September 2026. Measured through
            // pf_plan_preview over three 1 MiB members at -b2: 3,145,728 bytes, three
            // slices. The warning is this mock's own; the engine says nothing here, which
            // is a gap written up in the handoff rather than papered over.
            warnings.Add(
                $"{wanted:N0} blocks is fewer than the {sources.Count:N0} files in the set, and every file "
                + $"needs at least one block, so the set has {CountAt(hi):N0}.");
            return LegalBlockSize(sources, Math.Max(BlockSizeMultiple, RoundUpTo(totalBytes, BlockSizeMultiple)), warnings);
        }

        // Invariant: CountAt(hi) <= wanted, and CountAt(lo) is either over or
        // exactly at it. Halve until they meet on the multiple-of-four grid.
        while (lo < hi)
        {
            var mid = RoundUpTo(lo + ((hi - lo) / 2), BlockSizeMultiple);
            if (mid >= hi)
            {
                break;
            }

            if (CountAt(mid) <= wanted)
            {
                hi = mid;
            }
            else
            {
                lo = mid + BlockSizeMultiple;
            }
        }

        return LegalBlockSize(sources, hi, warnings);
    }

    /// <summary>
    /// Raises a slice size until the set fits <see cref="MaxInputSlices"/>, and says so.
    /// </summary>
    /// <remarks>
    /// THE ENGINE ENFORCES THE CEILING; this class only WARNED about it until
    /// 12 September 2026, and kept the illegal size - so the preview drew a block
    /// size and a block count the create would never use. Measured on the engine
    /// over one gibibyte at a 4,096 block: it answers 32,768 and 32,768 blocks with
    /// the warning below, where this answered 4,096 and 262,144 blocks.
    /// <para>
    /// It raises to a MULTIPLE of what was asked for, not to the first size that
    /// happens to fit, and that is not cosmetic: Usenet loses whole articles, and a
    /// block size that is an exact multiple of the article size never lets an
    /// article straddle two blocks. <c>parfast::create::legal_block_size</c> carries
    /// the measurements; this is the same search.
    /// </para>
    /// </remarks>
    public static long LegalBlockSize(
        IReadOnlyList<PlannedSource> sources, long asked, List<string> warnings)
    {
        long CountAt(long candidate) => sources.Sum(x => CeilDiv(x.Size, candidate));

        if (asked <= 0 || CountAt(asked) <= MaxInputSlices)
        {
            return asked;
        }

        var total = sources.Sum(x => x.Size);
        var step = Math.Max(BlockSizeMultiple, asked);
        for (var mult = 2L; step * mult <= Math.Max(total, BlockSizeMultiple); mult++)
        {
            var candidate = step * mult;
            if (CountAt(candidate) <= MaxInputSlices)
            {
                warnings.Add($"A block size of {asked:N0} would put the set over the spec's "
                             + $"{MaxInputSlices:N0} input slices, so {candidate:N0} is used.");
                return candidate;
            }
        }

        // No multiple fits before the payload itself does. One slice per member
        // always satisfies the ceiling, so creep up from the finest legal size.
        var bs = Math.Max(step, RoundUpTo(total / MaxInputSlices, BlockSizeMultiple));
        while (bs < Math.Max(total, BlockSizeMultiple) && CountAt(bs) > MaxInputSlices)
        {
            bs += BlockSizeMultiple;
        }

        warnings.Add($"A block size of {asked:N0} would put the set over the spec's "
                     + $"{MaxInputSlices:N0} input slices, so {bs:N0} is used.");
        return bs;
    }

    /// <summary>The engine's default redundancy when the spec names none (<c>-r5</c>).</summary>
    public const int DefaultRedundancyPct = 5;

    /// <summary>
    /// How many recovery slices the spec asks for, by the engine's own three rules.
    /// </summary>
    /// <remarks>
    /// Each arm was wrong here in a different way until 12 September 2026, and each
    /// is measured off <c>parfast::create::recovery_blocks</c>:
    /// <list type="bullet">
    /// <item>a SIZE is <c>bytes.div_ceil(block)</c>, a ceiling. This floor-divided,
    /// so 100 MiB + 1 byte at a 1 MiB block asked for 100 slices where the engine
    /// allocates 101 - a target the set does not actually reach.</item>
    /// <item>a PERCENTAGE is round-to-nearest with a FLOOR OF ONE BLOCK, measured
    /// against par2cmdline-turbo. This had the rounding and not the floor, so
    /// <c>-r1</c> over 32 blocks drew a set with NO recovery at all where the engine
    /// writes one slice - and then warned that the set could not repair.</item>
    /// <item>NOTHING GIVEN is the reference's 5%, not zero. All three properties are
    /// nullable, so "the user has not chosen yet" is a state the contract can hold,
    /// and it is the state a freshly opened Create pane is in.</item>
    /// </list>
    /// A fractional percentage is rounded to a whole one BY THE ENGINE, because
    /// <c>-r</c> is an integer percent in the reference's dialect; that rounding lives
    /// in <see cref="Plan"/>, where there is a warning list to say so in.
    /// </remarks>
    public static int ResolveRecoveryBlocks(RecoverySpec recovery, int blockCount, long blockSize)
    {
        if (recovery.Count is { } count)
        {
            return Math.Max(0, count);
        }

        if (recovery.Size is { } bytes)
        {
            return blockSize <= 0 ? 0 : (int)Math.Max(0, CeilDiv(bytes, blockSize));
        }

        var pct = recovery.Percent ?? DefaultRedundancyPct;
        return PercentBlocks(blockCount, (int)Math.Max(0, Math.Round(pct, MidpointRounding.AwayFromZero)));
    }

    /// <summary>
    /// The reference's percentage rule: round to nearest, halves up, and never fewer
    /// than one block when a non-zero percentage was asked for
    /// (<c>parfast::create::percent_blocks</c>, probed against par2cmdline-turbo 1.5.0
    /// over 32 blocks: -r49 to 16, -r50 to 16, -r51 to 16, -r52 to 17, -r1 to 1).
    /// </summary>
    public static int PercentBlocks(int blockCount, int pct) =>
        pct <= 0 || blockCount <= 0 ? 0 : Math.Max(1, (int)(((long)blockCount * pct + 50) / 100));

    /// <summary>
    /// Blocks per recovery volume, in file order. Empty only when the set has no
    /// recovery at all.
    /// </summary>
    /// <remarks>
    /// THE "NONE" SCHEME IS NOT AN EMPTY LAYOUT, and it was one here until
    /// 12 September 2026 - the index file grew to carry the recovery itself, so the
    /// preview listed ONE file. The engine writes TWO: a <c>-n1</c> create is an index
    /// carrying the critical packets and no parity, plus a single volume carrying
    /// every recovery slice (measured: <c>set.par2</c> at 2,384 bytes beside
    /// <c>set.vol00+10.par2</c> at 10,495,736). A preview that merges them under-counts
    /// the file list by one and mis-states both sizes.
    /// <para>
    /// The uniform arms resolve a volume COUNT and then split evenly, which is what
    /// the engine does (<c>recovery_file_count</c> into <c>par2gen::VolumePlan::Even</c>)
    /// and is not the same as taking blocks-per-file off the front until the blocks run
    /// out: an even split gives the REMAINDER TO THE FIRST volumes, so 100 slices over
    /// 7 files are 15 15 14 14 14 14 14 and never 15 15 15 15 15 15 10.
    /// </para>
    /// </remarks>
    public static List<int> VolumeLayout(
        VolumeSpec volumes, int recoveryBlocks, long blockSize,
        IReadOnlyList<PlannedSource> sources, List<string>? warnings = null)
    {
        var layout = new List<int>();
        if (recoveryBlocks <= 0)
        {
            return layout;
        }

        switch (volumes.Scheme)
        {
            // `-n1`: one volume holding everything, beside the index.
            case VolumeScheme.None:
                return EvenSplit(recoveryBlocks, 1);

            case VolumeScheme.Uniform:
                return EvenSplit(recoveryBlocks, UniformVolumeCount(volumes, recoveryBlocks, blockSize));

            case VolumeScheme.Pow2:
            case VolumeScheme.Pow2Limit:
            {
                var cap = volumes.Scheme == VolumeScheme.Pow2Limit
                    ? Pow2Cap(volumes, blockSize, sources, warnings)
                    : int.MaxValue;
                var remaining = recoveryBlocks;
                var step = 1;
                while (remaining > 0)
                {
                    var take = Math.Min(Math.Min(step, cap), remaining);
                    layout.Add(take);
                    remaining -= take;
                    if (step < cap && step <= int.MaxValue / 2)
                    {
                        step *= 2;
                    }
                }

                break;
            }
        }

        return layout;
    }

    /// <summary>
    /// <c>par2gen::VolumePlan::Even</c>: <c>k</c> volumes of <c>n/k</c> slices, with the
    /// remainder going to the FIRST volumes.
    /// </summary>
    public static List<int> EvenSplit(int recoveryBlocks, int volumes)
    {
        var k = Math.Clamp(volumes, 1, Math.Max(1, recoveryBlocks));
        var (baseBlocks, remainder) = (recoveryBlocks / k, recoveryBlocks % k);
        var layout = new List<int>(k);
        for (var i = 0; i < k; i++)
        {
            layout.Add(baseBlocks + (i < remainder ? 1 : 0));
        }

        return layout;
    }

    /// <summary>
    /// How many volumes the uniform scheme's three spellings mean
    /// (<c>parfast::create::recovery_file_count</c> and the planner's own translation).
    /// </summary>
    /// <remarks>
    /// All three resolve to a COUNT, which is the only thing the reference's <c>-n</c>
    /// can say. A file SIZE divides by the slice's cost ON DISK - the block plus the
    /// writer's 68-byte packet head - and not by the block size: at a 1 MiB block a
    /// 10 MiB volume holds NINE slices, not ten, and the mock's tenth slice would put
    /// the file over the size the user typed. Nothing given is <c>-u</c> alone, which
    /// keeps however many volumes the exponential plan would have written and makes
    /// them equal sizes; it does NOT mean one volume, which is what this answered
    /// until 12 September 2026 (20 slices drew 1 volume where the engine writes 5).
    /// </remarks>
    public static int UniformVolumeCount(VolumeSpec volumes, int recoveryBlocks, long blockSize)
    {
        if (volumes.Files is { } files and > 0)
        {
            return Math.Clamp(files, 1, MaxRecoveryFiles);
        }

        if (volumes.BlocksPerFile is { } per and > 0)
        {
            return (int)Math.Clamp(CeilDiv(recoveryBlocks, per), 1, MaxRecoveryFiles);
        }

        if (volumes.FileSize is { } bytes and > 0)
        {
            var perVolume = Math.Max(1, bytes / Math.Max(1, blockSize + SlicePacketOverhead));
            return (int)Math.Clamp(CeilDiv(recoveryBlocks, perVolume), 1, MaxRecoveryFiles);
        }

        return VariableVolumeCount(recoveryBlocks);
    }

    /// <summary>
    /// How many volumes the exponential plan writes for this many slices
    /// (<c>par2gen::variable_volume_count</c>): 1 + 2 + 4 + 8 ... so 20 slices are 5
    /// volumes.
    /// </summary>
    public static int VariableVolumeCount(int recoveryBlocks)
    {
        var (left, size, n) = (recoveryBlocks, 1, 0);
        while (left > 0)
        {
            left -= Math.Min(size, left);
            n++;
            size = size > int.MaxValue / 2 ? int.MaxValue : size * 2;
        }

        return n;
    }

    /// <summary>
    /// The largest number of slices one volume may carry under the pow2_limit scheme
    /// (<c>parfast::create::volume_ceiling</c>).
    /// </summary>
    /// <remarks>
    /// BOTH CEILINGS FLOOR-DIVIDE, and both divided the wrong way here until
    /// 12 September 2026. "largest_source" is the largest input file's size in slices
    /// and a volume may not exceed it, so a 20.5-block largest member caps a volume at
    /// TWENTY, not at the 21 a ceiling would give - a ceiling that rounds UP is not a
    /// ceiling. A byte limit divides by the slice's cost on disk (block + 68) for the
    /// same reason <see cref="UniformVolumeCount"/> does, and the engine says which
    /// block count the bytes became rather than leaving the user to infer it.
    /// </remarks>
    private static int Pow2Cap(
        VolumeSpec volumes, long blockSize, IReadOnlyList<PlannedSource> sources,
        List<string>? warnings)
    {
        switch (volumes.Limit)
        {
            case string s when s == "largest_source":
            {
                var largest = sources.Count == 0 ? 0 : sources.Max(x => x.Size);
                return (int)Math.Max(1, largest / Math.Max(1, blockSize));
            }

            case VolumeLimit { Blocks: { } blocks } when blocks > 0:
                return blocks;

            case VolumeLimit { Size: { } bytes } when bytes > 0:
            {
                var cap = (int)Math.Max(1, bytes / Math.Max(1, blockSize + SlicePacketOverhead));
                warnings?.Add($"A ceiling of {bytes:N0} bytes per volume is {cap:N0} recovery block(s) at "
                              + "this block size. Each volume also carries a copy of the set's critical "
                              + "packets, so a file is a little larger than that.");
                return cap;
            }

            default:
                return int.MaxValue;
        }
    }

    /// <summary>
    /// The names of a whole set's volumes, in file order
    /// (<c>parfast::create::final_volume_names</c>).
    /// </summary>
    /// <remarks>
    /// THE TWO FIELDS HAVE DIFFERENT WIDTHS, AND NEITHER IS FLOORED AT THREE. This
    /// class padded both to <c>max(3, digits(first + recovery))</c> until
    /// 12 September 2026, which is a third spelling: not the engine's fixed
    /// <c>vol000+01</c> and not par2cmdline's measured widths either. Measured against
    /// the engine over thirteen slices from zero, the names are
    /// <c>vol00+1 vol01+2 vol03+4 vol07+6</c> - and this drew <c>vol000+001</c> and
    /// friends for the same set. It matters because the next tool along finds a set's
    /// volumes by that pattern, and because the pane is telling a poster what will be
    /// on their disk.
    /// <list type="bullet">
    /// <item>the FIRST field is as wide as <c>first_block + recovery</c>, the exponent
    /// one past the last one written - NOT as wide as the largest index that actually
    /// appears, which is why thirteen slices go two wide with a largest index of 7;</item>
    /// <item>the SECOND field is as wide as the largest COUNT that appears, which for
    /// those same thirteen is one digit;</item>
    /// <item>under <c>--std-naming</c> both fields are exponents, so both take the
    /// FIRST field's width: <c>vol00-00 vol01-02 vol03-06 vol07-12</c>.</item>
    /// </list>
    /// </remarks>
    public static List<string> VolumeNames(
        string stem, IReadOnlyList<int> layout, int firstBlock, int recovery, bool stdNaming)
    {
        var firstWidth = Digits(firstBlock + recovery);
        var countWidth = layout.Count == 0 ? 1 : layout.Max(Digits);
        var names = new List<string>(layout.Count);
        var first = firstBlock;
        foreach (var blocks in layout)
        {
            names.Add(VolumeName(stem, first, blocks, stdNaming, firstWidth, countWidth));
            first += blocks;
        }

        return names;
    }

    /// <summary>
    /// One volume's name at the widths <see cref="VolumeNames"/> measured for the set.
    /// The default dialect is <c>name.vol00+10.par2</c> (first exponent plus count);
    /// <c>--std-naming</c> is the spec's own <c>name.vol00-09.par2</c> (first to last).
    /// </summary>
    public static string VolumeName(
        string stem, int firstBlock, int blocks, bool stdNaming, int firstWidth, int countWidth)
    {
        var first = firstBlock.ToString(CultureInfo.InvariantCulture).PadLeft(firstWidth, '0');
        var second = stdNaming
            ? (firstBlock + Math.Max(0, blocks - 1)).ToString(CultureInfo.InvariantCulture)
                .PadLeft(firstWidth, '0')
            : blocks.ToString(CultureInfo.InvariantCulture).PadLeft(countWidth, '0');
        var join = stdNaming ? '-' : '+';
        return $"{stem}.vol{first}{join}{second}.par2";
    }

    /// <summary>Decimal width of a non-negative number, floored at one digit.</summary>
    private static int Digits(int n) =>
        Math.Max(0, n).ToString(CultureInfo.InvariantCulture).Length;

    /// <summary>
    /// The equivalent command line, for the Copy command button of sections
    /// 5.2 and 5.3. Paths carrying a space are quoted; nothing else is
    /// escaped, because a line that needs shell escaping is a line somebody
    /// should read before running.
    /// </summary>
    /// <remarks>
    /// Measured switch for switch against <c>planner::command_args</c> on
    /// 12 September 2026, because a line that would not build the set the pane drew is
    /// worse than no button. Four arms were wrong:
    /// <list type="bullet">
    /// <item>the "none" scheme carried NO switch, so the line wrote the exponential
    /// default - a pane showing one volume pasting a line that writes 1+2+4+8+...
    /// It is <c>-n1</c>.</item>
    /// <item>all three pow2_limit ceilings pasted <c>-l</c>, which means "no volume
    /// larger than the largest source file" and nothing else. A block or byte ceiling
    /// is <c>--volume-blocks=N</c>, parfast's own long option, and the engine resolves
    /// the byte spelling into a block count before spelling it.</item>
    /// <item>a recovery SIZE pasted a floor-divided <c>-c</c>. The engine spells it
    /// <c>-r</c> with a k/m/g unit when one divides the byte count exactly, and an
    /// exact <c>-c</c> otherwise.</item>
    /// <item><c>--std-naming</c> was not on the line at all, so a set asked for the
    /// spec's own volume naming pasted a line that writes par2cmdline's.</item>
    /// </list>
    /// <c>-u</c> rides alone only when the uniform scheme names no count - with a count
    /// the engine spells <c>-n</c> and nothing else - and <c>-R</c> is never on the line:
    /// the engine expands a directory source itself and names the MEMBERS, which is
    /// what this does too, out of the planned sources it was handed.
    /// </remarks>
    public static string CommandLine(
        CreateSpec spec, IReadOnlyList<PlannedSource> sources, long blockSize,
        int recoveryBlocks, int volumeCount)
    {
        var sb = new StringBuilder("parfast c");

        if (spec.Block.Size is { } askedSize)
        {
            // THE SIZE THAT WAS ASKED FOR, not the one the rules resolved. The CLI applies
            // the multiple-of-four rounding and the slice-ceiling raise itself, so a line
            // carrying the RESOLVED size is a line that only reproduces the set by
            // accident - and where the raise bound, it would paste a different grid back.
            // Found by the real-engine parity test: the engine spells `-s4096` for a set
            // it resolved to a 32,768 byte block.
            sb.Append(" -s").Append(askedSize.ToString(CultureInfo.InvariantCulture));
        }
        else if (spec.Block.Count is { } count)
        {
            sb.Append(" -b").Append(count.ToString(CultureInfo.InvariantCulture));
        }

        if (spec.Recovery.Count is { } rc)
        {
            sb.Append(" -c").Append(rc.ToString(CultureInfo.InvariantCulture));
        }
        else if (spec.Recovery.Percent is { } pct)
        {
            sb.Append(" -r").Append(Trim(Math.Round(pct, MidpointRounding.AwayFromZero)));
        }
        else if (spec.Recovery.Size is { } bytes)
        {
            // `-r<c><n>` is a SCALED integer - k, m or g - and nothing else, so a byte
            // target no unit divides has no `-r` spelling. It has an exact `-c` one,
            // because that is what the size resolves to anyway.
            var scaled = Scaled(bytes);
            sb.Append(scaled is null
                ? " -c" + recoveryBlocks.ToString(CultureInfo.InvariantCulture)
                : " -r" + scaled);
        }

        switch (spec.Volumes.Scheme)
        {
            case VolumeScheme.None:
                sb.Append(" -n1");
                break;
            case VolumeScheme.Uniform when volumeCount > 0 && NamesAUniformCount(spec.Volumes):
                sb.Append(" -n").Append(volumeCount.ToString(CultureInfo.InvariantCulture));
                break;
            case VolumeScheme.Uniform:
                sb.Append(" -u");
                break;
            case VolumeScheme.Pow2Limit:
                switch (spec.Volumes.Limit)
                {
                    case VolumeLimit { Blocks: { } blocks } when blocks > 0:
                        sb.Append(" --volume-blocks=")
                          .Append(blocks.ToString(CultureInfo.InvariantCulture));
                        break;
                    case VolumeLimit { Size: { } bytes } when bytes > 0:
                        sb.Append(" --volume-blocks=").Append(
                            Math.Max(1, bytes / Math.Max(1, blockSize + SlicePacketOverhead))
                                .ToString(CultureInfo.InvariantCulture));
                        break;
                    default:
                        sb.Append(" -l");
                        break;
                }

                break;
        }

        if (spec.StdNaming)
        {
            sb.Append(" --std-naming");
        }

        if (spec.FirstRecoveryBlock > 0)
        {
            sb.Append(" -f").Append(spec.FirstRecoveryBlock.ToString(CultureInfo.InvariantCulture));
        }

        if (spec.PathMode == PathMode.Relative && !string.IsNullOrEmpty(spec.BasePath))
        {
            sb.Append(" -B").Append(Quote(spec.BasePath));
        }

        if (spec.Perf?.Threads is { } threads)
        {
            sb.Append(" -t").Append(threads.ToString(CultureInfo.InvariantCulture));
        }

        if (spec.Perf?.MemoryMb is { } mb)
        {
            sb.Append(" -m").Append(mb.ToString(CultureInfo.InvariantCulture));
        }

        if (!string.IsNullOrEmpty(spec.Comment))
        {
            sb.Append(" --comment=").Append(Quote(spec.Comment));
        }

        sb.Append(' ').Append(Quote(spec.Output));
        foreach (var source in sources)
        {
            sb.Append(' ').Append(Quote(source.Path));
        }

        return sb.ToString();
    }

    /// <summary>Whether the uniform scheme names a volume count, rather than meaning bare <c>-u</c>.</summary>
    private static bool NamesAUniformCount(VolumeSpec volumes) =>
        volumes.Files is > 0 || volumes.BlocksPerFile is > 0 || volumes.FileSize is > 0;

    /// <summary>
    /// <c>-r</c>'s scaled spelling for a byte count, largest unit first, or null for a
    /// count no unit divides exactly (<c>planner::scaled</c>).
    /// </summary>
    private static string? Scaled(long bytes)
    {
        foreach (var (letter, unit) in new[] { ('g', 1L << 30), ('m', 1L << 20), ('k', 1L << 10) })
        {
            if (bytes >= unit && bytes % unit == 0)
            {
                return letter + (bytes / unit).ToString(CultureInfo.InvariantCulture);
            }
        }

        return null;
    }

    /// <summary>The verify or repair command line, for the same button on section 5.2.</summary>
    public static string CommandLine(string par2, VerifyOptions options, bool repair, bool purge)
    {
        var sb = new StringBuilder(repair ? "parfast r" : "parfast v");
        if (repair && purge)
        {
            sb.Append(" -p");
        }

        if (options.RenameOnly)
        {
            sb.Append(" -O");
        }

        if (options.DataSkipping)
        {
            sb.Append(" -N");
            if (options.SkipLeaway != 64)
            {
                sb.Append(" -S").Append(options.SkipLeaway.ToString(CultureInfo.InvariantCulture));
            }
        }

        if (options.Threads is { } threads)
        {
            sb.Append(" -t").Append(threads.ToString(CultureInfo.InvariantCulture));
        }

        sb.Append(' ').Append(Quote(par2));
        return sb.ToString();
    }

    private static string Trim(double value) =>
        value == Math.Floor(value)
            ? ((long)value).ToString(CultureInfo.InvariantCulture)
            : value.ToString("0.##", CultureInfo.InvariantCulture);

    private static string Quote(string path) =>
        path.Contains(' ', StringComparison.Ordinal) ? $"\"{path}\"" : path;

    public static string StemOf(string output)
    {
        var name = PathUtil.FileName(output);
        return name.EndsWith(".par2", StringComparison.OrdinalIgnoreCase)
            ? name[..^5]
            : name;
    }

    private static double Efficiency(int blocks, long blockSize, long fileSize) =>
        fileSize == 0 ? 0 : (double)(blocks * blockSize) / fileSize * 100.0;

    /// <summary>
    /// The index file: the whole critical block, and no recovery data.
    /// </summary>
    /// <remarks>
    /// <c>nzbkit::par2gen::critical_packets</c> is what this models - a main packet
    /// naming every file, then per member a description packet and an input file slice
    /// checksum packet (sixteen bytes of MD5 plus four of CRC32 per block), then the
    /// creator packet. Measured against the engine over two 5,000-byte members at a
    /// 4,096 block: 692 bytes, of which this answers 700. The eight bytes are
    /// <see cref="CreatorPacketBytes"/>, whose body is the engine's own version string -
    /// a mock cannot know it, and it is the only part of the set's bytes this does not
    /// derive.
    /// </remarks>
    private static long IndexSize(IReadOnlyList<PlannedSource> sources, long blockSize) =>
        CriticalBlockBytes(sources, blockSize);

    /// <summary>
    /// One recovery volume's size on disk
    /// (<c>nzbkit::par2gen::plan_files_with_comment</c>).
    /// </summary>
    /// <remarks>
    /// THE CRITICAL BLOCK IS REPEATED, LOGARITHMICALLY, and this class carried exactly
    /// one copy of it until 12 September 2026 - and that copy left out the per-block
    /// slice checksums, which on a large set are most of the block. The engine
    /// interleaves <c>copies</c> whole copies of everything but the creator packet,
    /// where <c>copies</c> is the BIT LENGTH of the volume's slice count: one slice gets
    /// one copy, sixteen get five. So a volume is logarithmically more redundant and not
    /// proportionally so. Measured against the engine over one 100 MiB member at a 1 MiB
    /// block, sixteen slices in the volume: 16,789,904 bytes, which is
    /// 16 x (68 + 1,048,576) + 5 x 2,304 + 80 exactly.
    /// </remarks>
    private static long VolumeSize(IReadOnlyList<PlannedSource> sources, long blockSize, int blocks)
    {
        var creator = CreatorPacketBytes;
        var cycle = CriticalBlockBytes(sources, blockSize) - creator;
        var copies = 0;
        for (var n = blocks; n > 0; n >>= 1)
        {
            copies++;
        }

        return (blocks * (blockSize + SlicePacketOverhead)) + (copies * cycle) + creator;
    }

    /// <summary>
    /// The whole critical block: every packet the index carries, which is also what a
    /// volume repeats.
    /// </summary>
    private static long CriticalBlockBytes(IReadOnlyList<PlannedSource> sources, long blockSize)
    {
        const int header = 64;
        var main = header + 12 + (16L * sources.Count);
        var perMember = sources.Sum(s =>
            (long)header + 56 + RoundUpTo(Encoding.UTF8.GetByteCount(PathUtil.FileName(s.Path)), 4)
            + header + 16 + (20 * CeilDiv(s.Size, blockSize)));
        return main + perMember + CreatorPacketBytes;
    }

    /// <summary>
    /// The creator packet: a 64-byte header and the engine's own version string, padded
    /// to a multiple of four.
    /// </summary>
    /// <remarks>
    /// The string is <c>"nzbfast " + CARGO_PKG_VERSION</c>, so its padded length is 16
    /// bytes for every version from 1.5.0 (13 characters) up to a sixteen-character one -
    /// which is every version this project can plausibly reach. It was 24 here until
    /// 12 September 2026, which is why the mock over-reported the index by eight bytes
    /// and every volume by eight more. Named rather than folded into a sum because it is
    /// the ONE quantity in the set's byte count a mock reads off the engine rather than
    /// deriving, and a reader should be able to find it when a version string grows.
    /// </remarks>
    private const long CreatorPacketBytes = 64 + 16;

    public static long CeilDiv(long a, long b) => b <= 0 ? 0 : (a + b - 1) / b;

    private static long RoundUpTo(long value, long multiple) =>
        multiple <= 0 ? value : (value + multiple - 1) / multiple * multiple;
}

/// <summary>A source file as the planner sees it: a path and a size.</summary>
public sealed record PlannedSource(string Path, long Size, DateTimeOffset Modified = default);
