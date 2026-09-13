namespace Parfast.ViewModels;

/// <summary>
/// The last couple of minutes of a job's read rate, so the progress sheet can
/// answer "is it going fast" and "is it slowing down" instead of only "how fast
/// is it right now".
/// </summary>
/// <remarks>
/// <see cref="Parfast.Core.Contracts.JobSnapshot.RateBytesPerS"/> arrives on every
/// snapshot and the sheet used to print it and throw the previous value away. This
/// is the ring buffer that keeps them, and it is the only new DATA in the whole
/// charts change - the other two charts draw numbers that were already on the
/// wire.
/// <para>
/// THE X AXIS IS THE ENGINE'S OWN CLOCK, ONE SLOT PER ELAPSED SECOND, and that is
/// the decision worth reading. Snapshots do not arrive on a clock: the core
/// promises at most about twenty wakes a second, JobMonitor coalesces a burst of
/// them into one poll, and a busy UI thread can miss several in a row. A chart fed
/// one sample per snapshot therefore has an x axis of "polls", which stretches
/// and compresses time silently - a quiet second and a busy one occupy the same
/// width, so a real slowdown and a poll gap draw identically. Bucketing by
/// <c>elapsed_ms</c> costs nothing, needs no timer of its own, uses a clock the
/// engine already guarantees is monotone, and makes the series deterministic
/// under test.
/// </para>
/// <para>
/// A SECOND WITH NO SNAPSHOT IS CARRIED FORWARD, up to <see cref="MaxCarry"/>
/// seconds, and past that the history is CLEARED rather than bridged. Carrying one
/// or two seconds keeps the axis a real time axis and says only "as far as the UI
/// could see, the rate did not change", which is the truth about a step-sampled
/// series. Bridging a ten second stall would instead manufacture a long flat run
/// that looks like a plateau in the work, which is a claim about time nobody
/// observed. Clearing is honest and visibly different: the chart starts again.
/// </para>
/// </remarks>
public sealed class RateHistory
{
    /// <summary>
    /// How many one-second slots are kept: two minutes of history.
    /// </summary>
    /// <remarks>
    /// A sparkline is a shape rather than a measurement, and two minutes is the
    /// window over which "it was faster a moment ago" is a useful thing to see. A
    /// longer window on a 170 pixel strip would put several seconds in a pixel and
    /// flatten exactly the dip it is there to show.
    /// </remarks>
    public const int Capacity = 120;

    /// <summary>
    /// The longest run of unobserved seconds this will fill in before giving up and
    /// clearing. See the class remarks.
    /// </summary>
    public const int MaxCarry = 4;

    /// <summary>
    /// How much of the way the drawn y scale moves toward a new window maximum per
    /// second.
    /// </summary>
    /// <remarks>
    /// The VU-meter rule the nzbfast dashboard's own throughput chart uses: scale UP
    /// instantly so an incoming spike is never clipped, and decay DOWN gently so the
    /// whole chart does not re-scale under a spiky series - which reads as judder
    /// rather than as information. That chart decays per animation frame; this one
    /// advances once per sample, which is once per second, so the fraction is much
    /// larger for the same settling time: at 0.35 a scale that has to fall settles
    /// most of the way in about three seconds.
    /// </remarks>
    public const double ScaleDecayPerSecond = 0.35;

    private readonly long[] _slots = new long[Capacity];
    private int _count;
    private int _start;
    private long _lastSecond = -1;
    private double _displayMax;

    /// <summary>
    /// Whether the y scale eases toward a falling window maximum, or snaps to it.
    /// </summary>
    /// <remarks>
    /// The view sets this from the system's animation setting - Windows' equivalent
    /// of <c>prefers-reduced-motion</c> - and the easing is the only motion either
    /// of these charts has, so turning it off leaves a chart that is still entirely
    /// correct and merely steps rather than glides. Read here rather than in the
    /// control so the behaviour is testable without a window.
    /// </remarks>
    public bool SmoothScale { get; set; } = true;

    /// <summary>How many seconds of history are held.</summary>
    public int Count => _count;

    /// <summary>True once there is a shape to draw at all.</summary>
    public bool HasShape => _count >= 2 && Peak > 0;

    /// <summary>The newest sample, in bytes per second.</summary>
    public long Current => _count == 0 ? 0 : this[_count - 1];

    /// <summary>The largest sample held.</summary>
    public long Peak
    {
        get
        {
            var peak = 0L;
            for (var i = 0; i < _count; i++)
            {
                peak = Math.Max(peak, this[i]);
            }

            return peak;
        }
    }

    /// <summary>Sample <paramref name="index"/>, oldest first.</summary>
    public long this[int index] => _slots[(_start + index) % Capacity];

    /// <summary>
    /// The y scale the chart should draw against right now: at least the visible
    /// peak, eased downward when it falls.
    /// </summary>
    /// <remarks>
    /// Never zero, so a series of zeroes draws a flat line along the bottom rather
    /// than dividing by nothing. A job whose engine reports no rate at all is
    /// answered by <see cref="HasShape"/> instead - the chart is not shown, because
    /// there is nothing to show and a flat line at the floor would read as a stall.
    /// </remarks>
    public double DisplayMax => Math.Max(_displayMax, 1);

    /// <summary>
    /// Takes a snapshot's rate, bucketed into the elapsed second it belongs to.
    /// </summary>
    /// <param name="elapsedMs">The job's own elapsed clock.</param>
    /// <param name="rateBytesPerS">Its instantaneous rate.</param>
    public void Push(long elapsedMs, long rateBytesPerS)
    {
        var second = Math.Max(0, elapsedMs) / 1000;
        var rate = Math.Max(0, rateBytesPerS);

        if (_count == 0)
        {
            Append(rate);
            _lastSecond = second;
            Rescale();
            return;
        }

        if (second == _lastSecond)
        {
            // Several snapshots inside one second: the LATEST reading wins rather
            // than an average of them. The slot means "the rate as of this second",
            // and averaging would quietly smooth the series before the chart's own
            // smoothing got to it.
            _slots[(_start + _count - 1) % Capacity] = rate;
            Rescale();
            return;
        }

        if (second < _lastSecond)
        {
            // The clock went backwards, which means this is a different run of the
            // job than the samples already held. Drawing across that would join two
            // unrelated series into one line.
            Reset();
            Append(rate);
            _lastSecond = second;
            Rescale();
            return;
        }

        var missing = second - _lastSecond - 1;
        if (missing > MaxCarry)
        {
            Reset();
            Append(rate);
            _lastSecond = second;
            Rescale();
            return;
        }

        var carry = _count == 0 ? 0 : this[_count - 1];
        for (var i = 0; i < missing; i++)
        {
            Append(carry);
        }

        Append(rate);
        _lastSecond = second;
        Rescale();
    }

    /// <summary>Throws the history away, for a new job in the same sheet.</summary>
    public void Reset()
    {
        _count = 0;
        _start = 0;
        _lastSecond = -1;
        _displayMax = 0;
    }

    /// <summary>
    /// The most recent <paramref name="maxSamples"/> samples, oldest first.
    /// </summary>
    /// <remarks>
    /// The control asks for as many as it has pixels to give them, at two pixels a
    /// sample, so a narrow strip draws a shorter window rather than several seconds
    /// per pixel. This is the same thing the dashboard's <c>visN</c> does for the
    /// same reason.
    /// </remarks>
    public IReadOnlyList<long> Visible(int maxSamples)
    {
        var take = Math.Clamp(maxSamples, 0, _count);
        var window = new long[take];
        for (var i = 0; i < take; i++)
        {
            window[i] = this[_count - take + i];
        }

        return window;
    }

    /// <summary>
    /// How the current rate compares with the median of the history, as a signed
    /// fraction, or null while there is too little history to say.
    /// </summary>
    /// <remarks>
    /// THE MEDIAN AND NOT THE MEAN, because the series this runs over is spiky by
    /// nature: one stalled second at zero drags a mean of twenty samples down by
    /// five per cent and would report a slowdown that did not happen. The median is
    /// unmoved by it.
    /// <para>
    /// It answers the second half of the question the chart is here for. A shape
    /// says "slowing down" to somebody looking at it; this says the same thing in a
    /// sentence, which is what the screen reader gets and what the figure beside the
    /// chart prints.
    /// </para>
    /// </remarks>
    public double? Trend
    {
        get
        {
            // Fifteen seconds before it says anything. A comparison over the first
            // three samples of a job flaps between large positive and large negative
            // numbers while the engine's own rate estimate is settling, and a figure
            // that flickers is read as the app being confused rather than the job
            // being uneven.
            if (_count < 15)
            {
                return null;
            }

            var sorted = new long[_count];
            for (var i = 0; i < _count; i++)
            {
                sorted[i] = this[i];
            }

            Array.Sort(sorted);
            var median = sorted.Length % 2 == 1
                ? sorted[sorted.Length / 2]
                : (sorted[(sorted.Length / 2) - 1] + sorted[sorted.Length / 2]) / 2.0;

            return median <= 0 ? null : (Current - median) / median;
        }
    }

    /// <summary>
    /// The trend in words, or an empty string when there is not enough history.
    /// </summary>
    /// <remarks>
    /// A band around zero reads as steady rather than as a tiny change in a
    /// direction: the rate wobbles by a few per cent under normal disk behaviour and
    /// labelling that "3% slower" invites a reader to chase noise.
    /// </remarks>
    public string TrendText
    {
        get
        {
            if (Trend is not { } trend)
            {
                return string.Empty;
            }

            if (Math.Abs(trend) < 0.08)
            {
                return Strings.ProgressRateSteady;
            }

            // Fmt.Pct and NOT Fmt.Percent: Percent CLAMPS its argument to 0..1, so a
            // job running at five times the median would print "100% faster" and
            // understate itself by a factor of four. Pct takes a figure already
            // expressed out of a hundred and does not clamp.
            var pct = Fmt.Pct(Math.Abs(trend) * 100, 0);
            return Strings.Fill(
                trend > 0 ? Strings.ProgressRateFaster : Strings.ProgressRateSlower, "percent", pct);
        }
    }

    private void Append(long value)
    {
        if (_count < Capacity)
        {
            _slots[(_start + _count) % Capacity] = value;
            _count++;
            return;
        }

        _slots[_start] = value;
        _start = (_start + 1) % Capacity;
    }

    private void Rescale()
    {
        var target = (double)Peak;
        if (!SmoothScale || _displayMax <= 0 || target >= _displayMax)
        {
            _displayMax = target;
            return;
        }

        var eased = _displayMax + ((target - _displayMax) * ScaleDecayPerSecond);

        // Snap when it is within a fraction of a per cent, or the scale creeps
        // downward for ever and the chart never settles.
        _displayMax = target > 0 && (eased - target) / target < 0.002 ? target : eased;
    }
}
