#!/usr/bin/env python3
"""Three-window shape reduction for the nibble class at 1 MiB
(lane parfast-nibble-third-window-shape-18sep).

waskred.py reduces THREE ladders positionally (resident, -m2048, -m1024) and
answers "what is each crossover, and what is each excess". This answers the
next question, which that one cannot: ACROSS N WINDOW SIZES, does the k that
`ntt_window_row_gate` would need move SYSTEMATICALLY with the window, or are
the cells scattered by about as much as they differ?

    w3winred.py [--threads N] [--metric wall|cpu] [--gate G] [--boot N] \
        <resident.log> <S>=<win.log> [<S>=<win.log> ...]
    w3winred.py --grade [--metric wall|cpu] [--boot N] [--rungs a,b,c] \
        <label>[@threads]=<log> [<label>[@threads]=<log> ...]

IT IMPORTS waskred RATHER THAN REIMPLEMENTING IT. `legs`, `cell`, `shape`,
`crossover` and `crossing_state` all come from
rounds/wask-nibble-2026-09-16/waskred.py, which is importable since
2e98f4e63 and whose own --selftest pins it to the 16 Sep published table. Two
rounds that reduce differently stop being comparable, and this campaign has
paid for that more than once - so the only arithmetic added here is the part
waskred has no opinion about: the inversion for k, and the error on it.

WHY AN ERROR BAR IS THE POINT OF THIS SCRIPT. Two rounds have now reported
that no single k reproduces two window sizes, quoting cells "11% apart" and
"42% apart". Those spreads were never compared against anything. The inversion

    k = E * S / (gate + E)

is steep in E at wide windows and shallow at narrow ones - dk/dE = S*gate /
(gate + E)^2 - so the SAME error in rows becomes a very different error in k
depending on which window it was measured at, and a table of bare k values
invites a reader to compare numbers whose precisions differ several-fold. At
gate = 256 and a crossover error of ten rows, the S = 2,064 cell's k carries
about +-75 and the S = 1,040 cell's about +-20. An 11% gap between those two is
not evidence of anything; the same script has to be able to say so.

THE ERROR COMES FROM THE ROUND'S OWN LEGS, BY BOOTSTRAP, not from a constant.
Every cell is a median over its legs (the A/A arm pair across the reps), so the
legs ARE the sample. Resampling them with replacement and recomputing the whole
reduction gives the crossover's sampling distribution with no assumption about
how noisy a leg is - and, critically, it gets the CORRELATION right: every
excess in a round is measured from the SAME resident anchor, so a resample that
moves the anchor moves all the excesses together, exactly as a real anchor
error would. A per-cell error bar computed independently would understate the
excesses' agreement and overstate their spread.

    IT IS A BOOTSTRAP OVER FOUR LEGS PER CELL and it should be read as an order
    of magnitude, not a confidence interval. Four samples cannot resolve a tail.
    It is reported beside the campaign's own cross-sitting replicate evidence
    (the -t12 CPU arm read 252 against 255 and 400 against 387 on two nights),
    which is an EXTERNAL check on the same quantity and is the number to believe
    where the two disagree.

THE SHAPE TEST IS A LINE, AND THAT IS WHY IT IS WORTH RUNNING. The ask
`gate + gate*k/(S - k)` says the excess obeys E = gate*k/(S - k), so

    y = gate / E = S/k - 1

is LINEAR IN S with slope 1/k and intercept exactly -1. The form is therefore
testable without fitting anything to it: fit a line through the (S, y) points
and ask whether its intercept is -1. An intercept below -1 means the required k
grows as the window narrows, which is the shape failure; an intercept at -1
means one k fits every window and the scatter between cells is measurement.
With two points the line is exact and the intercept has no residual to test
against, which is precisely why a third window was needed and why this script
refuses to print a shape verdict from two.
"""
import math, os, random, statistics as st, sys

# NO BYTECODE, and here it is the difference between wiring this selftest
# and reddening main with it. `waskred` lives INSIDE the published tree,
# so importing it writes `wask-nibble-2026-09-16/__pycache__/waskred.cpython-NNN.pyc`
# beside it, and tools/site-leak-scan.py REFUSES a .pyc it cannot take
# apart - correctly, since a gate that cannot look inside must not report
# clean. kneeratio.py hit exactly that and reddened `tool-selftests` on
# main (claim red-tool-selftests-d5da7c6b, landed 1f8aefefa).
#
# Which makes this file the case where two gates pull against each other:
# selftest-roster REFUSES it as unwired, and the wiring it demands is what
# arms the leak scan. Both halves land together or neither does.
# Set BEFORE the import; Python consults it at import time.
# an internal note carries the class.
sys.dont_write_bytecode = True

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'wask-nibble-2026-09-16'))
import waskred  # noqa: E402  - the shared arithmetic; see the docstring


def read_legs(path, threads=None):
    """waskred.legs for a `.log`, and the SAME leg dicts out of a `.jsonl`.

    THIS IS AN INPUT ADAPTER, NOT A SECOND REDUCTION. It returns exactly the
    dict shape `waskred.legs` returns, so `cell`, `shape`, `crossover` and
    `reduce_once` below are reached unchanged and a figure graded from a jsonl
    is the same quantity, reduced by the same arithmetic, as one graded from a
    log. Nothing here interpolates, medians or compares.

    WHY IT HAD TO EXIST (18 Sep 2026, lane rowgate-ungraded-sections-sweep).
    The 15 Sep EPYC 9354P guest round - the campaign's FIRST class, the round
    the shipped 320 was kept on, and the only AVX-512-guest data in the corpus -
    is banked in the OLD rowgate.py log format, whose LEG line reads

        LEG 64k-ladder-m96-big-fold-t4-r1  ok path=fold wall=   2.07 cpu=  10.50

    Three things in that line defeat `waskred.legs`, which splits on whitespace
    and keeps tokens containing '=': `m` and the thread count live in the leg
    NAME rather than in a field, and `wall=` / `cpu=` are followed by a SPACE,
    so both parse to the empty string. It does not fail - it returns 204 legs
    with `{'wall': '', 'cpu': ''}` and no 'm' key at all, and the first thing to
    touch them raises. So that round read as ungradeable and was nearly reported
    that way. It is not: the same round banks a `.jsonl` beside every log, with
    every field the reduction needs, typed.

    Reading the jsonl rather than teaching the reducer that leg-name grammar is
    deliberate. The grammar is one dead harness's, the jsonl is what every later
    round also writes, and a parser for a format nothing will produce again is a
    second place for the two reductions to drift apart.

    `phase` is filtered to 'ladder'. The same file carries the `k` phase's legs
    (a `forcep` arm at its own rungs), which are not a fold-against-force ladder
    and would median into the force cells of whichever rungs they share.
    """
    if not path.endswith('.jsonl'):
        return waskred.legs(path, threads)
    import json
    out = []
    for lineno, line in enumerate(open(path, errors='replace'), 1):
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        if d.get('phase') != 'ladder' or not d.get('ok'):
            continue
        # THE SAME REFUSAL AS THE LOG SIDE, and it has to be here too: this
        # adapter's whole contract is that it returns the dict shape
        # `waskred.legs` returns, so a jsonl missing one of the reduced fields
        # would hand the reduction exactly the garbage the log-side check
        # exists to refuse - just from the other input. `d['m']` would raise a
        # bare KeyError naming nothing; `waskred.refuse_bad_leg` names the file,
        # the line and the field.
        leg = {'m': d.get('m'), 'arm': d.get('arm'), 'threads': str(d.get('threads')),
               'cpu': d.get('cpu'), 'wall': d.get('wall'),
               # shape() reads these three by .get and compares the tuple
               # across rungs, so they must be spelled as the log spells them -
               # strings - or a jsonl ladder and a log ladder would exclude
               # rungs differently.
               'windows': str(d.get('windows')), 'slabs': str(d.get('slabs')),
               'win_slices': str(d.get('win_slices', ''))}
        waskred.refuse_bad_leg(path, lineno, leg)
        out.append(leg)
    pools = sorted({x['threads'] for x in out})
    if threads is not None:
        out = [x for x in out if x['threads'] == str(threads)]
        if not out:
            sys.exit(f'{path}: no legs at threads={threads} (log has {pools})')
    elif len(pools) > 1:
        # waskred's refusal, word for word in effect: medianing a rung across
        # pools returns a crossover belonging to neither.
        sys.exit(f'{path}: {len(pools)} thread counts in one log ({pools}) - pass '
                 f'<label>@N=<path> to say which pool to read. Medianing a rung '
                 f'across pools returns a crossover belonging to neither.')
    if not out:
        sys.exit(f'{path}: no phase=ladder legs found')
    return out


def ladder(ls, metric):
    """One ladder's rungs, cells and in-shape rung set, waskred's way."""
    rungs = sorted({int(x['m']) for x in ls})
    fold = {m: waskred.cell(ls, m, ('fold', 'fold2'), metric) for m in rungs}
    force = {m: waskred.cell(ls, m, ('force', 'force2'), metric) for m in rungs}
    shapes = {m: waskred.shape(ls, m) for m in rungs}
    keep = [m for m in rungs if shapes[m] == shapes[rungs[0]]]
    return rungs, keep, fold, force, shapes


def rung_noise(ls, keep, fold, force, metric, x=None):
    """The RUNG-NOISE term on one crossover: rows per one per cent of F/T, the
    two bracketing rungs' own A/A floors, and the rows those floors imply.

    ONE COPY, CALLED FROM BOTH. This arithmetic was written inside
    `crossbias.py`'s `arm_sensitivity()` (lane crpin-coarse-vs-fine-bias-18sep,
    18 Sep 2026) and is lifted here so `--grade` and that arm are the same
    quantity, reduced by the same code. A second copy of it is the defect this
    campaign keeps paying for: two rounds that reduce differently stop being
    comparable, and a term quoted against a published crossover has to be the
    term that crossover's own file quotes.

    WHY IT IS WORTH A COLUMN. Every crossover this campaign publishes carries a
    bootstrap bar, and the bar omits the term that dominates it. A crossover is
    a root of log(F/T), so a cell wrong by e per cent moves the root by
    e / (100 * dy/dm) rows - and the ladder's own A/A floor is the campaign's
    measure of e. Measured 18 Sep on the 4 MiB create arms, one per cent of F/T
    is worth 3.9 to 5.3 rows at the coarse crossings against bracketing A/A
    floors of 0.03-1.74%, which prices "one bracketing rung drew badly" at 1.3
    to 3.6 rows: the same size as every coarse-to-fine gap in the corpus,
    present at EVERY rung spacing, and not removable by refining the grid.

    IT IS REPORTED BESIDE THE BOOTSTRAP BAR AND NEVER FOLDED INTO IT. How to
    combine a sampling bar with a systematic is a judgement, the two published
    error-bar files both say at length that a bar on this corpus is an order of
    magnitude rather than a confidence interval, and a single combined number
    would hide which half moved. Quote the two and let the reader do it.

    `term` is `per_pct * (the worst of the four bracketing A/A floors) / 2`.
    The halving is because an A/A floor is the gap between TWO independent
    draws of the same cell, so one draw's own error is about half of it.

    Returns None when there is no located crossover or no usable bracket, and
    `floors[m] = None` for a bracketing rung that carries no A/A pair - a
    ladder with a single fold and force arm has no measure of e at all, and
    saying so is not the same as reporting zero.
    """
    if x is None:
        x = waskred.crossover(keep, fold, force)
    if x is None:
        return None
    r = {m: fold[m] / force[m] for m in keep
         if fold.get(m) and force.get(m) and force[m] > 0}
    below = [m for m in r if m <= x]
    above = [m for m in r if m > x]
    if not below or not above:
        return None
    lo, hi = max(below), min(above)
    if r[lo] <= 0 or r[hi] <= 0:
        return None
    slope = (math.log(r[hi]) - math.log(r[lo])) / (hi - lo)
    if slope == 0:
        return None
    per_pct = 0.01 / slope
    floors = {}
    for m in (lo, hi):
        v = {a: [float(y[metric]) for y in ls
                 if int(y['m']) == m and y['arm'] == a]
             for a in ('fold', 'fold2', 'force', 'force2')}
        if not all(v.values()):
            floors[m] = None
            continue
        a0, b0 = st.median(v['fold']), st.median(v['fold2'])
        c0, d0 = st.median(v['force']), st.median(v['force2'])
        floors[m] = (abs(a0 - b0) / ((a0 + b0) / 2) * 100,
                     abs(c0 - d0) / ((c0 + d0) / 2) * 100)
    term = None
    if floors[lo] is not None and floors[hi] is not None:
        term = per_pct * max(max(floors[lo]), max(floors[hi])) / 2
    return dict(x=x, lo=lo, hi=hi, h=hi - lo, u=(x - lo) / (hi - lo),
                slope=slope, per_pct=per_pct, floors=floors, term=term)


def k_needed(S, E, gate):
    """The k that reproduces an excess of E rows at a window of S sources."""
    return E * S / (gate + E)


def dk_dE(S, E, gate):
    return S * gate / (gate + E) ** 2


def wls_line(xs, ys, ws):
    """Weighted least squares y = a*x + b. Returns (a, b) or None."""
    sw = sum(ws)
    sx = sum(w * x for w, x in zip(ws, xs))
    sy = sum(w * y for w, y in zip(ws, ys))
    sxx = sum(w * x * x for w, x in zip(ws, xs))
    sxy = sum(w * x * y for w, x, y in zip(ws, xs, ys))
    den = sw * sxx - sx * sx
    if abs(den) < 1e-12:
        return None
    a = (sw * sxy - sx * sy) / den
    b = (sy * sxx - sx * sxy) / den
    return a, b


def reduce_once(ladders, metric, resample=False, rng=None):
    """Crossovers for every ladder. `ladders` is [(label, S, legs)], resident first.

    With resample=True each cell's legs are drawn with replacement before the
    median, which is the bootstrap. The resident ladder is resampled in the
    SAME draw as the windowed ones, so the anchor's error stays common to every
    excess - see the docstring.
    """
    out = []
    for label, S, ls in ladders:
        rungs = sorted({int(x['m']) for x in ls})
        shapes = {m: waskred.shape(ls, m) for m in rungs}
        keep = [m for m in rungs if shapes[m] == shapes[rungs[0]]]
        fold, force = {}, {}
        for m in rungs:
            for name, arms in (('fold', ('fold', 'fold2')), ('force', ('force', 'force2'))):
                v = [float(x[metric]) for x in ls if int(x['m']) == m and x['arm'] in arms]
                if not v:
                    (fold if name == 'fold' else force)[m] = None
                    continue
                if resample:
                    v = [v[rng.randrange(len(v))] for _ in v]
                (fold if name == 'fold' else force)[m] = st.median(v)
        x = waskred.crossover(keep, fold, force)
        stt = waskred.crossing_state(keep, fold, force)
        out.append((label, S, keep, fold, force, x, stt))
    return out


def drift(argv):
    """`--drift <first.log> <second.log>` - the anchor's own movement across a sitting.

    Every excess this script prints is (windowed crossover - resident crossover),
    so a resident anchor that moves between the first ladder and the last moves
    all of them TOGETHER and in the same direction - which is exactly the
    signature a shape failure would leave, and nothing in the main reduction can
    tell the two apart. The 17 Sep round bounded ONE lock handover plus fifteen
    minutes at about 2% on two rungs; a five-ladder sitting is six hours and had
    nothing on it at all.

    The second ladder is a SHORT re-run of the resident rungs that bracket every
    resident crossover in the round, so it is compared on its OWN rungs and the
    first ladder is cut down to them. A crossover that the short ladder does not
    bracket is reported as such rather than extrapolated.
    """
    threads, metric = None, 'cpu'
    while len(argv) >= 2 and argv[0] in ('--threads', '--metric'):
        if argv[0] == '--threads':
            threads = int(argv[1])
        else:
            metric = argv[1]
        argv = argv[2:]
    if len(argv) != 2:
        sys.exit('--drift takes exactly two resident logs: the sitting\'s first and last')
    a = waskred.legs(argv[0], threads)
    b = waskred.legs(argv[1], threads)
    brungs = sorted({int(x['m']) for x in b})
    out = []
    for name, ls in (('first', a), ('last', b)):
        rungs = sorted({int(x['m']) for x in ls})
        shapes = {m: waskred.shape(ls, m) for m in rungs}
        keep = [m for m in rungs if shapes[m] == shapes[rungs[0]] and m in brungs]
        fold = {m: waskred.cell(ls, m, ('fold', 'fold2'), metric) for m in keep}
        force = {m: waskred.cell(ls, m, ('force', 'force2'), metric) for m in keep}
        x = waskred.crossover(keep, fold, force)
        stt = waskred.crossing_state(keep, fold, force)
        out.append((name, keep, fold, force, x, stt))
        print(f'   {name:6s} rungs {keep}  crossover '
              + (f'{x:.1f}' if x is not None else f'NOT BRACKETED ({stt})'))
    print('   per-rung cells (the control: a drift shows in the CELLS, not only the crossover)')
    for m in sorted(set(out[0][1]) & set(out[1][1])):
        f0, f1 = out[0][2][m], out[1][2][m]
        t0, t1 = out[0][3][m], out[1][3][m]
        if not all((f0, f1, t0, t1)):
            continue
        print(f'   m={m:5d} fold {f0:8.2f} -> {f1:8.2f} ({(f1-f0)/f0*100:+5.2f}%)'
              f'   force {t0:8.2f} -> {t1:8.2f} ({(t1-t0)/t0*100:+5.2f}%)')
    xa, xb = out[0][4], out[1][4]
    if xa is not None and xb is not None:
        print(f'   ANCHOR MOVED {xb - xa:+.1f} rows ({(xb-xa)/xa*100:+.1f}%) across the sitting'
              f' - every excess in this round carries that as a COMMON shift.')
    else:
        print('   the anchor could not be compared on these rungs; say so rather than'
              ' treating the excesses as drift-free.')
    return 0


def grade(argv):
    """`--grade <label>[@threads]=<log> ...` - an error bar on ANY crossover, and
    on every DIFFERENCE between them.

    WHY THIS ARM EXISTS AND WHY IT IS HERE RATHER THAN IN A NEW SCRIPT.
    The main arm above answers one question - across window sizes, does the
    demanded `k` move systematically - and it can only ask it of a round shaped
    like a windowed ask: one resident anchor, N windowed ladders, one gate. The
    campaign file publishes far more crossovers than that, and essentially all of
    its conclusions are DIFFERENCES of two of them: a pool step, a class step, a
    block-size step, a create-against-repair gap, a crossover moving between
    sittings. Not one of those carried an error bar
    (lane `campaign-crossover-error-bars-18sep`), so no reader could tell a
    finding from a coincidence. This arm grades them with the SAME bootstrap the
    main arm uses, by calling the SAME `reduce_once`, so a figure graded here and
    a figure graded above are the same quantity reduced the same way. A separate
    script would have been a second reduction of one campaign's logs, which is
    the mistake this file's docstring already refuses once.

    THE DIFFERENCES ARE PAIRED, AND THAT IS THE WHOLE POINT. Every ladder named
    on one command line is resampled in the SAME bootstrap draw, exactly as the
    main arm resamples the resident anchor with the windowed ladders. The
    difference is then formed INSIDE the draw, so any error the two crossovers
    share - a box that drifted, a fixture rebuilt between sittings, an anchor
    common to both - cancels in it, and any error they do not share adds. Two
    error bars computed independently and subtracted get this wrong in both
    directions: it overstates the error on two arms that were interleaved in one
    sitting, and understates it on two that were not. WHICH of those a given
    comparison is depends on the logs, not on this script, so the caller must say
    it: ladders that were genuinely interleaved belong on one command line, and
    two sittings that were not should be read against the campaign's
    cross-sitting replicates instead, which are an EXTERNAL check this bootstrap
    cannot substitute for.

    THE SIGN-FLIP FRACTION IS THE NUMBER TO QUOTE. Sigma invites a reader to
    reach for a normal table over four legs, which is not a thing four legs can
    support. "The sign of this gap flips in 38% of resamples" says what the
    reader needs with no distributional claim attached, and it stays honest when
    the bootstrap is skewed - which, at a crossover that is a log-interpolation
    between two rungs, it routinely is.

    `label@threads` reads one pool out of a multi-pool log, which is how the two
    arms of a pool step come from one file. `--rungs` restricts every ladder to a
    common rung set, for the comparisons the file makes "at the rungs they
    share"; without it each ladder keeps its own in-shape set, and a difference
    between two ladders reduced on different rung sets is reported with a warning
    rather than silently.
    """
    metric, nboot, rungs = 'cpu', 2000, None
    while len(argv) >= 2 and argv[0] in ('--metric', '--boot', '--rungs'):
        k, v = argv[0], argv[1]
        if k == '--metric':
            metric = v
            if metric not in ('wall', 'cpu'):
                sys.exit('--metric must be wall or cpu, not %r' % metric)
        elif k == '--boot':
            nboot = int(v)
        else:
            rungs = sorted(int(t) for t in v.split(','))
        argv = argv[2:]
    if len(argv) < 1:
        sys.exit('--grade takes one or more <label>[@threads]=<log> arguments')
    ladders, meta = [], []
    for a in argv:
        if '=' not in a:
            sys.exit('ladders are given as <label>[@threads]=<path>, not %r' % a)
        lbl, path = a.split('=', 1)
        # FAILING TO FIND IS FAILING, and here it is also failing to PARSE: the
        # split is on the FIRST '=', so a label containing one ('S=2064=x.log')
        # silently hands the rest to open() and the traceback names a path
        # nobody typed. Refuse by name instead.
        if not os.path.exists(path):
            sys.exit(f'--grade: {lbl!r} -> {path!r} does not exist. Labels must not '
                     f'contain "=" (the split is on the first one); write '
                     f'w2064@4=<log>, never S=2064@4=<log>.')
        th = None
        if '@' in lbl:
            lbl, t = lbl.rsplit('@', 1)
            th = int(t)
        ls = read_legs(path, th)
        if rungs is not None:
            ls = [x for x in ls if int(x['m']) in rungs]
            if not ls:
                sys.exit(f'{lbl}: no legs at rungs {rungs} in {os.path.basename(path)}')
        # TWO LADDERS UNDER ONE LABEL SILENTLY FUSE, and the output reads like
        # a measurement (18 Sep 2026, lane rowgate-ungraded-sections-sweep).
        # `boots` and every `draw` below are keyed on the LABEL, so a second
        # ladder with the same one overwrites the first in every resample: both
        # rows print the SECOND ladder's error bar, and their difference is the
        # difference of a ladder with ITSELF - `-31.6 rows, sd 0.0, inf sigma,
        # SIGN FLIPS IN 0.0%`, which is the most confident line this arm can
        # print and means nothing at all. It fires on exactly the spelling a
        # pool step invites, `x@4=log x@8=log`, which is the arm's own
        # documented idiom for reading two pools out of one file. Refuse by
        # name rather than de-duplicating silently: which ladder the caller
        # meant to rename is not this script's to guess.
        if any(l == lbl for l, _, _ in ladders):
            sys.exit(f'--grade: two ladders both labelled {lbl!r}. Labels key the '
                     f'bootstrap, so a repeat silently fuses them and prints their '
                     f'difference with itself as 0.0 sd / inf sigma. Name them '
                     f'apart - e.g. {lbl}_t4 and {lbl}_t8.')
        ladders.append((lbl, None, ls))
        meta.append((lbl, th, path))
    # hoisted: a backslash inside an f-string expression is a SyntaxError before 3.12
    rungs_note = rungs if rungs else "each ladder's own in-shape set"
    print(f'== {len(ladders)} ladder(s), metric={metric}, boot={nboot}, '
          f'rungs={rungs_note}')
    for (lbl, th, path), (_, _, ls) in zip(meta, ladders):
        print(f'   {lbl:22s} legs={len(ls):4d}  pool={th if th is not None else "single"}'
              f'  {os.path.basename(path)}')

    base = reduce_once(ladders, metric)
    print()
    print('== crossovers, with the round\'s own error on them')
    located = []
    for lbl, _, keep, fold, force, x, stt in base:
        if x is None:
            print(f'   {lbl:22s} NO CROSSOVER IN SHAPE ({stt}), in-shape rungs {keep}'
                  f' - this is a BOUND, not a point, and is excluded from every'
                  f' difference below.')
            continue
        located.append((lbl, x, tuple(keep)))
    if not located:
        print('   nothing located; no difference can be graded.')
        return 2

    rng = random.Random(20260918)
    boots = {lbl: [] for lbl, _, _ in located}
    paired = []
    for _ in range(nboot):
        b = reduce_once(ladders, metric, resample=True, rng=rng)
        draw = {}
        for lbl, _, keep, fold, force, x, stt in b:
            if x is not None:
                draw[lbl] = x
        for lbl in boots:
            if lbl in draw:
                boots[lbl].append(draw[lbl])
        paired.append(draw)

    def q(v, p):
        v = sorted(v)
        return v[max(0, min(len(v) - 1, int(p * len(v))))]

    for lbl, x, keep in located:
        bs = boots[lbl]
        if len(bs) < nboot * 0.5:
            print(f'   {lbl:22s} {x:7.1f}   BOOTSTRAP DEGENERATE'
                  f' ({len(bs)}/{nboot} resamples located a crossover) - the grid'
                  f' barely brackets this one, so no error bar is printed for it.')
            continue
        print(f'   {lbl:22s} {x:7.1f}   sd {st.pstdev(bs):6.1f}'
              f'   68% [{q(bs,0.16):6.1f}, {q(bs,0.84):6.1f}]   rungs {list(keep)}')

    # THE RUNG-NOISE COLUMN, which the bar above does NOT contain (added
    # 18 Sep 2026, owed by an internal note item 1).
    # The bootstrap resamples the legs at each rung, so it carries the scatter
    # WITHIN a cell; it cannot see a cell that is wrong in both its copies, and
    # the A/A floor is the campaign's own measure of exactly that. The two are
    # printed side by side and are NOT combined - see rung_noise's docstring.
    print()
    print('== the RUNG-NOISE term on each of those, which the bar above does NOT contain')
    print('   A crossover is a root of log(F/T), so a bracketing cell wrong by e%'
          ' of F/T moves it by e/(100 dy/dm) rows.')
    print('   The A/A floors are this round\'s own measure of e. Quote this BESIDE'
          ' the bar, never folded into it.')
    print('   ladder                 bracket        u    1% of F/T   A/A floors'
          ' fold/force (lo | hi)   implied rung-noise')
    legs_by_label = {lbl: ls for lbl, _, ls in ladders}
    for lbl, _, keep, fold, force, x, stt in base:
        if x is None:
            continue
        rn = rung_noise(legs_by_label[lbl], keep, fold, force, metric, x)
        if rn is None:
            print(f'   {lbl:22s} no usable bracket for the rung-noise term'
                  f' - reported as absent rather than as zero.')
            continue

        def _f(m):
            fl = rn['floors'][m]
            return 'no A/A pair' if fl is None else f'{fl[0]:.2f}/{fl[1]:.2f}%'

        term = ('   NOT PRICED (a bracketing rung has no A/A pair)'
                if rn['term'] is None else f'{rn["term"]:8.1f} rows')
        print(f'   {lbl:22s} [{rn["lo"]},{rn["hi"]}] h={rn["h"]:<3d}'
              f' {rn["u"]:5.3f} {rn["per_pct"]:9.1f} rows'
              f'   {_f(rn["lo"])} | {_f(rn["hi"])}'
              f'   {term}')

    if len(located) < 2:
        print()
        print('   one crossover located; no difference to grade.')
        return 0
    print()
    print('== every DIFFERENCE, paired inside the draw (the statistic the file'
          ' draws its conclusions from)')
    for i in range(len(located)):
        for j in range(i + 1, len(located)):
            li, xi, ki = located[i]
            lj, xj, kj = located[j]
            d = [p[lj] - p[li] for p in paired if li in p and lj in p]
            if len(d) < nboot * 0.5:
                print(f'   {li} -> {lj}: only {len(d)}/{nboot} resamples located both;'
                      f' NOT GRADED.')
                continue
            obs = xj - xi
            sd = st.pstdev(d)
            sig = abs(obs) / sd if sd else float('inf')
            flip = sum(1 for v in d if (v > 0) != (obs > 0)) / len(d)
            note = ''
            if ki != kj:
                # A difference between two ladders reduced on DIFFERENT rung sets
                # is not wrong, but it is not the quantity a reader assumes either:
                # the two crossovers were interpolated between different pairs of
                # rungs. Said out loud rather than folded into the number.
                note = f'   [!] rung sets differ: {list(ki)} vs {list(kj)}'
            print(f'   {li} -> {lj}: {obs:+8.1f} rows ({obs/xi*100:+6.1f}%)'
                  f'   sd {sd:6.1f}   {sig:4.1f} sigma'
                  f'   SIGN FLIPS IN {flip*100:5.1f}% of resamples{note}')
    return 0


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == '--selftest':
        return selftest()
    if argv and argv[0] == '--drift':
        return drift(argv[1:])
    if argv and argv[0] == '--grade':
        return grade(argv[1:])
    threads, metric, gate, nboot = None, 'cpu', 256, 2000
    while len(argv) >= 2 and argv[0] in ('--threads', '--metric', '--gate', '--boot'):
        k, v = argv[0], argv[1]
        if k == '--threads':
            threads = int(v)
        elif k == '--metric':
            metric = v
            if metric not in ('wall', 'cpu'):
                sys.exit('--metric must be wall or cpu, not %r' % metric)
        elif k == '--gate':
            gate = int(v)
        else:
            nboot = int(v)
        argv = argv[2:]
    if len(argv) < 3:
        sys.exit(__doc__.split('\n\n')[1].strip())
    spec = [('resident', None, argv[0])]
    for a in argv[1:]:
        if '=' not in a:
            sys.exit('windowed ladders are given as <S>=<path>, not %r' % a)
        s, p = a.split('=', 1)
        spec.append(('S=%s' % s, int(s), p))
    ladders = [(lbl, S, waskred.legs(p, threads)) for lbl, S, p in spec]
    # THE WINDOW SIZE IS READ BACK OFF THE LEGS, not taken on trust from the
    # command line. Every force leg reports `win_slices=`, which IS the window's
    # source count (2064 under -m2048, 1040 under -m1024), so the S this script
    # inverts for k can be CHECKED against the S the binary actually ran - and a
    # third window is exactly the case where a budget could resolve to a window
    # nobody predicted. FAILING TO FIND IS FAILING: a ladder whose legs carry no
    # win_slices at all is refused rather than silently believed.
    for lbl, S, ls in ladders:
        if S is None:
            continue
        in_shape = {int(x['win_slices'].split('/')[0]) for x in ls
                    if x['arm'].startswith('force') and x.get('win_slices')}
        if not in_shape:
            sys.exit(f'{lbl}: no force leg carries win_slices - cannot confirm the window '
                     f'size this ladder ran at, so its k inversion would be unverifiable.')
        if S not in in_shape:
            sys.exit(f'{lbl}: told S={S}, but the legs report win_slices '
                     f'{sorted(in_shape)}. The window the binary ran is not the window '
                     f'this would invert for k. Fix the argument, never this check.')
    print(f'== {len(ladders)} ladders, metric={metric}, gate={gate}, '
          f'threads={threads if threads is not None else "single-pool log"}, boot={nboot}')
    for (lbl, S, ls), (_, _, path) in zip(ladders, spec):
        print(f'   {lbl:10s} legs={len(ls):4d}  {os.path.basename(path)}')

    base = reduce_once(ladders, metric)
    res_x = base[0][5]
    print()
    print('== crossovers and the ask each window demands')
    if res_x is None:
        print('   resident ladder has no located crossover (%s) - no excess can be'
              ' computed and nothing below is printed.' % base[0][6])
        return 2
    print(f'   resident crossover {res_x:.1f}  (in-shape rungs {base[0][2]})')
    rows = []
    for lbl, S, keep, fold, force, x, stt in base[1:]:
        if x is None:
            print(f'   {lbl:10s} NO CROSSOVER IN SHAPE ({stt}), in-shape rungs {keep}'
                  f' - excess is a BOUND, excluded from the fit')
            continue
        E = x - res_x
        if E <= 0:
            # A WINDOW CAN ONLY EVER COST THE TRANSFORM ROWS, NEVER SAVE IT, so a
            # non-positive excess is not a small measurement - it is a statement
            # that this cell did not measure what it claims to. The 16 Sep
            # GFNI-256 round hit exactly this: its 4,112-source ladder read 24
            # rows BELOW its resident anchor while Windows Search walked the
            # fresh fixture, and that physical impossibility - not the noise
            # column - is what told that lane its anchor was contaminated.
            # Refused rather than down-weighted: inverse-variance weighting
            # drives such a point to ~0 weight on its own, which LOOKS like a
            # handled case and quietly leaves the fit running on whichever
            # resamples happened to produce a finite k.
            print(f'   {lbl:10s} crossover {x:6.1f}  excess {E:+7.1f} rows  '
                  f'REFUSED - a window cannot save the transform rows. This cell '
                  f'did not measure a window of {S} sources; excluded from the fit.')
            continue
        k = k_needed(S, E, gate)
        rows.append((S, x, E, k))
        print(f'   {lbl:10s} crossover {x:6.1f}  excess {E:+7.1f} rows  '
              f'k needed {k:6.1f}   dk/dE {dk_dE(S, E, gate):5.2f} k per row')

    # ---- the bootstrap, which is what turns those k values into a comparison
    rng = random.Random(20260918)
    boots = {S: [] for S, _, _, _ in rows}
    # A CELL THE BASE PASS REFUSED STAYS REFUSED IN EVERY RESAMPLE, and until
    # 18 Sep 2026 this loop did not know that: `boots` is keyed on the cells that
    # PASSED, while the loop below appended for any resampled cell with a
    # positive excess, so a round carrying a refused cell died on a bare
    # KeyError as soon as one resample happened to push that cell positive.
    # Found reducing the banked GFNI-256 round-2 logs in WALL, where the
    # 4,112-source cell reads 14.5 rows BELOW its own resident anchor.
    # THE FIX IS TO SKIP IT, NOT TO ADD THE KEY. A refusal here is the script
    # saying "this cell did not measure a window of S sources" - the physical
    # impossibility that told the 16 Sep lane its anchor was contaminated - and
    # a resample that happens to land positive is the same contaminated cell,
    # not evidence recovered. Adding the key would have let a cell the base pass
    # threw out re-enter the k table and the line fit through the back door, on
    # whichever resamples happened to produce a finite k: exactly the
    # "LOOKS like a handled case" failure the refusal above was written to
    # avoid.
    admitted = {S for S, _, _, _ in rows}
    ys = {}
    resamples = []
    binter, bslope = [], []
    for _ in range(nboot):
        b = reduce_once(ladders, metric, resample=True, rng=rng)
        rx = b[0][5]
        if rx is None:
            continue
        pts = []
        for lbl, S, keep, fold, force, x, stt in b[1:]:
            if x is None or S is None or S not in admitted:
                continue
            E = x - rx
            if E <= 0:
                continue
            boots[S].append(k_needed(S, E, gate))
            ys.setdefault(S, []).append(gate / E)
            pts.append((S, gate / E))
        if len(pts) >= 3:
            resamples.append(pts)

    # INVERSE-VARIANCE WEIGHTS, AND THEY ARE FROZEN BEFORE THE FIT IS BOOTSTRAPPED.
    # y = gate/E is far more precisely known at a NARROW window than a wide one -
    # measured on the 17 Sep logs the spread in y runs about 5x between S = 1,040
    # and S = 2,064, because the same error in rows is divided by E^2. An equal-
    # weight line therefore throws away most of the round's information and, worse,
    # lets the least certain point set the intercept. The weights come from a first
    # pass over the resamples and are then held FIXED while the fit is bootstrapped,
    # so the weighting cannot chase the data it is weighting.
    wt = {}
    for S in sorted(ys):
        sd = st.pstdev(ys[S]) if len(ys[S]) > 2 else 0.0
        wt[S] = 1.0 / (sd * sd) if sd > 0 else 1.0
    for pts in resamples:
        fit = wls_line([p[0] for p in pts], [p[1] for p in pts],
                       [wt.get(p[0], 1.0) for p in pts])
        if fit:
            bslope.append(fit[0])
            binter.append(fit[1])

    def q(v, p):
        v = sorted(v)
        return v[max(0, min(len(v) - 1, int(p * len(v))))]

    print()
    print('== the same k values with the round\'s OWN error on them (leg bootstrap,'
          ' anchor shared)')
    for S, x, E, k in rows:
        bs = boots[S]
        if len(bs) < nboot * 0.5:
            print(f'   S={S:5d}  k={k:6.1f}   bootstrap degenerate'
                  f' ({len(bs)}/{nboot} resamples located a crossover)')
            continue
        print(f'   S={S:5d}  k={k:6.1f}   68% [{q(bs,0.16):6.1f}, {q(bs,0.84):6.1f}]'
              f'   sd {st.pstdev(bs):6.1f}')
    if len(rows) >= 2:
        print()
        print('== is the spread between windows bigger than the error on it?')
        for i in range(len(rows)):
            for j in range(i + 1, len(rows)):
                Si, Sj = rows[i][0], rows[j][0]
                bi, bj = boots[Si], boots[Sj]
                n = min(len(bi), len(bj))
                if n < nboot * 0.5:
                    continue
                d = [bj[t] - bi[t] for t in range(n)]
                obs = rows[j][3] - rows[i][3]
                sd = st.pstdev(d)
                sig = abs(obs) / sd if sd else float('inf')
                same = sum(1 for v in d if (v > 0) != (obs > 0)) / n
                print(f'   S={Si} vs S={Sj}: k differs by {obs:+7.1f} '
                      f'({abs(obs)/rows[i][3]*100:4.1f}%), sd of that difference {sd:6.1f}'
                      f'  -> {sig:4.1f} sigma, sign flips in {same*100:4.1f}% of resamples')

    print()
    print('== THE SHAPE TEST: y = gate/E is linear in S with intercept EXACTLY -1')
    if len(rows) < 3:
        print('   REFUSED - %d window size(s) with a located crossover. Two points fit a'
              ' line exactly and leave no residual, so an intercept from them is not a'
              ' test of anything. This is the whole reason a third window was measured.'
              % len(rows))
        return 0
    pts = [(S, gate / E) for S, x, E, k in rows]
    wt = {}
    for S in sorted(ys):
        sd = st.pstdev(ys[S]) if len(ys[S]) > 2 else 0.0
        wt[S] = 1.0 / (sd * sd) if sd > 0 else 1.0
    fit = wls_line([p[0] for p in pts], [p[1] for p in pts],
                   [wt.get(p[0], 1.0) for p in pts])
    for S, y in pts:
        sd = st.pstdev(ys[S]) if S in ys and len(ys[S]) > 2 else float('nan')
        print(f'   S={S:5d}  y=gate/E={y:7.3f}  sd {sd:6.3f}  weight {wt.get(S,1.0):9.2f}')
    if not fit:
        print('   REFUSED - the window sizes are degenerate.')
        return 0
    a, b = fit
    print(f'   fitted line: y = S/{1/a:.1f} - {-b:.3f}     (the form REQUIRES the'
          f' intercept to be -1.000, and gives k = {1/a:.1f})')
    if binter:
        lo, hi = q(binter, 0.16), q(binter, 0.84)
        frac = sum(1 for v in binter if v <= -1.0) / len(binter)
        print(f'   intercept {b:+.3f}, 68% [{lo:+.3f}, {hi:+.3f}] over {len(binter)} resamples')
        print(f'   resamples with intercept at or below -1 (the shape-failure side):'
              f' {frac*100:.1f}%')
        sd = st.pstdev(binter)
        if sd:
            print(f'   deviation from -1: {b + 1:+.3f} = {abs(b + 1)/sd:.1f} sigma')
    return 0


# The 17 Sep round's PUBLISHED figures, pinned so this script cannot drift from
# the table it is read against. Source: the "windowed ask at the FOUR-thread
# pool" section of an internal note.
SELFTEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '..', 'wask-t4-nibble-2026-09-17')
SELFTEST_LOGS = ('i5-nibble-1m-n8192-resident-t4t12.log',
                 'i5-nibble-1m-n8192-windowed-m2048-t4t12.log',
                 'i5-nibble-1m-n8192-windowed-m1024-t4t12.log')


def selftest():
    """Reproduce the 17 Sep table through the SHARED arithmetic, and prove the
    two-point refusal refuses.

    The k column is the point: 376 and 416 at -t4 CPU, 370 and 414 at -t4 wall,
    337 and 478 at -t12 wall. Those are the published inversions, and if this
    script's k_needed ever stops reproducing them the round it reduces stops
    being comparable with the two before it.
    """
    paths = [os.path.join(SELFTEST_DIR, n) for n in SELFTEST_LOGS]
    bad = [p for p in paths if not os.path.exists(p)]
    if bad:
        # FAILING TO FIND IS FAILING.
        sys.exit('w3winred --selftest: banked log(s) missing: ' + ', '.join(bad))
    fails = []
    want = {(4, 'cpu'): (177, 234, 348, 376, 416),
            (4, 'wall'): (185, 240, 353, 370, 414),
            (12, 'wall'): (155, 205, 372, 337, 478)}
    for (th, metric), (wres, w2k, w1k, k2k, k1k) in want.items():
        lads = [('resident', None, waskred.legs(paths[0], th)),
                ('S=2064', 2064, waskred.legs(paths[1], th)),
                ('S=1040', 1040, waskred.legs(paths[2], th))]
        b = reduce_once(lads, metric)
        got = [b[0][5], b[1][5], b[2][5]]
        for name, g, w in zip(('resident', '-m2048', '-m1024'), got, (wres, w2k, w1k)):
            if g is None or round(g) != w:
                fails.append('t%d %s %s crossover %s, want %d' % (th, metric, name, g, w))
        if all(g is not None for g in got):
            for S, g, w in ((2064, got[1], k2k), (1040, got[2], k1k)):
                k = round(k_needed(S, g - got[0], 256))
                if abs(k - w) > 1:
                    fails.append('t%d %s S=%d k %d, want %d' % (th, metric, S, k, w))
    # The -t12 CPU -m1024 cell is a BOUND in the published table, and a bound
    # must not silently become a point.
    lads = [('resident', None, waskred.legs(paths[0], 12)),
            ('S=1040', 1040, waskred.legs(paths[2], 12))]
    b = reduce_once(lads, 'cpu')
    if b[1][5] is not None:
        fails.append('-t12 CPU -m1024 located a crossover; the published table has a bound')
    if b[1][6] != 'above_last':
        fails.append('-t12 CPU -m1024 state %r, want above_last' % b[1][6])
    if 512 in b[1][2]:
        fails.append('-t12 CPU -m1024 kept m=512; its shape changed there')
    # THE DRIFT ARM, against the 17 Sep A/D control's published deltas (-1.76%,
    # -1.77%, -0.80%, -1.40% at -t4 CPU). That control is the only same-box,
    # same-binary, same-fixture measurement of what a lock handover costs, and
    # this round's ladder E is the same instrument over six hours instead of
    # fifteen minutes - so the arm that reads it has to reproduce the one
    # reading that already exists.
    import io, contextlib
    extra = os.path.join(SELFTEST_DIR, 'i5-nibble-1m-n8192-resident-t4-extrareps.log')
    if not os.path.exists(extra):
        fails.append('drift arm: banked extra-reps log missing: %s' % extra)
    else:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            drift(['--threads', '4', '--metric', 'cpu', paths[0], extra])
        out = buf.getvalue()
        for want in ('-1.76%', '-1.77%', '-0.80%', '-1.40%'):
            if want not in out:
                fails.append('drift arm did not reproduce the A/D delta %s' % want)
        if 'ANCHOR MOVED' not in out:
            fails.append('drift arm printed no anchor movement')

    # A REFUSED CELL MUST NOT CRASH THE BOOTSTRAP, AND MUST NOT COME BACK
    # THROUGH IT (added 18 Sep 2026, lane gfni256-four-window-shape-1mib-18sep).
    # `boots` is keyed on the cells the BASE pass admitted; the bootstrap loop
    # used to append for any resampled cell with a positive excess, so the first
    # resample that pushed a refused cell positive died on a bare KeyError. Hit
    # reducing the banked GFNI-256 round-2 logs in WALL, where the 4,112-source
    # cell reads 14.5 rows BELOW its own resident anchor. This arm drives the
    # same shape off the banked NIBBLE logs - no new fixture - by inverting the
    # roles so the "windowed" ladder IS the resident one, which makes its excess
    # exactly zero and refuses it by the same rule.
    # It drives the REAL case rather than a contrived one: the banked GFNI-256
    # round-2 ladders read in WALL, where the 4,112-source cell sits 14.5 rows
    # BELOW its own resident anchor and the 1,552-source one is not bracketed.
    # A fabricated stand-in was tried first and could not reach the bug - the
    # win_slices guard refuses a resident log handed in as a windowed ladder,
    # correctly, which is itself worth knowing.
    g4 = os.path.join(os.path.dirname(SELFTEST_DIR), 'wform-ask-round2-2026-09-16')
    gres = os.path.join(g4, 'coreultra9-gfni256-1m-n8192-resident-ladder.log')
    gw4k = os.path.join(g4, 'coreultra9-gfni256-1m-n8192-windowed-m4096-ladder.log')
    gw15 = os.path.join(g4, 'coreultra9-gfni256-1m-n8192-windowed-m1536-ladder.log')
    if not all(os.path.exists(p) for p in (gres, gw4k, gw15)):
        fails.append('refused-cell arm: banked GFNI-256 round-2 log(s) missing under %s' % g4)
    else:
        saved = sys.argv
        out = ''
        try:
            sys.argv = ['w3winred.py', '--threads', '16', '--metric', 'wall',
                        '--gate', '352', '--boot', '60',
                        gres, '4112=' + gw4k, '1552=' + gw15]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    main()
                except KeyError as e:
                    fails.append('a REFUSED cell crashed the bootstrap with KeyError %s'
                                 ' - the refusal must be carried into the resamples,'
                                 ' never keyed around' % e)
            out = buf.getvalue()
        finally:
            sys.argv = saved
        if 'REFUSED - a window cannot save the transform rows' not in out:
            fails.append('refused-cell arm: the 4,112-source WALL cell was not refused;'
                         ' the arm proves nothing')
        if 'k needed' in out:
            fails.append('refused-cell arm: a k was printed from a round whose only'
                         ' cells are a refusal and a bound')

    # The shape test must REFUSE two points rather than printing an intercept.
    saved = sys.argv
    try:
        sys.argv = ['w3winred.py', '--threads', '4', '--boot', '50',
                    paths[0], '2064=' + paths[1], '1040=' + paths[2]]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main()
        out = buf.getvalue()
    finally:
        sys.argv = saved
    if rc != 0:
        fails.append('a valid two-ladder run returned %r, want 0' % rc)
    if 'REFUSED' not in out or 'Two points fit a line exactly' not in out:
        fails.append('the two-point shape test did not refuse by name')
    # THE --grade ARM, pinned against figures published by OTHER rounds. The
    # arm exists to grade the whole campaign, so pinning it to this round's own
    # logs would prove only that it agrees with itself. These three come from
    # three different sittings, two boxes and two kernel classes.
    #   * the 15 Sep block-size clause table: 1 MiB reads ~408 at -t4 and ~342
    #     at -t16 ("Results, CPU crossover at n = 16,384").
    #   * the 16 Sep create payload round: "+4 and -7 rows on structured text",
    #     which is the null this arm must reproduce WITH ITS SIGNS - the two
    #     pools disagreeing in sign is the whole content of that finding.
    # A REFUSAL is pinned too, for the reason waskred's selftest gives: a
    # refusal that exited 0 would be the same silent-pass shape as the defect.
    rounds = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
    bs = os.path.join(rounds, 'rowgate-2026-09-15',
                      'coreultra9-gfni256-1m-n16384-bs.log')
    if not os.path.exists(bs):
        fails.append('--grade arm: banked log missing: %s' % bs)
    else:
        for th, want in ((4, 410), (16, 343)):
            b = reduce_once([('x', None, waskred.legs(bs, th))], 'cpu')
            got = b[0][5]
            if got is None or abs(got - want) > 1.5:
                fails.append('--grade arm: 15 Sep 1 MiB -t%d CPU crossover %s, want ~%d'
                             % (th, got, want))
        # and the WALL crossover on the same ladder, which no section publishes
        # and which is 147 rows above the CPU one at -t16. Pinned because the
        # error-bar lane's section 2.1 quotes it and a reader will check it.
        b = reduce_once([('x', None, waskred.legs(bs, 16))], 'wall')
        if b[0][5] is None or abs(b[0][5] - 490) > 2:
            fails.append('--grade arm: 15 Sep 1 MiB -t16 WALL crossover %s, want ~490'
                         % b[0][5])
    cr4 = os.path.join(rounds, 'crg4-2026-09-16',
                       'coreultra9-gfni256-create-4m-n4096-t4-t16-ladder.log')
    crt = os.path.join(rounds, 'crgp4-2026-09-16',
                       'coreultra9-gfni256-create-4m-n4096-text-t4-t16-ladder.log')
    if not (os.path.exists(cr4) and os.path.exists(crt)):
        fails.append('--grade arm: banked create log(s) missing')
    else:
        for th, want in ((4, +4), (16, -7)):
            a = reduce_once([('x', None, waskred.legs(cr4, th))], 'cpu')[0][5]
            t = reduce_once([('x', None, waskred.legs(crt, th))], 'cpu')[0][5]
            if a is None or t is None or abs((t - a) - want) > 1.5:
                fails.append('--grade arm: create payload -t%d moves %s rows, want %+d'
                             % (th, None if a is None or t is None else round(t - a, 1), want))
    # THE JSONL ADAPTER, pinned against the 15 Sep EPYC guest round, whose .log
    # `waskred.legs` cannot read at all (see read_legs). Its three published CPU
    # crossovers are 234 / 202 at 64 KiB and 323 at 1 MiB. Pinned because the
    # adapter is the only route to that round's numbers and a silent change in
    # it would be invisible everywhere else.
    ep = os.path.join(rounds, 'rowgate-2026-09-15')
    e64 = os.path.join(ep, 'epyc9354p-avx512-64k.jsonl')
    e1m = os.path.join(ep, 'epyc9354p-avx512-1m.jsonl')
    if not (os.path.exists(e64) and os.path.exists(e1m)):
        fails.append('--grade arm: banked EPYC guest jsonl missing')
    else:
        for path, th, want in ((e64, 4, 234), (e64, 8, 202), (e1m, 8, 323)):
            g = reduce_once([('x', None, read_legs(path, th))], 'cpu')[0][5]
            if g is None or abs(g - want) > 1.5:
                fails.append('--grade arm: EPYC guest %s -t%d CPU crossover %s, want ~%d'
                             % (os.path.basename(path), th, g, want))
        # and the `k` phase must be OUT: its forcep arm shares rungs with the
        # ladder's, so leaving it in moves the force cells.
        if any(x['arm'] == 'forcep' for x in read_legs(e64, 4)):
            fails.append('--grade arm: read_legs let a phase=k leg through')

    saved = sys.argv
    # A REPEATED LABEL must be REFUSED, not fused. This is the exact spelling a
    # pool step invites, and before 18 Sep 2026 it printed `inf sigma`.
    try:
        sys.argv = ['w3winred.py', '--grade', '--boot', '20',
                    'ep@4=' + e64, 'ep@8=' + e64]
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = main()
        except SystemExit as e:
            rc = e.code
    finally:
        sys.argv = saved
    if not (isinstance(rc, str) and 'two ladders both labelled' in rc):
        fails.append('--grade arm: a repeated label was not refused by name (got %r)'
                     % (rc,))

    saved = sys.argv
    try:
        sys.argv = ['w3winred.py', '--grade', '--boot', '20', 'S=2064@4=' + bs]
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = main()
        except SystemExit as e:
            rc = e.code
    finally:
        sys.argv = saved
    if not (isinstance(rc, str) and 'Labels must not contain' in rc):
        fails.append('--grade arm: a label containing "=" was not refused by name (got %r)'
                     % (rc,))

    # THE RUNG-NOISE COLUMN, pinned to the figures crossbias.py's arm 5 PRINTS
    # (added 18 Sep 2026, item 1 of an internal note).
    # This is the cross-script pin and it is the whole point of moving the
    # arithmetic here: the same call that feeds `--grade` must still reproduce
    # the row that lane published, or there are two copies again and they have
    # already drifted. Source: the "ARM 5" table of
    # rounds/crossover-bias-2026-09-18/crossbias-output.txt.
    cp = os.path.join(rounds, 'crpin4m-2026-09-18', 'logs')
    for fname, metric, wx, wpct, wterm, wlo, whi in (
            ('cpe8.log', 'cpu', 396.43, 3.9, 3.4, 384, 416),
            ('cpe8.log', 'wall', 415.27, 4.2, 3.6, 384, 416),
            ('cpp4.log', 'cpu', 396.40, 5.3, 1.3, 384, 416),
            ('cpp4f.log', 'wall', 415.74, 0.8, 0.2, 412, 416)):
        lp = os.path.join(cp, fname)
        if not os.path.exists(lp):
            fails.append('rung-noise arm: banked crpin4m log missing: %s' % lp)
            continue
        ls = read_legs(lp)
        rungs = sorted({int(x['m']) for x in ls})
        shapes = {m: waskred.shape(ls, m) for m in rungs}
        keep = [m for m in rungs if shapes[m] == shapes[rungs[0]]]
        fold = {m: waskred.cell(ls, m, ('fold', 'fold2'), metric) for m in keep}
        force = {m: waskred.cell(ls, m, ('force', 'force2'), metric) for m in keep}
        rn = rung_noise(ls, keep, fold, force, metric)
        if rn is None:
            fails.append('rung-noise arm: %s [%s] located nothing' % (fname, metric))
            continue
        if abs(rn['x'] - wx) > 0.05 or (rn['lo'], rn['hi']) != (wlo, whi):
            fails.append('rung-noise arm: %s [%s] crossing %.2f bracket [%d,%d],'
                         ' want %.2f [%d,%d]'
                         % (fname, metric, rn['x'], rn['lo'], rn['hi'], wx, wlo, whi))
        if abs(round(rn['per_pct'], 1) - wpct) > 0.05:
            fails.append('rung-noise arm: %s [%s] one per cent of F/T is %.1f rows,'
                         ' crossbias published %.1f'
                         % (fname, metric, rn['per_pct'], wpct))
        if abs(round(rn['term'], 1) - wterm) > 0.05:
            fails.append('rung-noise arm: %s [%s] rung-noise term %.1f rows,'
                         ' crossbias published %.1f'
                         % (fname, metric, rn['term'], wterm))
    # A ladder with no A/A pair at a bracketing rung must report the term ABSENT
    # rather than as zero - "failing to find is failing", one rung down.
    if os.path.exists(bs):
        ls = waskred.legs(bs, 4)
        half = [x for x in ls if x['arm'] in ('fold', 'force')]
        rungs = sorted({int(x['m']) for x in half})
        fold = {m: waskred.cell(half, m, ('fold',), 'cpu') for m in rungs}
        force = {m: waskred.cell(half, m, ('force',), 'cpu') for m in rungs}
        rn = rung_noise(half, rungs, fold, force, 'cpu')
        if rn is None or rn['term'] is not None:
            fails.append('rung-noise arm: a ladder with no A/A pair priced a term'
                         ' (%r) instead of reporting it absent' % (rn and rn['term'],))

    # ...and the column REACHES the --grade output, which is the half a reader
    # actually sees.
    saved = sys.argv
    try:
        sys.argv = ['w3winred.py', '--grade', '--boot', '20',
                    'a4@4=' + bs, 'a16@16=' + bs]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main()
        out = buf.getvalue()
    finally:
        sys.argv = saved
    if rc != 0:
        fails.append('--grade with the rung-noise column returned %r, want 0' % rc)
    for want in ('RUNG-NOISE term', 'does NOT contain', 'A/A floors'):
        if want not in out:
            fails.append('--grade did not print the rung-noise column (%r missing)' % want)
    if 'implied rung-noise' in out and 'rows' not in out.split('implied rung-noise')[1]:
        fails.append('--grade printed the rung-noise header with no row under it')

    # THE JSONL SIDE OF THE LEG-FIELD REFUSAL. waskred's own selftest drives the
    # LOG side end to end on the banked old-format round; this adapter is the
    # other input to the same reduction, and a jsonl missing a reduced field
    # would hand it the identical garbage. Perturbed rather than asserted: one
    # banked line with its `m` removed, written to a temp file.
    import json as _json, tempfile
    with open(e64) as fh:
        lines = [l for l in fh if l.strip()]
    for field in ('m', 'arm', 'cpu'):
        d = None
        for l in lines:
            o = _json.loads(l)
            if o.get('phase') == 'ladder' and o.get('ok'):
                d = o
                break
        if d is None:
            fails.append('jsonl refusal arm: no phase=ladder leg in %s' % e64)
            break
        d = dict(d)
        d.pop(field, None)
        td = tempfile.mkdtemp()
        tp = os.path.join(td, 'perturbed.jsonl')
        with open(tp, 'w') as fh:
            fh.write(_json.dumps(d) + '\n')
        try:
            read_legs(tp)
        except SystemExit as e:
            msg = str(e.code)
            if 'perturbed.jsonl:1' not in msg or repr(field) not in msg:
                fails.append('jsonl refusal did not name file/line/field for %r: %r'
                             % (field, msg[:200]))
        else:
            fails.append('a jsonl leg with no %r was NOT refused' % field)
        finally:
            os.remove(tp)
            os.rmdir(td)

    if fails:
        for f in fails:
            print('FAIL ' + f)
        sys.exit('w3winred --selftest: %d check(s) failed' % len(fails))
    print('w3winred --selftest: OK - the 17 Sep crossovers (177/234/348, 185/240/353, '
          '155/205/372) and their published k values (376/416, 370/414, 337/478) '
          'reproduce through the shared arithmetic, the -t12 CPU -m1024 cell stays a '
          'bound with m=512 excluded, the drift arm reproduces the A/D control\'s four '
          'published deltas, a REFUSED cell neither crashes the bootstrap nor '
          're-enters it, the shape test refuses two window sizes by name, the '
          'jsonl adapter reproduces the 15 Sep EPYC guest (234/202/323 CPU) with '
          'the k phase excluded, a repeated --grade label is refused rather than '
          'fused, and the '
          '--grade arm reproduces the 15 Sep block-size table (410/343 CPU, 490 wall) '
          'and the create payload null (+4/-7 with its signs) and refuses a label '
          'containing "=", the rung-noise column reproduces crossbias arm 5 '
          '(3.9/3.4, 4.2/3.6, 5.3/1.3, 0.8/0.2 rows) through the ONE shared '
          'rung_noise and reaches the --grade output, and a leg missing a '
          'reduced field is refused by file, line and field on the jsonl side '
          'too')


if __name__ == '__main__':
    sys.exit(main() or 0)
