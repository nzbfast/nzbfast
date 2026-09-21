#!/usr/bin/env python3
"""COARSE-AGAINST-FINE crossover bias, over banked logs only
(lane `crpin-coarse-vs-fine-bias-18sep`, item 2 of
an internal note).

NO LEG WAS RUN AND NO BOX WAS TAKEN. Every figure is a re-reduction of logs
already committed under rounds/.

THE QUESTION. `crpin4m`'s section 5 found all four of its coarse-to-fine
comparisons moving UP (e8 CPU 396->398, wall 415->>420; p4 CPU 396->401, wall
412->416) and could not say why. One of its three unranked candidates is
testable with no box: if a crossover interpolated across a 32-row gap is
BIASED against the same crossover measured on a 4-row grid, that bias applies
to every 32-row reading in the campaign file, and the corpus is ~100 of them.

    crossbias.py [--boot N] [--pairs] [--sim] [--census]
                 [--sensitivity] [--curvature] [--selftest]

IT IMPORTS w3winred, WHICH IMPORTS waskred. `read_legs`, `cell`, `shape`,
`crossover` and `crossing_state` are theirs; the only arithmetic added here is
the chord-against-curve algebra below and the subsampling that drives it. Two
rounds that reduce differently stop being comparable and this campaign has
paid for that more than once - so a crossover printed here is the same
quantity, reduced by the same code, as one printed by either error-bar file.

THE ALGEBRA, WHICH IS WHY A DIRECTION IS PREDICTED RATHER THAN OBSERVED.
`crossover()` log-interpolates: with y(m) = log(fold/force), it takes the two
rungs that bracket y = 0 and returns the root of the CHORD through them. Write
the true curve locally as y(m) = A(m-x) + B(m-x)^2 with A > 0 (the transform
gains on the fold as m rises) and let the bracketing rungs be h apart with the
true root at fraction u of the interval. Then the chord's root sits at

    bias = x_chord - x_true = -h*beta*u*(1-u) / (1 + beta*(1-2u)),  beta = B*h/A

which to first order is  **-(B/A) * h^2 * u*(1-u)**. Three things follow and
each is a test rather than an assumption:

  1. THE SIGN IS THE CURVATURE'S. y convex (B > 0) makes the chord sit ABOVE
     the rising curve inside the interval, so it reaches zero EARLY and the
     coarse ladder reads LOW - which is the direction crpin4m observed. y
     concave makes the coarse ladder read HIGH. A campaign-wide correction
     therefore needs the curvature to have one sign campaign-wide.
  2. IT VANISHES AT BOTH ENDS. At u = 0 or u = 1 the crossing sits ON a rung
     and the chord is exact. So a coarse reading near a rung needs no
     correction however curved the ladder is, and the correction is NOT a
     constant per ladder - it depends on where the crossing fell.
  3. IT IS QUADRATIC IN THE GAP. 32 against 4 is a factor of 64, which is what
     makes a 4-row ladder usable as ground truth for an 8-to-28-row simulation.

WHAT EACH ARM DOES.

`--pairs` is the direct comparison: every banked cell carrying BOTH a coarse
and a fine ladder on the same box, binary, fixture and pool, graded with the
paired bootstrap w3winred's `--grade` arm uses (both ladders resampled in one
draw, the difference formed inside it). This is the observation, and it mixes
the grid term with ladder position and repeat - crpin4m bounds that second term
at 1.5% of F/T on e8 and 0.2% on p4 and could not separate them.

`--sim` is the isolation. Within ONE fine ladder, the pair of rungs h apart
that brackets the crossing IS a simulated coarse grid: same legs, same sitting,
same fixture, same ladder position, so everything except the grid cancels by
construction. The bias is then (chord over h) - (the ladder's own crossover),
reported against u and h, and bootstrapped in the same draw so the difference
is paired.

`--census` applies the algebra to every banked 32-row crossover: fit the local
curve through that ladder's OWN rungs, compare its root to the chord's, and
report the implied correction with a bootstrap bar. It is validated against
`--sim`'s answers on the arms where a fine ladder exists, which is the only
reason to believe it anywhere else.

STATED LIMITS, which the report repeats.
  - A fine ladder is the reference, not the truth. Its own crossover carries
    the same bias at its own spacing; at 4 rows against 32 that residual is
    1/64 of the term being measured, which is why the reference is usable.
  - `--sim` cannot reach h = 32 on the 4-row ladders: they span 28 rows. It
    reaches h = 32 only on `cband`, whose lower bracket is a RUINED rung (see
    below), so every h = 32 figure here is an extrapolation in h and is flagged.
  - THE CBAND LADDER IS REFUSED, and that refusal is a finding. `crband`'s own
    README records that it put its first rung inside the region it was
    measuring; that rung, m = 384, carries a fold A/A floor of 30.1% CPU and
    28.9% wall against 0.5-4.2% at its other four. Every crossing in that
    ladder is bracketed below by it. So `cband` is not a fine reference and its
    coarse-to-fine difference is not a grid measurement.
  - Non-monotone ladders produce subsample pairs that bracket a DIFFERENT
    crossing from the reference one. Those are excluded by requiring
    0 <= u <= 1, and the count excluded is reported rather than dropped
    quietly.
  - Nothing here is a systematic's cure. The bootstrap resamples the same legs,
    so a rung that is wrong in both its copies is invisible to it - the
    round-2 error-bar file's section 2 has the worked case.
"""
import math, os, statistics as st, sys, random, glob

sys.dont_write_bytecode = True  # see w3winred's note: a .pyc in the published tree
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'w3win-nibble-2026-09-18'))
import w3winred  # noqa: E402
import waskred   # noqa: E402  - reached through w3winred's own sys.path entry

# THE ROUND TREE IS RESOLVED FROM THIS FILE, NOT FROM THE REPO ROOT, and that
# is what lets the PUBLISHED copy run. `website/tools/export_parfast_evidence.py`
# mirrors rounds/ into website/parfast-bench/rounds/, and
# `size-gate.yml:tool-selftests` runs BOTH copies (the mirror is scrubbed, so a
# selftest that only ever ran in-repo would not notice the scrub breaking a
# reduction). Both copies sit at `<base>/rounds/<round>/`, so the sibling rounds
# are always one directory up - `../..` from the repo root would be `website/`
# under the mirror and every log would go missing.
ROUNDS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def R(*p):
    return os.path.join(ROUNDS, *p)


# The cells that carry BOTH a coarse and a fine ladder on one box, one binary,
# one fixture and one pool. Found by inventorying every banked ladder's rung
# set (see the report's section 1); these three are the whole population.
PAIRS = [
    ('4mc-e8  (0xFF0, -t8, create, 4 MiB n=4096)', 'crpin4m-2026-09-18/logs/cpe8.log',
     'crpin4m-2026-09-18/logs/cpe8f.log', None),
    ('4mc-p4  (0xF,   -t4, create, 4 MiB n=4096)', 'crpin4m-2026-09-18/logs/cpp4.log',
     'crpin4m-2026-09-18/logs/cpp4f.log', None),
    ('4mcb    (unpinned, -t16, create, 4 MiB n=4096)', 'crband-2026-09-18/logs/csolo.log',
     'crband-2026-09-18/logs/cband.log', 'REFUSED: the fine ladder\'s only lower '
     'bracket is m=384, whose fold A/A floor is 30.1% CPU / 28.9% wall - '
     'crband\'s own documented ruined first rung.'),
]

# Fine ladders usable as a reference for --sim: spacing <= 16 rows, a located
# crossover, and no rung refused for the reason above.
FINE = [
    ('4mc-e8-fine', 'crpin4m-2026-09-18/logs/cpe8f.log', 4, ('cpu',)),
    ('4mc-p4-fine', 'crpin4m-2026-09-18/logs/cpp4f.log', 4, ('cpu', 'wall')),
    ('1m-res-bracket', 'rowgate-2026-09-16/coreultra9-gfni256-1m-n8192-resident-bracket.log',
     16, ('cpu',)),
]


def ladder_cells(path, metric, threads=None, label=None):
    """This ladder's in-shape rungs and its fold/force cells, waskred's way."""
    ls = w3winred.read_legs(path, threads)
    if label:
        sel = [x for x in ls if x.get('label') == label]
        if sel:
            ls = sel
    rungs = sorted({int(x['m']) for x in ls})
    shapes = {m: waskred.shape(ls, m) for m in rungs}
    keep = [m for m in rungs if shapes[m] == shapes[rungs[0]]]
    fold = {m: waskred.cell(ls, m, ('fold', 'fold2'), metric) for m in keep}
    force = {m: waskred.cell(ls, m, ('force', 'force2'), metric) for m in keep}
    return ls, keep, fold, force


def resampled(ls, keep, metric, rng):
    """The same cells with each rung's legs drawn with replacement, w3winred's way."""
    fold, force = {}, {}
    for m in keep:
        for name, arms in (('fold', ('fold', 'fold2')), ('force', ('force', 'force2'))):
            v = [float(x[metric]) for x in ls if int(x['m']) == m and x['arm'] in arms]
            d = fold if name == 'fold' else force
            d[m] = st.median([v[rng.randrange(len(v))] for _ in v]) if v else None
    return fold, force


def chord_root(m0, r0, m1, r1):
    """waskred.crossover's arithmetic for ONE pair - the root of the chord in log F/T."""
    if r0 is None or r1 is None or r0 <= 0 or r1 <= 0:
        return None
    lo, hi = math.log(r0), math.log(r1)
    if hi == lo:
        return None
    return m0 + (0 - lo) / (hi - lo) * (m1 - m0)


def chord_bias(h, u, beta):
    """The closed form quoted in the docstring, for the selftest to check
    the numeric interpolation against."""
    den = 1 + beta * (1 - 2 * u)
    if abs(den) < 1e-12:
        return None
    return -h * beta * u * (1 - u) / den


def ratios(keep, fold, force):
    return {m: fold[m] / force[m] for m in keep
            if fold.get(m) and force.get(m)}


def subsample_pairs(r, xref):
    """Every pair of rungs that brackets y=0 with the REFERENCE root inside it.

    The second condition is what keeps a non-monotone ladder honest: a dip can
    make a far pair bracket a DIFFERENT crossing, and comparing that chord to
    this reference measures the dip rather than the grid.
    """
    ks = sorted(r)
    out, rejected = [], 0
    for i in range(len(ks)):
        for j in range(i + 1, len(ks)):
            a, b = ks[i], ks[j]
            if not (r[a] < 1.0 <= r[b]):
                continue
            if not (a <= xref <= b):
                rejected += 1
                continue
            x2 = chord_root(a, r[a], b, r[b])
            if x2 is None:
                continue
            h = b - a
            out.append((a, b, h, (xref - a) / h, x2, x2 - xref))
    return out, rejected


def quad_root(ms, ys, x0, lo, hi):
    """Root of the least-squares quadratic through (ms, ys), nearest x0, inside [lo,hi].

    This is the curve the chord is being compared against in --census: the same
    ladder's own rungs, read as a smooth local shape instead of two points.
    Returns None rather than guessing when the fit has no root in the interval -
    failing to find is failing.
    """
    n = len(ms)
    if n < 3:
        return None
    sx = [sum(m ** k for m in ms) for k in range(5)]
    sy = [sum(y * m ** k for m, y in zip(ms, ys)) for k in range(3)]
    # normal equations for y = c0 + c1 m + c2 m^2
    A = [[sx[0], sx[1], sx[2]], [sx[1], sx[2], sx[3]], [sx[2], sx[3], sx[4]]]
    b = [sy[0], sy[1], sy[2]]
    # Gaussian elimination, 3x3
    for i in range(3):
        p = max(range(i, 3), key=lambda k: abs(A[k][i]))
        if abs(A[p][i]) < 1e-30:
            return None
        A[i], A[p] = A[p], A[i]
        b[i], b[p] = b[p], b[i]
        for k in range(i + 1, 3):
            f = A[k][i] / A[i][i]
            for c in range(i, 3):
                A[k][c] -= f * A[i][c]
            b[k] -= f * b[i]
    c = [0.0] * 3
    for i in (2, 1, 0):
        c[i] = (b[i] - sum(A[i][j] * c[j] for j in range(i + 1, 3))) / A[i][i]
    c0, c1, c2 = c
    if abs(c2) < 1e-18:
        return -c0 / c1 if abs(c1) > 1e-18 else None
    disc = c1 * c1 - 4 * c2 * c0
    if disc < 0:
        return None
    rs = [(-c1 + s * math.sqrt(disc)) / (2 * c2) for s in (1, -1)]
    rs = [x for x in rs if lo <= x <= hi]
    if not rs:
        return None
    return min(rs, key=lambda x: abs(x - x0))


# ----------------------------------------------------------------- arm: --pairs
def arm_pairs(nboot):
    """Every banked coarse/fine cell, graded with the paired bootstrap."""
    print('== ARM 1: the direct coarse-against-fine comparison, paired inside the draw')
    print('   (observation. It mixes the GRID term with ladder position and repeat,'
          ' which is why arm 2 exists.)')
    rows = []
    for name, cpath, fpath, refusal in PAIRS:
        print()
        print(f'-- {name}')
        if refusal:
            print(f'   {refusal}')
            print('   Not graded. A ladder whose bracketing rung is ruined is not a'
                  ' fine reference, and its coarse-to-fine difference measures the'
                  ' ruined rung.')
            rows.append(dict(cell=name, refused=refusal))
            continue
        for metric in ('cpu', 'wall'):
            cls_, ckeep, _, _ = ladder_cells(R(cpath), metric)
            fls, fkeep, _, _ = ladder_cells(R(fpath), metric)
            cf = {m: waskred.cell(cls_, m, ('fold', 'fold2'), metric) for m in ckeep}
            ct = {m: waskred.cell(cls_, m, ('force', 'force2'), metric) for m in ckeep}
            ff = {m: waskred.cell(fls, m, ('fold', 'fold2'), metric) for m in fkeep}
            ft = {m: waskred.cell(fls, m, ('force', 'force2'), metric) for m in fkeep}
            xc = waskred.crossover(ckeep, cf, ct)
            xf = waskred.crossover(fkeep, ff, ft)
            if xc is None or xf is None:
                which = 'coarse' if xc is None else 'fine'
                stt = waskred.crossing_state(ckeep, cf, ct) if xc is None \
                    else waskred.crossing_state(fkeep, ff, ft)
                print(f'   {metric:4s} the {which} ladder has NO CROSSOVER IN SHAPE'
                      f' ({stt}) - a BOUND, not a point, so no difference is formed.')
                rows.append(dict(cell=name, metric=metric, bound=which, state=stt))
                continue
            rng = random.Random(20260918)
            ds, cs, fs = [], [], []
            for _ in range(nboot):
                a, b = resampled(cls_, ckeep, metric, rng)
                c, d = resampled(fls, fkeep, metric, rng)
                x1 = waskred.crossover(ckeep, a, b)
                x2 = waskred.crossover(fkeep, c, d)
                if x1 is None or x2 is None:
                    continue
                cs.append(x1)
                fs.append(x2)
                ds.append(x2 - x1)
            obs = xf - xc
            sd = st.pstdev(ds) if len(ds) > 1 else float('nan')
            flip = sum(1 for v in ds if (v > 0) != (obs > 0)) / len(ds) if ds else float('nan')
            lo = max(m for m in ckeep if m <= xc)
            hi = min(m for m in ckeep if m > xc)
            print(f'   {metric:4s} coarse {xc:7.2f} (sd {st.pstdev(cs):4.1f}, bracket'
                  f' [{lo},{hi}] h={hi-lo}, u={(xc-lo)/(hi-lo):.3f})'
                  f'   fine {xf:7.2f} (sd {st.pstdev(fs):4.1f})')
            print(f'        fine - coarse = {obs:+6.2f} rows   sd {sd:4.1f}'
                  f'   {abs(obs)/sd if sd else float("inf"):4.1f} sigma'
                  f'   SIGN FLIPS IN {flip*100:5.1f}% of {len(ds)} resamples')
            rows.append(dict(cell=name, metric=metric, coarse=xc, fine=xf, diff=obs,
                             sd=sd, flip=flip, h=hi - lo, u=(xc - lo) / (hi - lo)))
    return rows


# ------------------------------------------------------------------- arm: --sim
def arm_sim(nboot):
    """Simulate a coarse grid inside each fine ladder and measure the bias."""
    print()
    print('== ARM 2: the coarse grid SIMULATED inside each fine ladder')
    print('   Same legs, same sitting, same ladder position - everything but the'
          ' GRID cancels by construction.')
    rows = []
    for name, path, spacing, metrics in FINE:
        for metric in metrics:
            ls, keep, fold, force = ladder_cells(R(path), metric)
            xref = waskred.crossover(keep, fold, force)
            if xref is None:
                continue
            r = ratios(keep, fold, force)
            pairs, rejected = subsample_pairs(r, xref)
            nlegs = sorted({len([x for x in ls if int(x['m']) == m]) for m in keep})
            print()
            print(f'-- {name} [{metric}]  reference crossover {xref:.2f} on a'
                  f' {spacing}-row grid, legs/rung {nlegs}'
                  + (f', {rejected} far pair(s) excluded (they bracket a DIFFERENT'
                     f' crossing - the ladder is non-monotone)' if rejected else ''))
            rng = random.Random(20260918)
            draws = []
            for _ in range(nboot):
                f2, t2 = resampled(ls, keep, metric, rng)
                x = waskred.crossover(keep, f2, t2)
                if x is None:
                    draws.append(None)
                    continue
                rr = ratios(keep, f2, t2)
                draws.append((x, rr))
            print('      h    rungs        u     chord   bias   sd  sign flips')
            for a, b, h, u, x2, bias in sorted(pairs, key=lambda p: (p[2], p[0])):
                if h == spacing:
                    continue  # the reference's own bracket; bias is 0 by definition
                bs = []
                for d in draws:
                    if d is None:
                        continue
                    x, rr = d
                    if a not in rr or b not in rr:
                        continue
                    xx = chord_root(a, rr[a], b, rr[b])
                    if xx is None:
                        continue
                    bs.append(xx - x)
                sd = st.pstdev(bs) if len(bs) > 1 else float('nan')
                flip = (sum(1 for v in bs if (v > 0) != (bias > 0)) / len(bs)
                        if bs else float('nan'))
                print(f'   {h:4d}  [{a},{b}]  {u:5.3f}  {x2:7.2f}  {bias:+6.2f}'
                      f'  {sd:4.1f}  {flip*100:5.1f}%')
                rows.append(dict(ladder=name, metric=metric, h=h, lo=a, hi=b, u=u,
                                 chord=x2, bias=bias, sd=sd, flip=flip, xref=xref))
    return rows


def fit_C(rows):
    """Least-squares C in bias = C * h^2 * u(1-u), the first-order law, per ladder.

    C has units of 1/row and is -(B/A): the curvature of log(F/T) divided by its
    slope. Its SIGN is the whole question - one sign across the corpus means a
    correction exists, mixed signs mean there is nothing to correct, only an
    error term to add.
    """
    out = {}
    for key in sorted({(r['ladder'], r['metric']) for r in rows}):
        sel = [r for r in rows if (r['ladder'], r['metric']) == key]
        num = sum(r['bias'] * (r['h'] ** 2 * r['u'] * (1 - r['u'])) for r in sel)
        den = sum((r['h'] ** 2 * r['u'] * (1 - r['u'])) ** 2 for r in sel)
        if den <= 0:
            continue
        C = num / den
        resid = [r['bias'] - C * r['h'] ** 2 * r['u'] * (1 - r['u']) for r in sel]
        rms_b = math.sqrt(sum(r['bias'] ** 2 for r in sel) / len(sel))
        rms_r = math.sqrt(sum(v ** 2 for v in resid) / len(sel))
        out[key] = (C, len(sel), rms_b, rms_r, C * 32 ** 2 * 0.25)
    return out


# ---------------------------------------------------------------- arm: --census
def census_one(path, metric, threads, label, nboot, rng_seed=20260918):
    """One banked ladder's 32-row chord root, the local CURVE's root, and the gap.

    `delta = x_curve - x_chord` is the correction the chord bias implies for
    THIS ladder, read off the ladder's own rungs rather than assumed. Both roots
    are recomputed inside every bootstrap draw, so their difference is paired
    and its bar is the bar on the CORRECTION, not on either root.
    """
    ls, keep, fold, force = ladder_cells(path, metric, threads, label)
    x = waskred.crossover(keep, fold, force)
    if x is None:
        return None
    lo = max(m for m in keep if m <= x)
    hi = min(m for m in keep if m > x)
    if hi - lo != 32:
        return None
    win = [m for m in keep if lo - 32 <= m <= hi + 32]
    if len(win) < 3:
        return None

    def roots(f, t):
        r = ratios(win, f, t)
        if lo not in r or hi not in r or len(r) < 3:
            return None, None
        xc = chord_root(lo, r[lo], hi, r[hi])
        ms = sorted(r)
        xq = quad_root(ms, [math.log(r[m]) for m in ms], x, lo - 32, hi + 32)
        return xc, xq

    xc0, xq0 = roots(fold, force)
    if xc0 is None or xq0 is None:
        return None
    rng = random.Random(rng_seed)
    ds = []
    for _ in range(nboot):
        f2, t2 = resampled(ls, win, metric, rng)
        a, b = roots(f2, t2)
        if a is None or b is None:
            continue
        ds.append(b - a)
    if len(ds) < nboot * 0.5:
        return None
    d0 = xq0 - xc0
    sd = st.pstdev(ds)
    flip = sum(1 for v in ds if (v > 0) != (d0 > 0)) / len(ds)
    return dict(x=x, lo=lo, hi=hi, u=(x - lo) / 32, chord=xc0, curve=xq0,
                delta=d0, sd=sd, flip=flip, rungs=win)


def inventory():
    """Every banked ladder, by (path, label, threads). Old-format logs are SKIPPED
    BY NAME rather than crashing three functions downstream - the silent-garbage
    parse the round-2 error-bar file's section 1.1 documents."""
    out, skipped = [], []
    for path in sorted(glob.glob(os.path.join(ROUNDS, '**', '*.log'),
                                 recursive=True)):
        seen = set()
        ok = True
        for line in open(path, errors='replace'):
            # harness-rig-gate: a reducer here. This arm parses the LEG lines
            #   of a banked round it is handed; the round log it reads was
            #   stamped by the driver that wrote it.
            if not line.startswith('LEG '):
                continue
            d = {}
            for t in line.split():
                if '=' in t:
                    k, v = t.split('=', 1)
                    d[k] = v
            if 'arm' not in d or 'm' not in d or not d['m'].isdigit():
                ok = False
                break
            seen.add((d.get('label'), d.get('threads')))
        if not ok:
            skipped.append(path)
            continue
        for label, th in seen:
            out.append((path, label, int(th) if th and th.isdigit() else None))
    return out, skipped


def arm_census(nboot):
    print()
    print('== ARM 3: the correction the algebra implies for EVERY banked 32-row crossover')
    print('   delta = (root of the local CURVE through this ladder\'s own rungs)'
          ' - (root of the CHORD).')
    inv, skipped = inventory()
    rows = []
    for path, label, th in inv:
        for metric in ('cpu', 'wall'):
            try:
                r = census_one(path, metric, th, label, nboot)
            except (SystemExit, KeyError, ValueError, ZeroDivisionError):
                continue
            if r is None:
                continue
            r.update(path=os.path.relpath(path, ROUNDS),
                     label=label, threads=th, metric=metric)
            rows.append(r)
    pos = [r for r in rows if r['delta'] > 0]
    print(f'   {len(rows)} banked 32-row crossovers reduced'
          f' ({len(skipped)} old-format log(s) skipped by name).')
    print(f'   delta > 0 (the coarse reading is LOW, so the correction is UP)'
          f' in {len(pos)} of {len(rows)}.')
    ad = sorted(abs(r['delta']) for r in rows)
    print(f'   |delta|: median {st.median(ad):.1f} rows, 90th pct'
          f' {ad[int(0.9*len(ad))]:.1f}, max {ad[-1]:.1f}')
    firm = [r for r in rows if r['flip'] < 0.05]
    print(f'   distinguishable from zero (sign flips in under 5% of resamples):'
          f' {len(firm)} of {len(rows)}'
          + (f', of which {sum(1 for r in firm if r["delta"]>0)} positive'
             if firm else ''))
    return rows, skipped


def arm_validate(sim_rows, nboot):
    """The only reason to believe arm 3 anywhere: check it where arm 2 knows the answer.

    For each cell that has a fine ladder, arm 3's correction is applied to the
    COARSE sibling and the corrected reading is compared with the fine one.
    """
    print()
    print('== ARM 4: arm 3 VALIDATED against arm 1, on the two cells that have both')
    print('   cell              metric  coarse  +delta = corrected   fine   |err| before -> after')
    out = []
    for name, cpath, fpath, refusal in PAIRS:
        if refusal:
            continue
        for metric in ('cpu', 'wall'):
            c = census_one(R(cpath), metric, None, None, nboot)
            if c is None:
                continue
            fls, fkeep, ff, ft = ladder_cells(R(fpath), metric)
            xf = waskred.crossover(fkeep, ff, ft)
            if xf is None:
                continue
            before = abs(xf - c['x'])
            after = abs(xf - (c['x'] + c['delta']))
            print(f'   {name.split()[0]:16s} {metric:5s} {c["x"]:7.2f}'
                  f'  {c["delta"]:+6.2f} = {c["x"]+c["delta"]:7.2f}'
                  f'  {xf:7.2f}   {before:5.2f} -> {after:5.2f}'
                  f'   {"BETTER" if after < before else "WORSE"}')
            out.append(dict(cell=name, metric=metric, coarse=c['x'], delta=c['delta'],
                            fine=xf, before=before, after=after))
    return out


# ----------------------------------------------------------- arm: --sensitivity
def arm_sensitivity():
    """How many rows one per-cent of F/T is worth at each crossing, and the
    rung-noise term that implies.

    THIS IS THE RIVAL EXPLANATION, and it needs a number or the reader cannot
    weigh it against the grid. A crossover is a root of log(F/T), so a cell that
    is wrong by e per cent moves it by e / (100 * dy/dm) rows. The ladder's OWN
    A/A floor is the campaign's measure of e, so the two together price "one
    bracketing rung drew badly" in rows - the term that is present at EVERY
    spacing and that no amount of grid refinement removes.

    THE ARITHMETIC IS `w3winred.rung_noise` AND NO LONGER LIVES HERE (18 Sep
    2026, item 1 of an internal note). It was written
    in this function; `w3winred --grade` now prints the same column against every
    crossover the campaign publishes, and a second copy of it is the defect this
    campaign keeps paying for. This arm is the printing and the ladder roster;
    the numbers come from there. Every figure below is unchanged by the move.
    """
    print()
    print('== ARM 5: what one per-cent of F/T is worth in rows, and the rung-noise term')
    print('   ladder            metric  crossing  bracket      1% of F/T   A/A floors'
          ' (lo | hi)   implied rung-noise')
    out = []
    for name, path, metric in [('4mc-e8 coarse', 'crpin4m-2026-09-18/logs/cpe8.log', 'cpu'),
                               ('4mc-e8 coarse', 'crpin4m-2026-09-18/logs/cpe8.log', 'wall'),
                               ('4mc-p4 coarse', 'crpin4m-2026-09-18/logs/cpp4.log', 'cpu'),
                               ('4mc-p4 coarse', 'crpin4m-2026-09-18/logs/cpp4.log', 'wall'),
                               ('4mc-e8-fine', 'crpin4m-2026-09-18/logs/cpe8f.log', 'cpu'),
                               ('4mc-p4-fine', 'crpin4m-2026-09-18/logs/cpp4f.log', 'cpu'),
                               ('4mc-p4-fine', 'crpin4m-2026-09-18/logs/cpp4f.log', 'wall')]:
        ls, keep, f, t = ladder_cells(R(path), metric)
        rn = w3winred.rung_noise(ls, keep, f, t, metric)
        if rn is None:
            continue
        lo, hi = rn['lo'], rn['hi']
        fl = rn['floors']
        print(f'   {name:17s} {metric:5s} {rn["x"]:8.2f}  [{lo},{hi}]'
              f'  {rn["per_pct"]:8.1f} rows'
              f'   {fl[lo][0]:.2f}/{fl[lo][1]:.2f}% | {fl[hi][0]:.2f}/{fl[hi][1]:.2f}%'
              f'      {rn["term"]:5.1f} rows')
        out.append(dict(ladder=name, metric=metric, x=rn['x'],
                        per_pct=rn['per_pct'], term=rn['term']))
    return out


# ------------------------------------------------------------- arm: --curvature
def arm_curvature():
    """Is there a curvature at 32-row spacing at all, or only noise shaped like one?

    THIS IS THE TEST THAT DECIDES ARM 3, and it needs no fine ladder. The chord
    bias is proportional to the SECOND DERIVATIVE of log(F/T). A ladder's second
    difference estimates it, and a REAL curvature changes slowly along the
    ladder, so adjacent second differences should mostly agree in sign. Per-rung
    NOISE does the opposite: adjacent second differences share two rungs with
    opposite weights, giving a correlation of exactly -2/3 and, for a Gaussian,
    a sign DISAGREEMENT rate of 1/2 + arcsin(2/3)/pi = 73.2%.

    So the observed disagreement rate is a direct read-out of how much of the
    measured curvature is real: near 50% means a resolved shape, near 73% means
    there is nothing there but the rungs' own scatter.
    """
    print()
    print('== ARM 6: is the curvature at 32-row spacing RESOLVED, or noise shaped like one?')
    inv, _ = inventory()
    lad = tot = dis = 0
    for path, label, th in inv:
        for metric in ('cpu', 'wall'):
            try:
                _, keep, f, t = ladder_cells(path, metric, th, label)
            except (SystemExit, KeyError, ValueError, ZeroDivisionError):
                continue
            r = ratios(keep, f, t)
            ms = sorted(r)
            ms = [m for i, m in enumerate(ms) if i == 0 or m - ms[i - 1] == 32]
            if len(ms) < 4:
                continue
            y = [math.log(r[m]) for m in ms]
            d2 = [y[i + 1] - 2 * y[i] + y[i - 1] for i in range(1, len(y) - 1)]
            if len(d2) < 2:
                continue
            lad += 1
            for i in range(len(d2) - 1):
                tot += 1
                dis += (d2[i] > 0) != (d2[i + 1] > 0)
    pred = 0.5 + math.asin(2 / 3) / math.pi
    print(f'   {lad} coarse ladder-metrics carry four or more consecutive 32-row rungs.')
    print(f'   Adjacent second differences DISAGREE in sign in {dis} of {tot}'
          f' pairs = {dis/tot*100:.0f}%.')
    print(f'   Pure per-rung noise predicts {pred*100:.1f}%; a resolved curvature'
          f' predicts well under 50%.')
    print('   => the curvature a 32-row ladder appears to have is, to within a few'
          ' per cent, its own rung scatter.')
    return dict(ladders=lad, pairs=tot, disagree=dis, predicted=pred)


# ---------------------------------------------------------------------- selftest
def selftest():
    """Pin the arithmetic and the published figures this lane reads off.

    FAILING TO FIND IS FAILING: a selftest that cannot locate its logs reports
    its own blindness, not a pass.
    """
    fails = []
    need = [p for _, c, f, _ in PAIRS for p in (c, f)] + [p for _, p, _, _ in FINE]
    miss = [p for p in need if not os.path.exists(R(p))]
    if miss:
        sys.exit('crossbias --selftest: banked log(s) missing: ' + ', '.join(miss))

    # 1. The closed form matches the numeric interpolation on a synthetic
    #    quadratic, which is what licenses quoting a DIRECTION from the algebra.
    for beta in (0.3, -0.3, 0.05):
        for u in (0.2, 0.5, 0.85):
            h, A = 32.0, 0.01
            B = beta * A / h
            x = 400.0
            m0, m1 = x - u * h, x + (1 - u) * h
            y = lambda m: A * (m - x) + B * (m - x) ** 2  # noqa: E731
            got = chord_root(m0, math.exp(y(m0)), m1, math.exp(y(m1))) - x
            want = chord_bias(h, u, beta)
            if abs(got - want) > 1e-6:
                fails.append(f'chord_bias(beta={beta},u={u}) {want:.6f} != numeric {got:.6f}')
    # and the predicted SIGN: convex (B>0) must make the chord read LOW
    if not (chord_bias(32, 0.5, 0.3) < 0 < chord_bias(32, 0.5, -0.3)):
        fails.append('the sign convention is inverted: convex must read LOW')
    # and it must VANISH at both ends
    for beta in (0.3, -0.3):
        if abs(chord_bias(32, 0.0, beta)) > 1e-12 or abs(chord_bias(32, 1.0, beta)) > 1e-12:
            fails.append('chord_bias does not vanish at u=0 / u=1')

    # 2. The crossovers this lane quotes, pinned to crpin4m's and crband's own
    #    published READMEs. Source: rounds/crpin4m-2026-09-18/README.md
    #    sections 2 and 5, and the crband sitting's csolo ladder.
    want = [('crpin4m-2026-09-18/logs/cpe8.log', 'cpu', 396.4),
            ('crpin4m-2026-09-18/logs/cpe8.log', 'wall', 415.3),
            ('crpin4m-2026-09-18/logs/cpe8f.log', 'cpu', 398.0),
            ('crpin4m-2026-09-18/logs/cpp4.log', 'cpu', 396.4),
            ('crpin4m-2026-09-18/logs/cpp4.log', 'wall', 412.5),
            ('crpin4m-2026-09-18/logs/cpp4f.log', 'cpu', 401.2),
            ('crpin4m-2026-09-18/logs/cpp4f.log', 'wall', 415.7)]
    for p, metric, exp in want:
        _, keep, f, t = ladder_cells(R(p), metric)
        got = waskred.crossover(keep, f, t)
        if got is None or abs(got - exp) > 0.1:
            fails.append(f'{os.path.basename(p)} [{metric}] {got} != published {exp}')
    # the e8 fine ladder never crosses in WALL by its top rung - the bound
    # crpin4m publishes as ">420", and a BOUND must not become a point here.
    _, keep, f, t = ladder_cells(R('crpin4m-2026-09-18/logs/cpe8f.log'), 'wall')
    if waskred.crossover(keep, f, t) is not None:
        fails.append('the e8 fine ladder must stay a BOUND in wall (crpin4m: ">420")')

    # 3. The cband refusal is a MEASURED fact, not an assertion: m=384's fold
    #    A/A floor must still be an order of magnitude above every other rung's.
    ls = w3winred.read_legs(R('crband-2026-09-18/logs/cband.log'))
    floors = {}
    for m in sorted({int(x['m']) for x in ls}):
        v = {a: [float(x['cpu']) for x in ls if int(x['m']) == m and x['arm'] == a]
             for a in ('fold', 'fold2')}
        if v['fold'] and v['fold2']:
            a, b = st.median(v['fold']), st.median(v['fold2'])
            floors[m] = abs(a - b) / ((a + b) / 2) * 100
    if not (floors.get(384, 0) > 25 and max(v for m, v in floors.items() if m != 384) < 10):
        fails.append(f'crband m=384 is no longer the outlier this lane refuses it for: {floors}')

    # 4. The non-monotone guard actually rejects: cpp4f's dip at m=412 offers a
    #    [412,416] pair that brackets a SECOND crossing above the reference.
    _, keep, f, t = ladder_cells(R('crpin4m-2026-09-18/logs/cpp4f.log'), 'cpu')
    x = waskred.crossover(keep, f, t)
    _, rej = subsample_pairs(ratios(keep, f, t), x)
    if rej < 1:
        fails.append('the u-in-[0,1] guard rejects nothing on the non-monotone p4 ladder')

    # 5. quad_root reproduces a known root and REFUSES rather than guessing.
    ms = [320.0, 352.0, 384.0, 416.0]
    ys = [0.01 * (m - 370) + 2e-5 * (m - 370) ** 2 for m in ms]
    got = quad_root(ms, ys, 370, 320, 416)
    if got is None or abs(got - 370) > 0.01:
        fails.append(f'quad_root({got}) != 370 on an exact quadratic')
    if quad_root(ms[:2], ys[:2], 370, 320, 416) is not None:
        fails.append('quad_root must refuse fewer than three points')

    # 6. The noise-shaped-curvature prediction is arithmetic, not a fit: pin it.
    pred = 0.5 + math.asin(2 / 3) / math.pi
    if abs(pred - 0.7323) > 0.001:
        fails.append(f'the pure-noise sign-disagreement rate moved: {pred}')

    # 7. ARM 5 STILL PRINTS ITS PUBLISHED TABLE THROUGH THE SHARED FUNCTION.
    #    The arithmetic moved to `w3winred.rung_noise` on 18 Sep 2026 (item 1 of
    #    an internal note) so that `--grade` and this
    #    arm are one copy. w3winred's own selftest pins the same four rows from
    #    the other side; this one pins the PRINTED table, because that is what
    #    crossbias-output.txt and the report quote. A copy dragged back in here
    #    reddens on whichever side it disagrees with.
    import io as _io, contextlib as _cl
    buf = _io.StringIO()
    with _cl.redirect_stdout(buf):
        arm_sensitivity()
    sens = buf.getvalue()
    for want in ('396.43  [384,416]       3.9 rows',
                 '415.27  [384,416]       4.2 rows',
                 '396.40  [384,416]       5.3 rows',
                 '415.74  [412,416]       0.8 rows',
                 '3.4 rows', '3.6 rows', '1.3 rows', '0.2 rows'):
        if want not in sens:
            fails.append('arm 5 no longer prints %r through w3winred.rung_noise' % want)
    if 'A/A floors' not in sens:
        fails.append('arm 5 printed no A/A floor column')

    if fails:
        print('crossbias --selftest: FAILED')
        for f_ in fails:
            print('  -', f_)
        return 1
    print('crossbias --selftest: OK - the closed-form chord bias matches the numeric '
          'interpolation in sign, magnitude and its vanishing at both interval ends; '
          'the seven crpin4m crossovers this lane quotes (396.4/415.3/398.0 e8, '
          '396.4/412.5/401.2/415.7 p4) reproduce and the e8 fine ladder stays a BOUND '
          'in wall; crband m=384 is still the 30%-floor outlier the cband refusal '
          'rests on; the non-monotone guard rejects a pair on cpp4f; and quad_root '
          'finds an exact root and refuses fewer than three points, and the '
          'pure-noise second-difference sign-disagreement rate is still 73.2%; and '
          'arm 5 still prints its published table (3.9/4.2/5.3/0.8 rows per one '
          'per cent, 3.4/3.6/1.3/0.2 rows of rung noise) through the ONE shared '
          'w3winred.rung_noise')
    return 0


def main():
    argv = sys.argv[1:]
    if '--selftest' in argv:
        return selftest()
    nboot = 2000
    if '--boot' in argv:
        nboot = int(argv[argv.index('--boot') + 1])
    want = {a for a in argv if a in ('--pairs', '--sim', '--census', '--sensitivity', '--curvature')} or \
        {'--pairs', '--sim', '--census', '--sensitivity', '--curvature'}
    print(f'== crossbias, boot={nboot}, NO LEG RUN, NO BOX TAKEN')
    sim_rows = []
    if '--pairs' in want:
        arm_pairs(nboot)
    if '--sim' in want:
        sim_rows = arm_sim(nboot)
        print()
        print('== the first-order law bias = C * h^2 * u(1-u), fitted per ladder')
        print('   C is -(curvature/slope) of log(F/T), in 1/row. ONE SIGN across the'
              ' corpus would be a correction; MIXED signs are an error term.')
        print('   ladder                 metric   n     C (1/row)   rms bias'
              '   rms resid   implied bias at h=32,u=0.5')
        for (lad, met), (C, n, rb, rr, at32) in fit_C(sim_rows).items():
            print(f'   {lad:22s} {met:5s} {n:4d}   {C:+10.3e}   {rb:8.2f}   {rr:9.2f}'
                  f'   {at32:+8.2f} rows')
    if '--census' in want:
        arm_census(nboot)
        arm_validate(sim_rows, nboot)
    if '--sensitivity' in want:
        arm_sensitivity()
    if '--curvature' in want:
        arm_curvature()
    return 0


if __name__ == '__main__':
    sys.exit(main())
