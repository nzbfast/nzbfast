#!/usr/bin/env python3
"""Cross-ladder reduction for the nibble windowed-ask round
(lane parfast-nibble-windowed-ask-1mib-16sep).

rowgate.py read gives each ladder's own table and crossover. This adds the
three things the comparison needs and it does not: the per-rung SHAPE
(windows/win_slices/slabs) so a rung whose shape changed is excluded and said
so, the FOLD column across the three ladders (if the fold moves, something
other than the window moved), and the EXCESS of each windowed crossover over
the resident one.

    waskred.py [--threads N] [--metric wall|cpu] <resident.log> <win2k.log> <win1k.log>

WALL OR CPU, AND WALL IS WHAT SETTLES A SHIPPING QUESTION (17 Sep 2026).
`--metric wall` reduces the same ladders on elapsed seconds instead of
core-seconds. The standing rule is the maintainer's, recorded as memory topic
`nzbfast-wall-time-is-the-deciding-metric`: where a CPU crossover and a wall
crossover disagree, the WALL one decides, and a result quoted only in CPU does
not answer a shipping question - it names this campaign as the place to watch
for it, because these crossovers are habitually stated as "N% of repair CPU".
CPU stays the DEFAULT here, deliberately, for two reasons: every banked figure
in the section this reduces is CPU, so changing the default would silently
restate them; and CPU is far more robust on a loaded box, which is the right
quantity for a mechanism study. Run BOTH and report both; if they disagree,
that divergence is a finding rather than noise to resolve quietly.

ONE POOL PER RUN, AND IT REFUSES RATHER THAN FUSING TWO. Every cell is a
median over the legs at a rung, and `wcomb.ps1 -Threads '4,12'` writes BOTH
pools' legs into one log - so a reducer that medians a rung without looking at
`threads=` returns a crossover belonging to neither pool, with nothing in the
output saying so. This one refuses a multi-pool log unless `--threads` names
which pool to read, and prints the pools it found. Caught 17 Sep 2026 by the
lane running the -t4 arm, which needed exactly that shape; the -t12 round this
was written for was single-pool, so the defect could not fire here and would
have fired there.

VALIDATED AGAINST A BANKED ROUND before this lane's own logs existed: run over
rounds/wcomb-k-2026-09-16/coreultra9-gfni256-1m-n8192-*.log it
reproduces that lane's published crossovers (357 resident, 370 at -m2048,
+13 rows of excess) to the row, and excludes its m = 512 rung on the shape
change that lane excluded it on by hand (windows 7 -> 6, win_slices 1040 ->
2080, slabs 1 -> 2).
"""
import math, os, re, statistics as st, subprocess, sys

# The four fields EVERY reduction in this chain reads off a leg: `int(x['m'])`
# in every rung set, `x['arm']` in `cell` and `shape`, and `float(x[metric])` in
# `cell` for metric in (wall, cpu). A leg that cannot answer all four is not a
# leg this reducer can use, whatever else it carries.
REDUCED_FIELDS = ('m', 'arm', 'wall', 'cpu')


def leg_fault(f):
    """Which of the reduced fields makes this leg unusable, or None if it is fine.

    A PARSER THAT SUCCEEDS AND RETURNS GARBAGE is the weaker sibling of
    CLAUDE.md's "failing to find is failing", and this chain met it on 18 Sep
    2026. `legs` splits on whitespace and keeps tokens containing '=', so the
    15 Sep EPYC guest round's older LEG grammar -

        LEG 64k-ladder-m96-big-fold-t4-r1  ok path=fold wall=   2.07 cpu=  10.50

    - parses into 204 legs of `{'wall': '', 'cpu': ''}` with no 'm' key at all.
    It does not fail. The first thing to TOUCH those legs raises, three
    functions downstream, and that round (the campaign's first class, and the
    round the shipped NTT_MIN_MISSING = 320 was kept on) very nearly went into
    a graded table as "not gradeable, no readable logs".

    THE CHECK IS ON THE FIELDS THE REDUCTION READS, NOT ON EVERY FIELD, and
    that is load-bearing: `gf16force=` is legitimately empty on every modern
    LEG line and `win_slices=none` is a string. Widening this to "no field may
    be empty" would refuse the whole modern corpus.

    Returns (field, why) or None.
    """
    for k in REDUCED_FIELDS:
        # `is None` as well as absent: the jsonl adapter builds its leg with
        # `d.get(...)`, so a field missing from the json line arrives here as a
        # None VALUE under a key that exists. Keying on presence alone would let
        # exactly the case that arm perturbs walk straight through.
        if k not in f or f[k] is None:
            return k, 'is missing from the leg'
        if str(f[k]).strip() == '':
            return k, 'parsed as the EMPTY STRING'
    try:
        int(str(f['m']))
    except ValueError:
        return 'm', 'does not parse as an integer (%r)' % (f['m'],)
    for k in ('wall', 'cpu'):
        try:
            v = float(str(f[k]))
        except ValueError:
            return k, 'does not parse as a float (%r)' % (f[k],)
        # float('nan') and float('inf') PARSE, and a cell medianed out of them
        # is a crossover that silently exists and means nothing - the same
        # succeeds-and-returns-garbage shape one level down.
        if not math.isfinite(v):
            return k, 'parses as a float but is not finite (%r)' % (f[k],)
    return None


def refuse_bad_leg(path, lineno, f):
    """Refuse BY NAME - file, line and field - rather than returning the garbage.

    REFUSE, NEVER REPAIR. Guessing `m` and the thread count out of a leg NAME is
    one dead harness's grammar; the rounds that wrote it also bank a `.jsonl`
    beside every log with every field typed, and `w3winred.read_legs` reads that.
    A parser for a format nothing will produce again would be a second place for
    two reductions of one campaign to drift apart, which is the mistake this
    whole chain exists to avoid.
    """
    fault = leg_fault(f)
    if fault is None:
        return
    field, why = fault
    jsonl = os.path.splitext(path)[0] + '.jsonl'
    sys.exit(
        f'{path}:{lineno}: LEG field {field!r} {why} - the reduction reads '
        f'{", ".join(REDUCED_FIELDS)} off every leg and this one cannot answer. '
        f'This is almost certainly a round in the OLD rowgate.py LEG grammar, '
        f'which keeps m and the thread count in the leg NAME and writes '
        f'"wall=   2.07" with a SPACE after the "=", so both fields parse empty. '
        f'Reduce that round from its .jsonl instead '
        f'({os.path.basename(jsonl)}{"" if os.path.exists(jsonl) else " - NOT beside this log; look for one in the round directory"}), '
        f'which carries every field typed: w3winred.read_legs takes either. '
        f'REFUSING RATHER THAN REPAIRING is deliberate - see leg_fault.')


def legs(path, threads=None):
    out = []
    for lineno, line in enumerate(open(path, errors='replace'), 1):
        # harness-rig-gate: a reducer over a banked round's LEG lines. It
        #   writes a table and no round log; the second LEG literal below is a
        #   selftest expectation over the same read.
        if not line.startswith('LEG '):
            continue
        f = dict(kv.split('=', 1) for kv in line.split() if '=' in kv)
        refuse_bad_leg(path, lineno, f)
        out.append(f)
    pools = sorted({x.get('threads') for x in out})
    if threads is not None:
        out = [x for x in out if x.get('threads') == str(threads)]
        if not out:
            sys.exit(f'{path}: no legs at threads={threads} (log has {pools})')
    elif len(pools) > 1:
        sys.exit(f'{path}: {len(pools)} thread counts in one log ({pools}) - pass '
                 f'--threads N to say which pool to read. Medianing a rung across '
                 f'pools returns a crossover belonging to neither.')
    return out

def cell(ls, m, arms, metric='cpu'):
    v = [float(x[metric]) for x in ls if int(x['m']) == m and x['arm'] in arms]
    return st.median(v) if v else None

def shape(ls, m):
    s = {(x.get('windows'), x.get('win_slices','').split('/')[0], x.get('slabs'))
         for x in ls if int(x['m']) == m and x['arm'].startswith('force')}
    return s

def crossing_state(rungs, fold, force):
    """Why a ladder has no crossover, which is NOT one condition but two.

    Added 17 Sep 2026, when reducing the banked -t12 round on `--metric wall`
    printed "NOT REACHED in shape" for the RESIDENT ladder - whose F/T is
    already 1.103 at its first rung, meaning the transform had won BEFORE the
    grid started - in the identical words it prints for the -m1024 CPU ladder,
    whose F/T is 0.724 at its TOP rung and still rising, meaning the fold was
    winning throughout. Those are opposite findings and the wording implied the
    second one in both cases. A ladder that crossed below its first rung bounds
    its crossover from ABOVE; one that never crossed bounds it from BELOW, and
    an excess computed from the wrong side has the wrong sign.

    Returns 'below_first' (force already winning at rung 1 - crossover is
    BELOW the grid), 'above_last' (fold still winning at the top - crossover is
    ABOVE the grid), or 'spans' (the grid brackets it).
    """
    usable = [m for m in rungs if fold.get(m) and force.get(m)]
    if not usable:
        return 'none'
    if fold[usable[0]] / force[usable[0]] >= 1.0:
        return 'below_first'
    if fold[usable[-1]] / force[usable[-1]] < 1.0:
        return 'above_last'
    return 'spans'


def crossover(rungs, fold, force):
    """log-interpolate F/T = 1 between the bracketing rungs, as rowgate.py does."""
    prev = None
    for m in rungs:
        if fold.get(m) is None or force.get(m) is None:
            continue
        r = fold[m] / force[m]
        if prev and prev[1] < 1.0 <= r:
            m0, r0 = prev
            t = (0 - math.log(r0)) / (math.log(r) - math.log(r0))
            return m0 + t * (m - m0)
        prev = (m, r)
    return None

# The round's published figures, pinned here so the reducer cannot drift away
# from the table it produced without saying so. Source: the "WINDOWED ASK on
# the NIBBLE class at 1 MiB" section of
# an internal note.
SELFTEST_LOGS = ('i5-nibble-1m-n8192-resident-ladder.log',
                 'i5-nibble-1m-n8192-windowed-m2048-ladder.log',
                 'i5-nibble-1m-n8192-windowed-m1024-ladder.log')
MULTIPOOL_LOG = '../wcomb-k-nibble-2026-09-16/i5-nibble-k-1m-n8192-m2048.log'


def selftest():
    """Reproduce the published table, and prove the multi-pool refusal refuses.

    Written 17 Sep 2026 after the -t4 lane verified all three arms of the
    pool-fusing fix BY HAND. A check run by hand exists once; this one runs
    every time. It pins four published figures and both exit codes, because a
    refusal that exited 0 would be the same silent-pass shape as the defect it
    replaces - that observation is the -t4 lane's and it is the reason the exit
    codes are asserted here rather than assumed.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    paths = [os.path.join(here, n) for n in SELFTEST_LOGS]
    bad = [p for p in paths if not os.path.exists(p)]
    if bad:
        # FAILING TO FIND IS FAILING: a selftest that cannot locate its logs is
        # reporting its own blindness, not a pass.
        sys.exit('waskred --selftest: banked log(s) missing: ' + ', '.join(bad))

    def measure(threads=None, metric='cpu'):
        # PINNED TO CPU: every figure this selftest asserts (255 / 387 / +132 /
        # >193) is a CPU crossover from the banked -t12 round, so the default
        # must stay CPU here or the assertions would silently change meaning.
        out = []
        for path in paths:
            ls = legs(path, threads)
            rungs = sorted({int(x['m']) for x in ls})
            fold = {m: cell(ls, m, ('fold', 'fold2'), metric) for m in rungs}
            force = {m: cell(ls, m, ('force', 'force2'), metric) for m in rungs}
            shapes = {m: shape(ls, m) for m in rungs}
            keep = [m for m in rungs if shapes[m] == shapes[rungs[0]]]
            out.append((rungs, keep, crossover(keep, fold, force)))
        return out

    fails = []
    for label, threads in (('no flag', None), ('--threads 12', 12)):
        (_, _, res), (_, _, w2k), (r1k, keep1k, w1k) = measure(threads)
        checks = [
            ('resident crossover 255', res is not None and round(res) == 255),
            ('-m2048 crossover 387', w2k is not None and round(w2k) == 387),
            ('excess +132 rows', res and w2k and round(w2k - res) == 132),
            ('-m1024 never crosses in shape', w1k is None),
            ('-m1024 m=512 excluded on its shape change', 512 in r1k and 512 not in keep1k),
            ('-m1024 bound > 193 rows', res and round(max(keep1k) - res) == 193),
        ]
        for name, ok in checks:
            if not ok:
                fails.append('%s (%s)' % (name, label))

    # The refusal, against a log that really does carry two pools, and its exit
    # code. `sys.executable` rather than `python3`, so the check runs under the
    # interpreter that is running it.
    mp = os.path.join(here, MULTIPOOL_LOG)
    if not os.path.exists(mp):
        fails.append('multi-pool log missing: %s' % mp)
    else:
        r = subprocess.run([sys.executable, os.path.abspath(__file__), mp, paths[1], paths[2]],
                           capture_output=True, text=True)
        if r.returncode != 1:
            fails.append('multi-pool refusal exited %d, want 1' % r.returncode)
        if 'thread counts in one log' not in (r.stdout + r.stderr):
            fails.append('multi-pool refusal did not name the defect')
        ok = subprocess.run([sys.executable, os.path.abspath(__file__)] + paths,
                            capture_output=True, text=True)
        if ok.returncode != 0:
            fails.append('a valid run exited %d, want 0' % ok.returncode)

    # THE LEG-FIELD REFUSAL (added 18 Sep 2026, item 2 of
    # an internal note). Three things are pinned and
    # all three are needed: that `leg_fault` names the RIGHT field for each way
    # a leg can be unusable, that the refusal fires END TO END on the real
    # 15 Sep EPYC guest log with exit 1 (the round that actually met this, and
    # the only banked instance of the old grammar), and - the arm that keeps the
    # check from being widened into uselessness - that it does NOT fire on the
    # empty and non-numeric fields modern LEG lines legitimately carry.
    good = {'m': '384', 'arm': 'fold', 'wall': '2.07', 'cpu': '10.50',
            'gf16force': '', 'win_slices': 'none', 'threads': '4'}
    if leg_fault(good) is not None:
        fails.append('leg_fault refuses a MODERN leg (gf16force= is empty and '
                     'win_slices=none is a string on every one of them): %r'
                     % (leg_fault(good),))
    for field in REDUCED_FIELDS:
        missing = {k: v for k, v in good.items() if k != field}
        got = leg_fault(missing)
        if not got or got[0] != field:
            fails.append('leg_fault did not name the MISSING field %r (got %r)'
                         % (field, got))
        empty = dict(good, **{field: ''})
        got = leg_fault(empty)
        if not got or got[0] != field:
            fails.append('leg_fault did not name the EMPTY field %r (got %r)'
                         % (field, got))
    for field in ('m', 'wall', 'cpu'):
        got = leg_fault(dict(good, **{field: 'ok'}))
        if not got or got[0] != field or 'parse' not in got[1]:
            fails.append('leg_fault did not name %r as unparseable (got %r)'
                         % (field, got))
    for field in ('wall', 'cpu'):
        for v in ('nan', 'inf'):
            got = leg_fault(dict(good, **{field: v}))
            if not got or got[0] != field or 'finite' not in got[1]:
                fails.append('leg_fault let %r=%s through - it PARSES as a float'
                             ' and medians into a meaningless cell (got %r)'
                             % (field, v, got))
    # The empty-string case is EXACTLY what the old grammar produces, and the
    # old grammar is banked: drive it rather than a fabricated stand-in.
    epyc = os.path.join(here, '..', 'rowgate-2026-09-15',
                        'epyc9354p-avx512-64k.log')
    if not os.path.exists(epyc):
        fails.append('leg-field arm: banked old-format log missing: %s' % epyc)
    else:
        r = subprocess.run([sys.executable, os.path.abspath(__file__),
                            epyc, paths[1], paths[2]],
                           capture_output=True, text=True)
        msg = r.stdout + r.stderr
        if r.returncode != 1:
            fails.append('the old-format log exited %d, want 1' % r.returncode)
        for want in ('epyc9354p-avx512-64k.log:18', 'LEG field', '.jsonl'):
            if want not in msg:
                fails.append('the leg-field refusal did not name %r: %r' % (want, msg[:400]))

    if fails:
        for f in fails:
            print('FAIL ' + f)
        sys.exit('waskred --selftest: %d check(s) failed' % len(fails))
    print('waskred --selftest: OK - 255 / 387 / +132 / bound >193 reproduce with '
          'and without --threads, m=512 excluded on its shape change, a '
          'multi-pool log is refused by name with exit 1, and a leg that cannot '
          'answer m/arm/wall/cpu is refused by file, line and field - fired end '
          'to end on the banked 15 Sep EPYC old-format log and silent on the '
          'empty gf16force= and win_slices=none every modern leg carries')


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == '--selftest':
        return selftest()
    threads = None
    metric = 'cpu'
    while len(argv) >= 2 and argv[0] in ('--threads', '--metric'):
        if argv[0] == '--threads':
            threads = int(argv[1])
        else:
            metric = argv[1]
            if metric not in ('wall', 'cpu'):
                sys.exit("--metric must be wall or cpu, not %r" % metric)
        argv = argv[2:]
    names = ['resident', '-m2048', '-m1024']
    tabs = []
    states = {}
    for path, name in zip(argv[:3], names):
        ls = legs(path, threads)
        rungs = sorted({int(x['m']) for x in ls})
        fold = {m: cell(ls, m, ('fold', 'fold2'), metric) for m in rungs}
        force = {m: cell(ls, m, ('force', 'force2'), metric) for m in rungs}
        shapes = {m: shape(ls, m) for m in rungs}
        base = shapes[rungs[0]]
        bad = [m for m in rungs if shapes[m] != base]
        keep = [m for m in rungs if m not in bad]
        pool = sorted({x.get('threads') for x in ls})
        print(f'== {name} ({path})  legs={len(ls)}  threads={",".join(pool)}  metric={metric}  base shape={base}')
        for m in rungs:
            mark = '  EXCLUDED shape=' + str(shapes[m]) if m in bad else ''
            ft = fold[m] / force[m] if fold[m] and force[m] else float('nan')
            print(f'   m={m:5d} fold={fold[m]:8.2f} force={force[m]:8.2f} F/T={ft:6.3f}{mark}')
        x = crossover(keep, fold, force)
        st_ = crossing_state(keep, fold, force)
        if x:
            note = f'{x:.0f}'
        elif st_ == 'below_first':
            note = (f'BELOW THE GRID - F/T is already >=1 at the first in-shape rung '
                    f'(m={keep[0]}), so the transform had won before this ladder started. '
                    f'Crossover < {keep[0]}; re-run with lower rungs to locate it.')
        elif st_ == 'above_last':
            note = (f'ABOVE THE GRID - the fold is still winning at the top in-shape rung '
                    f'(m={keep[-1]}). Crossover > {keep[-1]}.')
        else:
            note = 'NO USABLE RUNGS'
        print(f'   crossover (in-shape rungs {keep}): ' + note)
        states[name] = st_
        tabs.append((name, rungs, fold, force, keep, x))
    print()
    print(f'== fold across the three ladders, {metric} (the control: it must not move)')
    allr = sorted(set(tabs[0][1]) & set(tabs[1][1]) & set(tabs[2][1]))
    for m in allr:
        vs = [t[2].get(m) for t in tabs]
        if all(vs):
            sp = (max(vs) - min(vs)) / min(vs) * 100
            print(f'   m={m:5d} ' + ' '.join(f'{v:8.2f}' for v in vs) + f'   spread {sp:4.1f}%')
    print()
    print(f'== the measured ask, in {metric}'
          + ('   <- WALL DECIDES a shipping question (nzbfast-wall-time-is-the-deciding-metric)'
             if metric == 'wall' else ''))
    res = tabs[0][5]
    rkeep = tabs[0][4]
    rstate = states.get('resident')
    if res is None and rstate == 'below_first':
        # The resident crossover is bounded from ABOVE, so every excess taken
        # against it is bounded from BELOW - and the bound is only as good as
        # the first rung. Say so rather than printing a number.
        print(f'   resident: crossover is BELOW m={rkeep[0]} and is NOT located, so every'
              f' excess below is a LOWER BOUND taken against m={rkeep[0]}, not a reading.')
        for name, _, _, _, keep, x in tabs[1:]:
            if x:
                print(f'   {name}: crossover {x:.0f}, excess over resident > {x - rkeep[0]:+.0f} rows (LOWER BOUND)')
            else:
                print(f'   {name}: no crossover in shape either; nothing can be said about the excess')
    elif res is not None:
        for name, _, _, _, keep, x in tabs[1:]:
            if x:
                print(f'   {name}: crossover {x:.0f}, excess over resident {x - res:+.0f} rows')
            elif states.get(name) == 'above_last':
                print(f'   {name}: never crossed in shape up to m={max(keep)}; '
                      f'excess > {max(keep) - res:.0f} rows (LOWER BOUND)')
            else:
                print(f'   {name}: crossover is BELOW m={min(keep)}; excess < {min(keep) - res:+.0f} rows (UPPER BOUND)')
    else:
        print('   resident ladder has no crossover and no usable state; no excess can be computed')


# GUARDED so this file can be IMPORTED, not only run. Unguarded, `main()` fired
# on import and died in the fold-control block before a caller could reach a
# single function - which is not hypothetical: the -t4 lane needed these exact
# functions to reduce one ladder at a time (a resident ladder alone has no
# win2k/win1k to pair with) and had to strip this line with a regex to get at
# them. A reducer whose arithmetic cannot be reused is a reducer every next
# round reimplements, which is how two rounds stop being comparable.
if __name__ == '__main__':
    main()
