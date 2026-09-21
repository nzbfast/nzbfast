#!/usr/bin/env python3
"""Sequential round runner for the Mac rigs.

Waits on the per-box rig lock AND on any of our tool binaries being up - a lock
only excludes rounds that agreed to take it, and on 11 Sep 2026 a round that
took none at all let a second round start a 23 GiB create beside a running
repair. Then runs each round in turn, one at a time, each to its own log.

It waits on the LOCK, never on a marker line in another round's log: a log
renamed when it is banked silently disarms every round waiting on it.

And it waits on the lock's HOLDER, never on the lock file's existence - see
lock_hold() below and riglock_state.py, which is the one place this fleet
decides what "held" means.

SINCE 18 Sep 2026 IT ALSO READS THE BOX'S COORDINATION FILE, and until that
day NOTHING ON THE UNIX SIDE DID. Censused across `harness/*.py` on
main that day: `riglock_state.coordination_file()` was called from exactly one
place, `announce_orphan`, to POST a note; `cstripe-mac.py` opens its `COORD=`
file `"a"`; no unix driver read one to decide a take. So a lane holding this
box by an open CLAIM in prose - having not yet taken the flock, which is the
two-minute gap between staging a round and acquiring - was invisible to every
unix round on the fleet. The Windows side got its reader on 18 Sep
(`plib.ps1`'s `Get-OpenClaimants`); this is the same half, and the two
platforms were missing OPPOSITE halves, because unix already has the one
Windows lacked: `riglock.take()` is a real blocking queued flock, so its
acquire IS its probe and there is no gap inside it. Nothing was built there
and nothing needed to be
(an internal note section 1).

IT IS THE QUEUE'S GATE THAT NEEDED THIS, not the round's take. `main()` below
breaks out of the `busy()` loop and THEN spawns a round as a subprocess, so
this file - alone on the unix side - is probe-then-act, which is the shape
both dated instances of the incident happened in.

AND THE READER IS CALLED, NEVER RE-WRITTEN. `tools/bench-box-gate.py` is the
fleet's tested may-I-take-this-box gate: it imports the marker vocabulary from
`.claude/tools/bench-accounts-parse.py` (95 markers classified by reading
7,036 real lines, so `QUEUED` opens no hold and an UNCLASSIFIED marker opens
one), folds per lane, and carries the stale and phantom tiers a straight fold
does not. A second copy here would be the fourth spelling of a rule this repo
has already paid for twice.
"""
import os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pdrv
import riglock_state

LOCK = os.path.expanduser("~/.parfast-rig.lock")
# CORROBORATION ONLY since 18 Sep 2026 - see census() below. This was the
# WHOLE non-lock arm, and four names is the `parfast|cargo|rustc` defect of
# the Windows incident with one more name: an ISCC compile is none of them and
# the box read free through 90 seconds of it. `cargo` and `rustc` are here now
# because these boxes certainly run them, but the point of the fix is that NO
# NAME LIST CAN BE COMPLETE, so the list is no longer what decides.
TOOLS = ("parfast", "par2turbo", "par2j", "par2", "cargo", "rustc")

# THE CPU DIAL, AND THE PREDICATE IT IS APPLIED TO. Per-process CPU over a
# sampling window, as a percentage of ONE core, for every process outside our
# own tree - but the dial is compared against the sum of the HEAVY processes
# only, those at `CPU_HEAVY_PCT` or more each, NOT against the total.
#
# THAT DISTINCTION IS MEASURED, and the naive total was written first and was
# wrong. On the dev Mac, 18 Sep 2026:
#
#   an interactive desktop, no round        total 310%   heavy   0%   (FREE)
#     (WindowServer 40%, three Chrome helpers 19-20%, fseventsd 17%)
#   the same box under another lane's
#     `cargo nextest` test binaries         total 596%   heavy 335%   (BUSY)
#   ...and with four saturating spinners
#     added on top                          total 1019%  heavy 645%   (BUSY)
#
# A TOTAL-BASED DIAL CALLS THE FIRST ROW BUSY, which would wedge this queue for
# 24 hours on any box somebody is also sitting at - a wrong "busy" is bounded
# and loud where a wrong "free" is neither, but a gate that is wrong on an idle
# desktop is a gate that gets disabled. Desktop noise is MANY processes at
# 17-40%; real work is a FEW at 60-100%+ each, because that is what saturating
# a thread looks like. Heavy-sum separates them with a wide margin in both
# directions and reports the total either way.
#
# 150 is "a core and a half of genuinely saturated work". Set `CPU_BUSY_PCT` to
# 0 to disable the arm - the reading is still REPORTED, which is the half that
# made the Windows incident re-readable afterwards.
CPU_BUSY_PCT = float(os.environ.get("MQUEUE_CPU_BUSY_PCT", "150"))
CPU_HEAVY_PCT = float(os.environ.get("MQUEUE_CPU_HEAVY_PCT", "50"))
CPU_SAMPLE_S = float(os.environ.get("MQUEUE_CPU_SAMPLE_S", "3"))


def lock_hold(path=LOCK, announce=True):
    """The lock half of busy(): a string when the lock is really held, else None.

    This WAS `if os.path.exists(LOCK): return "lock " + LOCK` - existence as
    the hold - and on 16 Sep 2026 that held apple-m3-ultra for eight hours against a
    zero-byte file eight hours cold with no holder anywhere on the box, which
    two lanes each had to disprove by hand. Existence is not a hold; a live
    holder is. riglock_state answers that off the holder's pid and never off
    the file's age, because a legitimate round can own this box for hours and
    any age bound that clears the orphan would steal from one of those.

    It never UNLINKS the orphan. This process does not take the lock - the
    round it launches does, through pdrv.RigLock, which clears the file it
    proved dead while holding the flock on it. Deleting from here would be a
    second, unlocked deleter of a file we never held, which is the shape of
    the 15 Sep double-holder incident. Announcing is ours; removing is the
    taker's.
    """
    state, who = riglock_state.lock_state(path)
    if state == "held":
        return "lock %s held by: %s" % (path, who)
    if state == "orphan" and announce:
        riglock_state.announce_orphan(path, who, "ignored by mqueue (not removed - the round clears it)")
    return None


# --- the coordination file: somebody else's OPEN CLAIM ---------------------
#
# WHERE THE GATE IS LOOKED FOR, and why a miss is not fatal. Only
# `harness/` and `the bench rig library` are deployed to a rig box
# (`tools/bench-deploy-check.py`'s two ROLES), flat, against `~/pubrun` or
# `<rig>` - so `tools/bench-box-gate.py` is NOT on a rig box unless somebody
# put it there, and a path relative to this file finds it only in a repo
# checkout. Hence a short search with an env override at the front.
#
# AND WHEN IT IS NOT FOUND THIS QUEUE STILL RUNS, LOUDLY. That is the one
# place here that departs from "failing to find is failing", and it is a
# deliberate, narrow exception rather than an oversight. Blocking would be the
# usual answer, but this arm is NEW on a path where the answer today is
# already "nobody reads the coordination file at all": refusing to start would
# convert a fleet-wide blind spot into a fleet-wide 24-hour WEDGE on every box
# whose deploy predates this change, which is a far larger failure than the one
# being fixed and would land on boxes this lane cannot test. So an unresolved
# gate prints MQUEUE-COORD-BLIND and proceeds - strictly better than the
# silence it replaces, and it converges the moment the gate is on a box.
# A file that EXISTS AND CANNOT BE READ is the opposite case and DOES block:
# see coord_hold().
GATE_CANDIDATES = (
    os.environ.get("MQUEUE_BOX_GATE"),
    os.path.join(HERE, "bench-box-gate.py"),
    os.path.join(HERE, "..", "..", "tools", "bench-box-gate.py"),
    os.path.expanduser("~/pubrun/bench-box-gate.py"),
    os.path.expanduser("~/Claude/nzbfast/tools/bench-box-gate.py"),
)


def _box_gate():
    """`tools/bench-box-gate.py` as a module, or None when this box has no copy.

    Imported by path because the filename carries hyphens - the same
    `importlib` route that file itself uses to reach the marker roster.
    """
    import importlib.util
    for cand in GATE_CANDIDATES:
        if not cand or not os.path.exists(cand):
            continue
        try:
            spec = importlib.util.spec_from_file_location("_mq_box_gate", cand)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception as exc:                      # noqa: BLE001 - report, never die
            print("MQUEUE-COORD-BLIND %s would not load: %s" % (cand, exc), flush=True)
            return None
        for attr in ("parse_events", "fold", "read_coord"):
            if not hasattr(mod, attr):
                print("MQUEUE-COORD-BLIND %s no longer exports %s - repoint this, "
                      "do not write a second reader" % (cand, attr), flush=True)
                return None
        return mod
    return None


def coord_hold(coord=None, me=None):
    """Another lane's OPEN marker on this box's coordination file, or None.

    THE POLARITY IS THE WHOLE THING. A missed CLOSE costs this queue a wait,
    which the 24h cap bounds and the MQUEUE-WAIT line makes visible. A missed
    OPEN costs somebody their round, and there is no bound on that and nothing
    afterwards can tell you it happened. So every uncertainty here resolves to
    "the box is held":

      - AN UNREADABLE FILE IS NOT AN EMPTY ONE. "no open claim" reads as TAKE
        THE BOX, and the usual "a failed read is None" convention would turn a
        permissions error into a green light. It comes back as a hold naming
        the path, the same decision `Get-OpenClaimants` records on the Windows
        side as its `(unreadable:<path>)` pseudo-id.
      - AN UNCLASSIFIED MARKER IS A HOLD. That is the gate's own rule
        (decision A there) and it is inherited rather than re-decided.
      - A STALE HOLD IS STILL A HOLD HERE. bench-box-gate REFUSES on one,
        because a lane running it can act; this queue has nobody to ask, so it
        waits and NAMES it, which is what puts it in the log for whoever reads
        the round afterwards.

    A PHANTOM does not block - the gate has proved the box turned over since -
    and is reported for the same reason.

    NO AGE BOUND IS ADDED HERE and none may be. The staleness tiers are the
    gate's, measured over 174 real spans; `riglock_state.py`'s docstring refuses
    an age bound on the LOCK in capitals and the reasoning carries over
    unchanged: liveness comes from the holder, never from the clock.
    """
    gate = _box_gate()
    if gate is None:
        print("MQUEUE-COORD-BLIND no bench-box-gate.py on this box (tried %s) - "
              "NOBODY'S OPEN CLAIM WAS READ. Deploy it or set $MQUEUE_BOX_GATE."
              % ", ".join(c for c in GATE_CANDIDATES if c), flush=True)
        return None
    if coord is None:
        coord = riglock_state.coordination_file()
    if not coord:
        print("MQUEUE-COORD-NONE this box has no unambiguous "
              "~/bench-out/COORDINATION-*.txt (and no $BOXGATE_COORD), so no open "
              "claim was read. Set $BOXGATE_COORD to name one.", flush=True)
        return None
    if me is None:
        me = os.environ.get("BOXGATE_ID") or ""
    try:
        text = gate.read_coord(coord)
    except SystemExit:
        # read_coord's own refusal: the file is not there at all. A box whose
        # coordination file is MISSING is a box nobody has claimed on, which is
        # different from one we cannot read - so this is reported, not a hold.
        print("MQUEUE-COORD-NONE %s does not exist - no open claim was read."
              % coord, flush=True)
        return None
    except OSError as exc:
        return ("coordination file %s EXISTS AND CANNOT BE READ (%s) - that is "
                "not an empty file, and an empty one would read as TAKE THE BOX"
                % (coord, exc))
    holds = gate.fold(gate.parse_events(text))
    blocking, phantoms = [], []
    for lane, h in sorted(holds.items()):
        if me and lane == me:
            continue
        if h.phantom:
            phantoms.append("%s (%s, overtaken by %s)" % (lane, h.event.marker, h.superseded_by))
            continue
        note = "%s %s %s (%.1fh)" % (lane, h.event.marker, gate.stamp(h.event.ts), h.age_s / 3600.0)
        if h.unknown_marker:
            note += " [MARKER NOBODY HAS CLASSIFIED - classify it in the roster]"
        if h.unresolved:
            note += (" [STALE, nothing has overtaken it - somebody owes a "
                     "`DONE <ts> <you> FOR %s's ROUND`]" % lane)
        blocking.append(note)
    if phantoms:
        print("MQUEUE-COORD-PHANTOM %s - reported, blocking nothing"
              % "; ".join(phantoms), flush=True)
    if blocking:
        return "coordination %s: open claim(s) %s" % (coord, "; ".join(blocking))
    print("MQUEUE-COORD-CLEAR %s: %d marker line(s), no open claim but mine"
          % (coord, len(gate.parse_events(text))), flush=True)
    return None


# --- the process census: CPU first, the name list as corroboration ---------


def _ps_rows():
    """(pid, ppid, cpu_seconds, comm) for every process, or None if ps failed."""
    out = subprocess.run(["ps", "-Ao", "pid=,ppid=,time=,comm="],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return None
    rows = []
    for line in out.stdout.splitlines():
        f = line.split(None, 3)
        if len(f) < 4:
            continue
        try:
            pid, ppid = int(f[0]), int(f[1])
        except ValueError:
            continue
        # `[[DD-]HH:]MM:SS[.ss]` - the cumulative CPU time ps reports.
        t, secs, mult = f[2], 0.0, 1.0
        if "-" in t:
            days, _, t = t.partition("-")
            try:
                secs += float(days) * 86400.0
            except ValueError:
                continue
        try:
            for part in reversed(t.split(":")):
                secs += float(part) * mult
                mult *= 60.0
        except ValueError:
            continue
        rows.append((pid, ppid, secs, os.path.basename(f[3].strip())))
    return rows


def _own_tree(rows, self_pid):
    """Our own pid, its ancestors and its descendants - the set to exclude.

    Both directions. Descendants because a round's children are ours; ancestors
    because the shell or `detachq.py` that launched this queue is not a foreign
    lane. Nothing here is near the CPU dial anyway; excluding them is about the
    reading being HONEST rather than about the verdict.
    """
    parent = {pid: ppid for pid, ppid, _s, _c in rows}
    mine = {self_pid}
    p = parent.get(self_pid)
    seen = 0
    while p and p > 1 and p not in mine and seen < 64:
        mine.add(p)
        p = parent.get(p)
        seen += 1
    changed = True
    while changed:
        changed = False
        for pid, ppid, _s, _c in rows:
            if ppid in mine and pid not in mine:
                mine.add(pid)
                changed = True
    return mine


def census(sample_s=None):
    """What is running on this box, as a (verdict, reading) pair.

    `verdict` is a string when the box is busy and None when it is not;
    `reading` is ALWAYS a sentence, and the caller ALWAYS prints it. That is
    the half the Windows incident turned on: the figure that would have made
    the 13:26Z probe re-readable afterwards was the one taken when it said
    FREE, and nobody had it.

    THE PRIMARY ARM IS PER-PROCESS CPU ATTRIBUTION AND THE NAME LIST IS
    CORROBORATION, which is the fix's whole shape. A name list cannot be
    complete - the box read genuinely free through 90 seconds of an ISCC
    compile because `parfast|cargo|rustc` does not name Inno Setup - so the
    deciding arm has to be "is this box DOING anything", not "do I recognise
    it". Unix makes that easier than Windows did: two samples of ps's
    cumulative CPU time, differenced over the window, is a real CPU share over
    a known interval and needs no /proc and no privileged call. `ps`'s own
    `pcpu` column is NOT used - on macOS it is a lifetime average, so a process
    that burned a core for an hour and is now idle reads high, and one that
    started 20 seconds ago reads low.

    The HEAVY subset is what the dial is compared against; see CPU_BUSY_PCT
    above for the measurement that forced that and for what the naive total
    would have done to an interactive box.

    A BOX WE CANNOT LOOK AT IS NEVER A CLEAR BOX: `ps` failing is a hold.
    """
    sample_s = CPU_SAMPLE_S if sample_s is None else sample_s
    first = _ps_rows()
    if first is None:
        return ("census BLIND: `ps` failed on this box, which is never the same "
                "as a clear box"), "census BLIND (ps failed)"
    t0 = time.monotonic()
    time.sleep(max(0.0, sample_s))
    second = _ps_rows()
    if second is None:
        return ("census BLIND: `ps` failed on the second sample"), "census BLIND (ps failed)"
    return attribute(first, second, max(1e-6, time.monotonic() - t0))


def attribute(first, second, elapsed, self_pid=None):
    """The arithmetic half of census(), split out so it can be TESTED.

    Two `_ps_rows()` samples and the seconds between them in; the same
    (verdict, reading) pair out. Separate from the sampling because a test that
    has to sleep to reach the arithmetic measures the sleep, and one that does
    not sleep divides by zero - `rig_lock_selftest.py` drives canned samples
    through here with a known `elapsed` and needs neither.
    """
    mine = _own_tree(second, os.getpid() if self_pid is None else self_pid)
    was = {pid: secs for pid, _pp, secs, _c in first}
    foreign, total = [], 0.0
    for pid, _ppid, secs, comm in second:
        if pid in mine or pid not in was:
            continue
        pct = (secs - was[pid]) / elapsed * 100.0
        if pct >= 1.0:
            foreign.append((pct, pid, comm))
            total += pct
    foreign.sort(reverse=True)
    heavy = [x for x in foreign if x[0] >= CPU_HEAVY_PCT]
    heavy_total = sum(v for v, _p, _c in heavy)
    top = ", ".join("%s pid=%d %.0f%%" % (c, p, v) for v, p, c in foreign[:5]) or "nothing above 1%"
    reading = ("census over %.1fs: foreign CPU %.0f%% of one core across %d process(es), "
               "of which %.0f%% in %d process(es) at >=%.0f%% each [%s]"
               % (elapsed, total, len(foreign), heavy_total, len(heavy), CPU_HEAVY_PCT, top))

    # The name list, CPU-burning members first: a `parfast` at 700% is the
    # interesting one, and a `cargo` that is merely resident still counts.
    named = [(pid, comm) for _v, pid, comm in foreign if comm in TOOLS]
    seen = {pid for pid, _c in named}
    named += [(pid, comm) for pid, _ppid, _secs, comm in second
              if comm in TOOLS and pid not in mine and pid not in seen]
    if named:
        reading += "; name list corroborates: " + ", ".join(
            "%s pid=%d" % (c, p) for p, c in named[:5])
        return "tool %s pid=%d (%s)" % (named[0][1], named[0][0], reading), reading
    if CPU_BUSY_PCT > 0 and heavy_total >= CPU_BUSY_PCT:
        return ("busy: %s - the heavy figure is over the %.0f%% dial "
                "($MQUEUE_CPU_BUSY_PCT), and NO NAME IN %s EXPLAINS IT, which is "
                "exactly the case a name list cannot see"
                % (reading, CPU_BUSY_PCT, "/".join(TOOLS))), reading
    return None, reading


def busy():
    """Is this box somebody else's right now? A string saying so, or None.

    THE ORDER IS THE HOLD RULE FIRST AND IT IS UNCHANGED: `lock_hold()` asks
    `riglock_state`, which is the one place this fleet decides what held means,
    and it is the cheapest and most certain of the three. Then the coordination
    file, then the box itself.
    """
    held = lock_hold()
    if held:
        return held
    held = coord_hold()
    if held:
        return held
    verdict, reading = census()
    print("MQUEUE-CENSUS %s" % reading, flush=True)
    return verdict


def main():
    rounds = sys.argv[1:]
    print("MQUEUE-START %s rounds=%s" % (pdrv.utcnow(), ",".join(rounds)), flush=True)
    waited = 0
    while True:
        held = busy()
        if not held:
            break
        if waited % 600 == 0:
            print("MQUEUE-WAIT held by %s (%dm)" % (held, waited // 60), flush=True)
        time.sleep(60)
        waited += 60
        if waited > 86400:
            print("MQUEUE-TIMEOUT %s still held after 24h" % held, flush=True)
            return 19
    # RESOLVE EVERY NAME BEFORE RUNNING ANYTHING, and FAIL if one does not
    # resolve. This check used to sit inside the loop, printing MQUEUE-MISSING,
    # continuing, and returning 0 - so a queue whose rounds were all misnamed
    # produced START / MISSING / DONE and exited zero, which reads exactly like
    # a queue that finished its work. That is the same shape that cost the
    # Windows queue a night when `-rounds a,b` bound one element named "a,b",
    # and it happened again on 11 Sep 2026 when a round was launched as
    # `mred.py` and the queue looked for `mred.py.py`.
    #
    # Up front rather than in the loop, because a typo in the THIRD round is
    # otherwise discovered after the first two have run for six hours, at which
    # point the box is free and nobody is watching.
    missing = [r for r in rounds if not os.path.exists(os.path.join(HERE, r + ".py"))]
    if missing:
        for r in missing:
            print("MQUEUE-MISSING %s" % os.path.join(HERE, r + ".py"), flush=True)
        print("MQUEUE-FAIL %d of %d round name(s) do not resolve: %s - NOTHING RAN"
              % (len(missing), len(rounds), ",".join(missing)), flush=True)
        print("MQUEUE-HINT rounds are named WITHOUT the .py suffix: `detach.py mred`, not `detach.py mred.py`",
              flush=True)
        return 21
    for r in rounds:
        script = os.path.join(HERE, r + ".py")
        log = os.path.join(HERE, r + ".log")
        print("MQUEUE-BEGIN %s %s" % (r, pdrv.utcnow()), flush=True)
        with open(log, "w") as fh:
            rc = subprocess.call([sys.executable, script], stdout=fh, stderr=subprocess.STDOUT)
        print("MQUEUE-END %s rc=%d %s" % (r, rc, pdrv.utcnow()), flush=True)
    print("MQUEUE-DONE %s" % pdrv.utcnow(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
