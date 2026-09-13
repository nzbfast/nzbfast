#!/usr/bin/env python3
"""Generate the parfast GUI acceptance corpus: nine damaged PAR2 sets with a measured verdict each.

The two parfast GUI apps (`apps/parfast/mac`, `apps/parfast/windows`) are
graded against ONE set of scenarios, and this script is where those
scenarios come from. Plan section 7 of
`research/PLAN-PARFAST-GUI-2026-09-12.md` names them: clean; one damaged
file; one missing; one misnamed; one moved to a sibling folder;
unrepairable; unicode names; a ten thousand block set; and a
multi-volume set with gaps in its volume numbering. Every UI state in
plan section 5.2 is reachable from one of the nine, which is the point:
a screenshot pass over this corpus is a screenshot pass over the
product.

    make-corpus.py OUTDIR [--source DIR] [--scenarios a,b] [--force]
    make-corpus.py --check OUTDIR
    make-corpus.py --list
    make-corpus.py --selftest

WHY THE VERDICT IS MEASURED AND NOT DECLARED. A fixture whose expected
answer was typed by hand is a fixture that tests the typist. Each
scenario below declares what it is FOR and what the UI must end up
showing; the numbers underneath it - block size, source blocks, blocks
available, recovery blocks, the per-file census, the exit code - are
read back out of `parfast v` after the damage is applied, and a
scenario whose measured verdict disagrees with its declared intent is a
GENERATION FAILURE that refuses rather than a fixture that quietly
ships with the wrong answer in it. That is also why the recovery
percentages differ per scenario and look unprincipled: they are chosen
so that the intended verdict is the one the arithmetic actually gives,
and the refusal is what holds them honest when the engine's block
accounting moves.

WHY THE REPAIR IS PROBED ON A COPY. `ui.repair` says what the app must
be able to do, so it is measured too: the scenario directory is copied
aside, `parfast r` runs in the copy, the copy is re-verified, and the
copy is deleted. Running the repair in place would hand the QA lane a
corpus that is already repaired, which is the exact failure `--check`
exists to catch. `--no-repair-probe` skips it when only the shapes are
wanted.

WHY `--check` EXISTS AT ALL. These scenarios are DAMAGED sets, and the
first thing anyone does with a damaged set is repair it. A corpus that
has been driven through one app is no longer the corpus the second app
is supposed to face, and a repaired scenario reads as a clean one with
no diagnostic whatsoever - it verifies, it is green, the screenshot
looks right and proves nothing. So every generated file is recorded
with its sha256 and `--check` refuses a corpus that has moved. Run it
before each app's pass, not only at the start of the day.

    `--check` IS MAC-SIDE ONLY IN PRACTICE, and that is a stated limit
    rather than an oversight: the Windows build box carries no Python
    (which is also why this script is stdlib-only and the corpus is
    generated here and copied there). Check before the copy out and
    after the copy back; between those two moments the Windows pass is
    covered by the app's own behaviour and by the operator, not by this
    script.

WHAT THIS SCRIPT IS NOT. It is not a gate: it reddens no push, it is in
no CI roster, and nothing runs it unattended. It is a fixture builder
whose output is read by people and by two apps. The house rules it does
follow, because they are what make a fixture trustworthy, are the ones
about refusing rather than guessing: every anchor it parses out of
`parfast v` must be present or the run fails naming the missing line,
and a scenario that cannot be built is never written half way.

THE SOURCE FOLDER IS OPTIONAL, and the default is not a convenience. A
corpus built from synthetic bytes is reproducible on any box: the same
seed gives the same files, so two operators comparing two runs are
comparing the same thing. `--source DIR` takes real files instead
(the plan's "from any input folder"), which is what you want when the
question is how the UI handles real names, real sizes and a real folder
tree. The scenarios that need a particular shape - the ten thousand
block set, the unicode names - always synthesise, and say so below.

    NOTHING UNDER `--source` IS EVER WRITTEN TO. Files are copied into
    the output directory and damaged there. The corpus is damage; the
    input folder is somebody's data.

    A `--source` run CAN refuse, and the refusal is the feature. The
    recovery percentages are sized against the synthetic file shape, so
    a source folder whose first four files are wildly lopsided can turn
    an intended unrepairable into a repairable one; the generator says
    which scenario and what it measured, and the answer is a different
    source folder rather than a fixture quietly carrying the wrong
    verdict. Measured 12 Sep 2026: all nine intents hold on the
    synthetic payload, and on `web/` as a source the five common-set
    scenarios hold too.

SIZE ON DISK: about 85 MB for all nine, 45 MB of which is the ten
thousand block set (ten thousand 4 KiB blocks is 41 MB of payload, and
the block count is the point of the scenario, so it cannot be shrunk by
shrinking the blocks without dropping below the map's merge threshold).
`--scenarios` builds a subset when that matters.
"""

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
import zlib
from pathlib import Path

SCHEMA = 1
KIB = 1024
MIB = 1024 * 1024

# ---------------------------------------------------------------------
# The scenario table.
#
# Each entry is the whole definition of one scenario: the payload it
# needs, the create switches, the damage, and the UI claim it exists to
# support. `intent` is the verdict the generator REFUSES to disagree
# with (see the header). `ui` is what the two apps are graded against
# and is copied verbatim into expected.json.
#
# `payload` is one of:
#   "common"   the four file set below, synthesised or taken from --source
#   "unicode"  four files whose names are not ASCII, always synthesised
#   "big"      one file sized to a named block count, always synthesised
#
# Sizes are in blocks of the scenario's own block size, so the intent is
# readable without arithmetic: with a 64 KiB block the common set is
# 16 + 32 + 8 + 24 = 80 source blocks.
# ---------------------------------------------------------------------

COMMON_FILES = [
    ("alpha.bin", 16 * 64 * KIB),
    ("bravo.bin", 32 * 64 * KIB),
    ("charlie.bin", 8 * 64 * KIB),
    ("delta.bin", 24 * 64 * KIB),
]

UNICODE_FILES = [
    ("Ünïcôde tëst.bin", 16 * 64 * KIB),
    ("日本語のファイル.bin", 8 * 64 * KIB),
    ("naïve café.bin", 12 * 64 * KIB),
    ("Привет мир.bin", 4 * 64 * KIB),
]

SCENARIOS = [
    {
        "name": "clean",
        "payload": "common",
        "create": ["-s65536", "-r10"],
        "damage": [],
        "intent": "complete",
        "purpose": "an intact set: the green verdict, an all present block map, "
                   "and the one state where the Repair button must be disabled",
        "ui": {
            "verdict": "complete",
            "status_pill": "Complete - no repair needed",
            "block_states_present": ["present"],
            "repair_button": "disabled",
            "notes": [
                "The file table shows every row Complete and the Problems "
                "filter shows an empty table with its own empty state.",
            ],
        },
    },
    {
        "name": "damaged",
        "payload": "common",
        "create": ["-s65536", "-r10"],
        "damage": [("corrupt", "bravo.bin", 3)],
        "intent": "repairable",
        "purpose": "one damaged file: the amber verdict and a block map carrying "
                   "a short run of damaged cells inside a present one",
        "ui": {
            "verdict": "repairable",
            "status_pill": "Repairable",
            "block_states_present": ["present", "damaged"],
            "repair_button": "enabled",
            "notes": [
                "The damaged run is contiguous and sits inside one file, so the "
                "block map hover must name a block range and a file.",
                "The post repair summary card names one file repaired.",
            ],
        },
    },
    {
        "name": "missing",
        "payload": "common",
        "create": ["-s65536", "-r20"],
        "damage": [("delete", "charlie.bin", 0)],
        "intent": "repairable",
        "purpose": "one missing file: the Missing row state and a solid run of "
                   "missing cells, still repairable",
        "ui": {
            "verdict": "repairable",
            "status_pill": "Repairable",
            "block_states_present": ["present", "missing"],
            "repair_button": "enabled",
            "notes": [
                "Missing and damaged are different colours and different words. "
                "A UI that shows this scenario the same as `damaged` has failed it.",
            ],
        },
    },
    {
        "name": "misnamed",
        "payload": "common",
        "create": ["-s65536", "-r20"],
        "damage": [("rename", "charlie.bin", "IMG_4417.dat")],
        "intent": "repairable",
        "purpose": "one file renamed in place: the Misnamed row state, the found as "
                   "column, and the rename to expected name row action",
        "ui": {
            "verdict": "repairable",
            "status_pill": "Repairable",
            "block_states_present": ["present", "misnamed"],
            "repair_button": "enabled",
            "notes": [
                "The renamed file is still in the folder, so the engine can adopt "
                "its blocks. The app must show the row as Misnamed with found as "
                "IMG_4417.dat and NOT as plain Missing.",
                "This is the whole file rename mechanism, not block adoption from "
                "an unrelated file. The two are distinct in the engine and the "
                "survey model keeps them distinct.",
                "THE TWO VOCABULARIES DIFFER HERE AND THAT IS NOT A DEFECT. "
                "cli.files_missing below reads 1, because the reference tool "
                "calls a member whose name is not on disk MISSING. The engine's "
                "survey calls the same member MISNAMED and carries found_as. "
                "Both describe the same disk and both spend the same 8 recovery "
                "blocks, so cli.blocks_owed and the verdict agree; only the word "
                "differs. Grade the APP against this ui block, never against "
                "cli.files_missing, which is recorded as what the reference tool "
                "says and not as what the GUI should show.",
                "This field listed all three states until 12 Sep 2026, which was "
                "a hedge rather than an expectation: an assertion that accepts "
                "either route cannot fail, and the whole purpose of this "
                "scenario is that the misnamed state is DISTINCT from missing. "
                "Chip B's app drew [present, misnamed], matching the survey, and "
                "was graded against a field that would have accepted either.",
            ],
        },
    },
    {
        "name": "moved",
        "payload": "common",
        "create": ["-s65536", "-r10"],
        "damage": [("move", "delta.bin", "elsewhere")],
        "intent": "unrepairable",
        "purpose": "one file moved to a sibling folder: unrepairable until the app "
                   "scans the other folder, then complete. The Scan other folders "
                   "feature has no other test",
        "ui": {
            "verdict": "unrepairable",
            "status_pill": "Not repairable",
            "block_states_present": ["present", "missing"],
            "repair_button": "disabled",
            "after_scan_extra_dirs": {
                "extra_dirs": ["elsewhere"],
                "verdict": "repairable",
                "notes": [
                    "Adding the sibling folder must flip the verdict live, "
                    "without reopening the set, and the moved file's row must "
                    "become Misnamed with its found as path outside the set folder.",
                ],
            },
            "notes": [
                "The recovery in this set is deliberately smaller than the moved "
                "file, so a UI that silently repairs without the sibling folder "
                "is reporting something that cannot have happened.",
            ],
        },
    },
    {
        "name": "unrepairable",
        "payload": "common",
        "create": ["-s65536", "-r5"],
        "damage": [("delete", "bravo.bin", 0)],
        "intent": "unrepairable",
        "purpose": "more damage than recovery: the red verdict, the needs N more "
                   "blocks sentence, and a disabled Repair button",
        "ui": {
            "verdict": "unrepairable",
            "status_pill": "Not repairable",
            "block_states_present": ["present", "missing"],
            "repair_button": "disabled",
            "notes": [
                "The shortfall sentence must carry the real number of blocks owed. "
                "cli.blocks_needed below is that number.",
                "Nothing in the UI may offer a repair here. An enabled button that "
                "fails on press is worse than a disabled one.",
            ],
        },
    },
    {
        "name": "unicode",
        "payload": "unicode",
        "create": ["-s65536", "-r20"],
        "damage": [("corrupt", "日本語のファイル.bin", 2)],
        "intent": "repairable",
        "purpose": "names outside ASCII in every column, the window title, the block "
                   "map hover and the log drawer",
        "ui": {
            "verdict": "repairable",
            "status_pill": "Repairable",
            "block_states_present": ["present", "damaged"],
            "repair_button": "enabled",
            "notes": [
                "Four scripts, one of them right to left free but two of them wide. "
                "Check truncation, column width and the sort order of the file table.",
                "The file names are NFC. A platform that hands back NFD (macOS "
                "filesystems do) must still match the row to the set member.",
            ],
        },
    },
    {
        "name": "blocks10k",
        "payload": "big",
        "payload_blocks": 10000,
        "create": ["-s4096", "-r1"],
        "damage": [("corrupt_scattered", "big.bin", 6)],
        "intent": "repairable",
        "purpose": "ten thousand source blocks: the block map's merge mode, where "
                   "cells become proportional segments and hover names a range",
        "ui": {
            "verdict": "repairable",
            "status_pill": "Repairable",
            "block_states_present": ["present", "damaged"],
            "repair_button": "enabled",
            "notes": [
                "Above four thousand blocks the map merges cells. Six scattered "
                "damaged blocks in ten thousand must still be VISIBLE after the "
                "merge: a merge that averages them away has lost the signal the "
                "map exists for.",
                "Hover must read as a range, for example blocks 2,048 to 2,303.",
                "This is also the scenario that answers whether the map redraws at "
                "a usable frame rate while the verify walks the file.",
            ],
        },
    },
    {
        "name": "volgaps",
        "payload": "common",
        "create": ["-s65536", "-r30", "-u", "-n8"],
        "damage": [
            ("delete_volumes", "every-other", 0),
            ("corrupt", "bravo.bin", 4),
        ],
        "intent": "repairable",
        "purpose": "a multi volume set with holes in its volume numbering: the "
                   "header card's recovery figure must count what is PRESENT, not "
                   "what the set was created with",
        "ui": {
            "verdict": "repairable",
            "status_pill": "Repairable",
            "block_states_present": ["present", "damaged"],
            "repair_button": "enabled",
            "notes": [
                "Half the recovery volumes are gone. An app that reads the recovery "
                "block count out of the index packet rather than out of the volumes "
                "it can actually open will overstate it here and may offer a repair "
                "it cannot complete.",
                "The recovery band under the block map must show the available "
                "count against the needed count, both real.",
            ],
        },
    },
    {
        "name": "checksums",
        "payload": "checksum",
        "create": ["-s65536"],          # unused: no PAR2 set here, see below
        "damage": [],
        "intent": "checksum",
        "purpose": "an SFV file with one mismatch and one missing entry: the only "
                   "scenario that grades plan 5.4's Name | Expected | Status "
                   "table, which is the least covered screen in both apps",
        "ui": {
            "verdict": "checksum",
            "status_pill": "2 ok, 1 mismatch, 1 missing",
            "block_states_present": [],
            "repair_button": "absent",
            "notes": [
                "There is no block map and no Repair here. A checksum file says "
                "whether a file changed; it cannot rebuild anything, and an app "
                "offering a repair on this screen is reporting something it "
                "cannot do.",
                "The per-file table is the point. `result.checksum.entries` "
                "landed 12 Sep 2026 NESTED INSIDE the checksum result, not "
                "beside it - the Windows lane coded against the flat spelling "
                "and got an empty table, which reads as a clean checksum file "
                "rather than as a missing field. So grade this row by LOOKING "
                "at the table: four rows, not zero.",
                "Each row carries name, expected, actual and status. `actual` "
                "is empty for the missing row, which is the one row where an "
                "app is likely to render the word 'null'.",
                "THE JOB FINISHES `failed`, NOT `done`, AND STILL CARRIES ITS "
                "FULL RESULT. A checksum verify with problems ends with code "
                "`checksum_mismatch` and a message like '1 mismatched, 1 "
                "missing of 4'. A host that reads `result` only on `done` "
                "therefore shows an EMPTY table on exactly the file the user "
                "opened it for - which is the empty-table failure again by a "
                "second route. The job is FAILED and the table is FULL, and "
                "both are correct. Chip B hit this and it is recorded here so "
                "the next lane does not.",
                "CROSS-CHECKED 12 Sep 2026 and no longer a lone derivation. "
                "parfast-session's own checksum verify, driven through the "
                "FFI over this directory, arrives at these four rows "
                "independently - name, expected, actual and status, row for "
                "row. The test is "
                "`testTheChecksumScenarioMatchesTheEngineRowForRow` in the mac "
                "app's suite. So the derivation and an independent "
                "implementation agree, which is what the docstring's caveat "
                "asked for.",
            ],
        },
    },
]

SCENARIO_NAMES = [s["name"] for s in SCENARIOS]

# The four files the checksum scenario protects, and what is done to each.
# Sizes are small on purpose: this scenario is about a TABLE, not about
# throughput, and a reader opening the directory should be able to see what
# happened to each file at a glance.
CHECKSUM_FILES = [
    ("first.bin", 40 * KIB, "ok"),
    ("second.bin", 24 * KIB, "ok"),
    ("third.bin", 16 * KIB, "mismatch"),
    ("fourth.bin", 8 * KIB, "missing"),
]

# ---------------------------------------------------------------------
# parfast, and reading its verdict back.
# ---------------------------------------------------------------------

# The anchors this script parses out of `parfast v`. Every one of them is
# printed by crates/parfast/src/verify.rs at Terse or Normal level, which
# is what a bare `parfast v` shows. They are matched rather than
# searched for loosely because a missing anchor means the output shape
# moved, and a parser that shrugs at that writes a corpus full of nulls.
RE_SET_SUMMARY = re.compile(
    r"^There are (\d+) recoverable files and (\d+) other files\.$", re.M)
RE_BLOCK_SIZE = re.compile(r"^The block size used was (\d+) bytes\.$", re.M)
RE_TOTAL_BLOCKS = re.compile(r"^There are a total of (\d+) data blocks\.$", re.M)
RE_TOTAL_BYTES = re.compile(
    r"^The total size of the data files is (\d+) bytes\.$", re.M)
RE_TARGET = re.compile(
    r'^Target: "(.+)" - (found|missing|damaged)\.'
    r'(?: Found (\d+) of (\d+) data blocks\.)?$', re.M)
RE_AVAILABLE = re.compile(
    r"^You have (\d+) out of (\d+) data blocks available\.$", re.M)
RE_RECOVERY = re.compile(r"^You have (\d+) recovery blocks available\.$", re.M)
RE_NEEDED = re.compile(
    r"^You need (\d+) more recovery blocks to be able to repair\.$", re.M)
RE_WILL_USE = re.compile(
    r"^(\d+) recovery blocks will be used to repair\.$", re.M)
RE_EXCESS = re.compile(
    r"^You have an excess of (\d+) recovery blocks\.$", re.M)
RE_CENSUS_DAMAGED = re.compile(r"^(\d+) file\(s\) exist but are damaged\.$", re.M)
RE_CENSUS_MISSING = re.compile(r"^(\d+) file\(s\) are missing\.$", re.M)
RE_CENSUS_OK = re.compile(r"^(\d+) file\(s\) are ok\.$", re.M)

VERDICT_ALL_OK = "All files are correct, repair is not required."
VERDICT_POSSIBLE = "Repair is possible."
VERDICT_NOT_POSSIBLE = "Repair is not possible."

# parfast's exit codes, from crates/parfast/src/lib.rs. They are
# par2cmdline's, and scripts branch on them, so they are named here
# rather than written as digits at the comparison sites.
EXIT_SUCCESS = 0
EXIT_REPAIR_POSSIBLE = 1
EXIT_REPAIR_NOT_POSSIBLE = 2

INTENT_EXIT = {
    "complete": EXIT_SUCCESS,
    "repairable": EXIT_REPAIR_POSSIBLE,
    "unrepairable": EXIT_REPAIR_NOT_POSSIBLE,
}


class Refusal(Exception):
    """Something this script could not do. Never a partial corpus."""


def find_parfast(explicit=None):
    """Locate the parfast binary, or refuse naming the build line."""
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise Refusal(f"no parfast binary at {p}")
        return p.resolve()
    here = Path(__file__).resolve()
    # apps/parfast/shared/corpus/make-corpus.py -> repo root is four up.
    root = here.parents[4]
    for rel in ("target/release/parfast", "target/debug/parfast"):
        cand = root / rel
        if cand.is_file():
            if rel.endswith("debug/parfast"):
                warn("using the DEBUG parfast - correct, but slow on blocks10k")
            return cand
    raise Refusal(
        "no parfast binary found. Build one:\n"
        "    cargo build --release --locked -p parfast\n"
        "or pass --parfast PATH")


def run_parfast(parfast, cwd, args):
    """One parfast run. Returns (exit code, stdout + stderr)."""
    proc = subprocess.run(
        [str(parfast), *args], cwd=str(cwd), capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def parse_verify(text, code):
    """Read the facts out of a `parfast v` transcript, or refuse.

    Refuses on a missing anchor rather than returning a hole: the whole
    value of expected.json is that its numbers came from the engine.
    """
    def one(rx, what, group=1, required=True):
        m = rx.search(text)
        if not m:
            if required:
                raise Refusal(
                    f"parfast output carries no {what} line - the output shape "
                    f"moved and this parser is stale.\n--- transcript ---\n{text}")
            return None
        return int(m.group(group))

    out = {
        "verify_exit": code,
        "block_size": one(RE_BLOCK_SIZE, "block size"),
        "source_blocks": one(RE_TOTAL_BLOCKS, "data block total"),
        "source_bytes": one(RE_TOTAL_BYTES, "data file size"),
        "recoverable_files": one(RE_SET_SUMMARY, "set summary"),
    }

    targets = {}
    for m in RE_TARGET.finditer(text):
        name, state, have, total = m.group(1), m.group(2), m.group(3), m.group(4)
        entry = {"state": state}
        if state == "damaged":
            entry["blocks_ok"] = int(have)
            entry["blocks_total"] = int(total)
        targets[name] = entry
    if not targets:
        raise Refusal(
            "parfast output carries no Target: lines - nothing was verified.\n"
            f"--- transcript ---\n{text}")
    out["targets"] = targets

    if VERDICT_ALL_OK in text:
        out["verdict"] = "complete"
        out["available_blocks"] = out["source_blocks"]
        out["recovery_blocks"] = None
        out["blocks_needed"] = 0
    elif VERDICT_POSSIBLE in text:
        out["verdict"] = "repairable"
    elif VERDICT_NOT_POSSIBLE in text:
        out["verdict"] = "unrepairable"
    else:
        raise Refusal(
            "parfast printed no verdict sentence.\n"
            f"--- transcript ---\n{text}")

    if out["verdict"] != "complete":
        m = RE_AVAILABLE.search(text)
        if not m:
            raise Refusal(
                "a damaged set printed no blocks available census.\n"
                f"--- transcript ---\n{text}")
        out["available_blocks"] = int(m.group(1))
        out["recovery_blocks"] = one(RE_RECOVERY, "recovery block count")
        # TWO different numbers, and the status pill needs both. Blocks
        # to rebuild is what the repair has to reconstruct; blocks short
        # is how far the recovery falls below that. par2cmdline prints
        # the first only when the repair is possible and the second only
        # when it is not, so exactly one of them is ever on screen.
        out["blocks_to_rebuild"] = one(RE_WILL_USE, "repair size",
                                       required=False) or 0
        out["blocks_short"] = one(RE_NEEDED, "shortfall", required=False) or 0
        out["recovery_excess"] = one(RE_EXCESS, "excess", required=False)
        out["files_damaged"] = one(RE_CENSUS_DAMAGED, "damaged census",
                                   required=False) or 0
        out["files_missing"] = one(RE_CENSUS_MISSING, "missing census",
                                   required=False) or 0
        out["files_ok"] = one(RE_CENSUS_OK, "ok census", required=False) or 0
        # The census must add up. `owed` is derivable from the two block
        # figures, and the engine prints it separately, so a disagreement
        # means one of the two is being computed over a different set of
        # blocks than the other. That is an engine finding, not a corpus
        # one, and it is worth catching here because the block map draws
        # the first number and the status pill prints the second.
        owed = out["source_blocks"] - out["available_blocks"]
        out["blocks_owed"] = owed
        if out["verdict"] == "repairable" and out["blocks_to_rebuild"] != owed:
            raise Refusal(
                f"parfast says {out['blocks_to_rebuild']} recovery blocks will "
                f"be used but {owed} data blocks are unavailable. These are "
                "the same quantity.\n"
                f"--- transcript ---\n{text}")
        if out["verdict"] == "unrepairable":
            short = owed - out["recovery_blocks"]
            if out["blocks_short"] != short:
                raise Refusal(
                    f"parfast says {out['blocks_short']} more recovery blocks "
                    f"are needed; {owed} unavailable minus "
                    f"{out['recovery_blocks']} available is {short}.\n"
                    f"--- transcript ---\n{text}")
    else:
        out["files_damaged"] = 0
        out["files_missing"] = 0
        out["files_ok"] = len(targets)
        out["blocks_to_rebuild"] = 0
        out["blocks_short"] = 0
        out["blocks_owed"] = 0
        out["recovery_excess"] = None
    return out


# ---------------------------------------------------------------------
# Payload.
# ---------------------------------------------------------------------

def synth_bytes(rng, n):
    """Deterministic pseudo random bytes.

    Random rather than a pattern on purpose: PAR2 does not care, but a
    compressible payload makes every size on screen a lie about what the
    same UI will show on real data, and the bundles this corpus ends up
    beside are measured on disk.
    """
    return rng.randbytes(n)


def write_payload(rng, directory, files):
    made = []
    for name, size in files:
        p = directory / name
        p.write_bytes(synth_bytes(rng, size))
        made.append(name)
    return made


def stage_from_source(source, directory, want, rng):
    """Copy real files out of --source into the scenario directory.

    Takes the first `len(want)` regular files, by sorted name, that are
    at least one block long. Refuses if there are not enough: a corpus
    silently built from two files where nine scenarios expect four is a
    corpus whose per file states cannot all be reached.
    """
    cands = sorted(
        (p for p in source.rglob("*") if p.is_file() and p.stat().st_size >= 64 * KIB),
        key=lambda p: str(p).lower())
    if len(cands) < len(want):
        raise Refusal(
            f"--source {source} has {len(cands)} file(s) of at least 64 KiB; "
            f"this corpus needs {len(want)}")
    made = []
    for src, (name, _) in zip(cands, want):
        dst = directory / src.name
        if dst.exists():
            dst = directory / f"{len(made)}-{src.name}"
        shutil.copy2(src, dst)
        made.append(dst.name)
    return made


# ---------------------------------------------------------------------
# Damage.
#
# Every function here takes the scenario directory and returns a line
# for expected.json's `damage` list, so the corpus says what was done to
# it. A scenario nobody can read the damage out of is one nobody can
# debug an app against.
# ---------------------------------------------------------------------

def damage_corrupt(directory, name, blocks, block_size, rng):
    """Overwrite a contiguous run of whole blocks in the middle of a file."""
    p = directory / name
    size = p.stat().st_size
    total = (size + block_size - 1) // block_size
    if blocks >= total:
        raise Refusal(f"{name} has {total} block(s); cannot corrupt {blocks}")
    first = max(0, total // 2 - blocks // 2)
    with p.open("r+b") as fh:
        fh.seek(first * block_size)
        fh.write(synth_bytes(rng, blocks * block_size))
    return {"kind": "corrupt", "file": name,
            "blocks": [first, first + blocks - 1]}


def damage_corrupt_scattered(directory, name, blocks, block_size, rng):
    """Overwrite single blocks spread across the whole file.

    The merge mode scenario needs its damage SPREAD, because the
    question it asks is whether a merged cell still shows a single bad
    block inside it. A contiguous run would be visible under any merge
    rule and would answer nothing.
    """
    p = directory / name
    total = p.stat().st_size // block_size
    if blocks > total:
        raise Refusal(f"{name} has {total} block(s); cannot corrupt {blocks}")
    step = total // (blocks + 1)
    picks = [step * (i + 1) for i in range(blocks)]
    with p.open("r+b") as fh:
        for b in picks:
            fh.seek(b * block_size)
            fh.write(synth_bytes(rng, block_size))
    return {"kind": "corrupt_scattered", "file": name, "blocks": picks}


def damage_delete(directory, name, _blocks, _bs, _rng):
    (directory / name).unlink()
    return {"kind": "delete", "file": name}


def damage_rename(directory, name, newname, _bs, _rng):
    (directory / name).rename(directory / newname)
    return {"kind": "rename", "file": name, "to": newname}


def damage_move(directory, name, sibling, _bs, _rng):
    dest = directory.parent / sibling
    dest.mkdir(parents=True, exist_ok=True)
    shutil.move(str(directory / name), str(dest / name))
    return {"kind": "move", "file": name, "to": f"../{sibling}/{name}"}


def damage_delete_volumes(directory, which, _blocks, _bs, _rng):
    """Delete recovery volumes, leaving holes in the numbering.

    `every-other` keeps the index file and every second volume. The
    index is never deleted: a set with no index is a different scenario
    (and a different engine path) from a set with gaps in its recovery.
    """
    vols = sorted(p for p in directory.glob("*.par2")
                  if ".vol" in p.name.lower())
    if len(vols) < 4:
        raise Refusal(
            f"expected at least 4 recovery volumes, found {len(vols)} - "
            "the create switches for this scenario are stale")
    gone = []
    for i, p in enumerate(vols):
        if which == "every-other" and i % 2 == 1:
            gone.append(p.name)
            p.unlink()
    if not gone:
        raise Refusal("volume deletion removed nothing")
    return {"kind": "delete_volumes", "removed": gone,
            "kept": [p.name for p in vols if p.name not in gone]}


DAMAGE = {
    "corrupt": damage_corrupt,
    "corrupt_scattered": damage_corrupt_scattered,
    "delete": damage_delete,
    "rename": damage_rename,
    "move": damage_move,
    "delete_volumes": damage_delete_volumes,
}


# ---------------------------------------------------------------------
# Building one scenario.
# ---------------------------------------------------------------------

def block_size_of(create_args):
    for a in create_args:
        if a.startswith("-s"):
            return int(a[2:])
    raise Refusal(f"scenario create args name no block size: {create_args}")


def sha256_of(path):
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_of(root):
    """Every file under root, relative path to sha256 and size, sorted.

    The corpus's own fingerprint. `--check` compares against it.
    expected.json is excluded: it is written after the manifest and is
    not part of the set.
    """
    out = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.name == "expected.json":
            continue
        rel = p.relative_to(root).as_posix()
        out[rel] = {"sha256": sha256_of(p), "bytes": p.stat().st_size}
    return out


def build_checksum_scenario(spec, outdir, parfast, rng):
    """The SFV scenario: write the files, write the .sfv, then damage.

    ITS EXPECTATIONS ARE DERIVED, NOT MEASURED THROUGH THE TOOL, and that
    is the one place this corpus departs from its own rule, so it is
    stated rather than hidden. Every other scenario reads its verdict back
    out of `parfast v`; parfast is a par2cmdline drop-in and has no SFV
    mode at all, so there is no reference run to read. What is written
    here instead is a CRC32 computed from the bytes on disk by the
    standard algorithm an SFV file is defined in terms of - a fact about
    the file rather than an opinion about it - and a per-row status that
    follows from whether those bytes were then changed or deleted. The
    derivation has no freedom in it, which is why it is acceptable; a
    declared VERDICT would not be.

    The cross-check that would close the gap is the session crate's own
    checksum verify over this directory. It lives in another lane's
    crate, so it was named here rather than reached for - AND IT HAS
    SINCE BEEN DONE: chip B drives it through the FFI and arrives at
    these four rows independently, row for row
    (`testTheChecksumScenarioMatchesTheEngineRowForRow`, 12 Sep 2026).
    The derivation is therefore no longer trusted on its own. The caveat
    stays written down because it was true when the scenario landed, and
    because the NEXT scenario added here will start in the same state.
    """
    root = outdir / spec["name"]
    setdir = root / "set"
    setdir.mkdir(parents=True)

    entries = []
    for name, size, fate in CHECKSUM_FILES:
        (setdir / name).write_bytes(synth_bytes(rng, size))
        crc = zlib.crc32((setdir / name).read_bytes()) & 0xFFFFFFFF
        entries.append({"name": name, "expected": f"{crc:08X}", "fate": fate})

    # The SFV, in the format every tool that reads one expects: a comment
    # banner, then `name CRC32` per line, uppercase hex, no padding.
    lines = ["; Generated by make-corpus.py for the parfast GUI acceptance corpus",
             "; Two entries match, one does not, one file is gone."]
    lines += [f"{e['name']} {e['expected']}" for e in entries]
    (setdir / "set.sfv").write_text("\n".join(lines) + "\n", encoding="utf-8")

    applied = []
    for e in entries:
        if e["fate"] == "mismatch":
            p = setdir / e["name"]
            b = bytearray(p.read_bytes())
            b[len(b) // 2] ^= 0xFF        # one bit-flipped byte: same size
            p.write_bytes(bytes(b))
            e["actual"] = f"{zlib.crc32(bytes(b)) & 0xFFFFFFFF:08X}"
            applied.append({"kind": "flip_one_byte", "file": e["name"]})
        elif e["fate"] == "missing":
            (setdir / e["name"]).unlink()
            e["actual"] = ""
            applied.append({"kind": "delete", "file": e["name"]})
        else:
            e["actual"] = e["expected"]

    counts = {"ok": 0, "mismatch": 0, "missing": 0}
    for e in entries:
        counts[e["fate"]] += 1

    ui = dict(spec["ui"])
    ui["checksum"] = {
        "format": "sfv",
        "file": "set.sfv",
        "counts": counts,
        "entries": [{"name": e["name"], "expected": e["expected"],
                     "actual": e["actual"], "status": e["fate"]}
                    for e in entries],
    }

    doc = {
        "schema": SCHEMA,
        "scenario": spec["name"],
        "purpose": spec["purpose"],
        "generated_by": "apps/parfast/shared/corpus/make-corpus.py",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "parfast": parfast_version(parfast),
        "payload": "synthesised",
        "set": {"dir": "set", "checksum_file": "set.sfv", "par2": None,
                "members": [e["name"] for e in entries]},
        "damage": applied,
        "cli": {"verify_argv": None,
                "note": "parfast is a par2cmdline drop-in and has no SFV mode; "
                        "this scenario's expectations are derived from the "
                        "bytes rather than read back out of a reference run. "
                        "See build_checksum_scenario's docstring."},
        "ui": ui,
    }
    doc["files"] = manifest_of(root)
    (root / "expected.json").write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return doc


def build_scenario(spec, outdir, parfast, source, rng, repair_probe=True):
    if spec["payload"] == "checksum":
        return build_checksum_scenario(spec, outdir, parfast, rng)

    name = spec["name"]
    root = outdir / name
    setdir = root / "set"
    setdir.mkdir(parents=True)
    bs = block_size_of(spec["create"])

    if spec["payload"] == "common":
        if source is not None:
            names = stage_from_source(source, setdir, COMMON_FILES, rng)
        else:
            names = write_payload(rng, setdir, COMMON_FILES)
    elif spec["payload"] == "unicode":
        names = write_payload(
            rng, setdir,
            [(unicodedata.normalize("NFC", n), s) for n, s in UNICODE_FILES])
    elif spec["payload"] == "big":
        names = write_payload(
            rng, setdir, [("big.bin", spec["payload_blocks"] * bs)])
    else:
        raise Refusal(f"{name}: unknown payload {spec['payload']!r}")

    code, text = run_parfast(
        parfast, setdir, ["c", *spec["create"], "set.par2", *names])
    if code != EXIT_SUCCESS:
        raise Refusal(f"{name}: create failed (exit {code})\n{text}")
    created = sorted(p.name for p in setdir.glob("*.par2"))
    if "set.par2" not in created:
        raise Refusal(f"{name}: create wrote no index file. Wrote: {created}")

    applied = []
    for kind, target, arg in spec["damage"]:
        fn = DAMAGE.get(kind)
        if fn is None:
            raise Refusal(f"{name}: unknown damage {kind!r}")
        # `target` is a member name for most kinds and a selector for
        # delete_volumes; the source folder renames members, so a
        # scenario built with --source maps positionally.
        if source is not None and kind != "delete_volumes":
            idx = [n for n, _ in COMMON_FILES]
            if target in idx:
                target = names[idx.index(target)]
        applied.append(fn(setdir, target, arg, bs, rng))

    code, text = run_parfast(parfast, setdir, ["v", "set.par2"])
    cli = parse_verify(text, code)
    cli["verify_argv"] = ["v", "set.par2"]
    cli["par2_files_present"] = sorted(p.name for p in setdir.glob("*.par2"))

    want = spec["intent"]
    if cli["verdict"] != want:
        raise Refusal(
            f"{name}: intended {want}, parfast says {cli['verdict']}. The "
            "scenario's create switches or damage no longer produce the state "
            "it exists to show.\n"
            f"--- transcript ---\n{text}")
    if code != INTENT_EXIT[want]:
        raise Refusal(
            f"{name}: verdict {want} but exit {code}, expected "
            f"{INTENT_EXIT[want]}. The verdict sentence and the exit code "
            "disagree, which is an engine bug and not a corpus one.")

    repair = None
    if repair_probe:
        repair = probe_repair(parfast, root, name)

    doc = {
        "schema": SCHEMA,
        "scenario": name,
        "purpose": spec["purpose"],
        "generated_by": "apps/parfast/shared/corpus/make-corpus.py",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "parfast": parfast_version(parfast),
        "payload": "from --source" if source is not None else "synthesised",
        "set": {
            "dir": "set",
            "par2": "set.par2",
            "create_args": spec["create"],
            "members": names,
        },
        "damage": applied,
        "cli": cli,
        "ui": spec["ui"],
    }
    if repair is not None:
        doc["ui"] = dict(doc["ui"])
        doc["ui"]["repair"] = repair
    doc["files"] = manifest_of(root)
    (root / "expected.json").write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return doc


def probe_repair(parfast, root, name):
    """Repair a COPY and report what happened, then delete the copy.

    See the header: measuring this in place would repair the corpus.
    """
    tmp = Path(tempfile.mkdtemp(prefix=f"parfast-corpus-{name}-"))
    try:
        copy = tmp / "root"
        shutil.copytree(root, copy)
        code, text = run_parfast(parfast, copy / "set", ["r", "set.par2"])
        after, _ = run_parfast(parfast, copy / "set", ["v", "set.par2"])
        return {
            "expected": "repaired" if after == EXIT_SUCCESS else "not repaired",
            "repair_exit": code,
            "verify_exit_after_repair": after,
            "measured_on": "a throwaway copy at generation time",
            "transcript_tail": [
                ln for ln in text.splitlines() if ln.strip()][-6:],
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def parfast_version(parfast):
    code, text = run_parfast(parfast, Path.cwd(), ["-VV"])
    if code != EXIT_SUCCESS:
        return "unknown"
    return " / ".join(text.strip().splitlines()[:2])


# ---------------------------------------------------------------------
# check
# ---------------------------------------------------------------------

def check_corpus(outdir, quiet=False):
    """Is this corpus still in the state it was generated in?

    `quiet` is for the selftest, which deliberately checks a TAMPERED
    corpus and would otherwise print a failure report in the middle of a
    passing run. A reader scrolling a CI log should not have to work out
    which of the two ✗ blocks is the expected one.
    """
    say = (lambda *a: None) if quiet else print
    outdir = Path(outdir)
    roots = sorted(p for p in outdir.iterdir()
                   if p.is_dir() and (p / "expected.json").is_file())
    if not roots:
        raise Refusal(
            f"{outdir} holds no scenario with an expected.json - nothing to "
            "check. An empty check is not a clean one.")
    bad = 0
    for root in roots:
        doc = json.loads((root / "expected.json").read_text(encoding="utf-8"))
        want = doc.get("files")
        if not want:
            raise Refusal(f"{root.name}: expected.json carries no file manifest")
        have = manifest_of(root)
        missing = sorted(set(want) - set(have))
        added = sorted(set(have) - set(want))
        changed = sorted(k for k in set(want) & set(have)
                         if want[k]["sha256"] != have[k]["sha256"])
        if missing or added or changed:
            bad += 1
            say(f"✗ {root.name}")
            for k in missing:
                say(f"    gone:    {k}")
            for k in added:
                say(f"    added:   {k}")
            for k in changed:
                say(f"    changed: {k}")
        else:
            say(f"✓ {root.name}  ({len(have)} file(s))")
    if bad:
        say(f"\n{bad} of {len(roots)} scenario(s) have moved since generation.")
        say("A repaired or edited scenario no longer shows the state it was "
            "built for. Regenerate before grading an app against it.")
        return 1
    say(f"\n{len(roots)} scenario(s) unchanged since generation.")
    return 0


# ---------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------

# A real `parfast v` transcript, kept here so the PARSER can be tested
# without a binary. Regenerate by hand from a live run if the output
# shape ever moves; the parser refusing is the signal that it has.
SAMPLE_DAMAGED = """\
Loading "set.par2".
Loaded 4 new packets

There are 4 recoverable files and 0 other files.
The block size used was 65536 bytes.
There are a total of 80 data blocks.
The total size of the data files is 5242880 bytes.

Verifying source files:

Target: "alpha.bin" - found.
Target: "bravo.bin" - damaged. Found 29 of 32 data blocks.
Target: "charlie.bin" - found.
Target: "delta.bin" - found.

Scanning extra files:

Repair is required.
1 file(s) exist but are damaged.
3 file(s) are ok.
You have 77 out of 80 data blocks available.
You have 8 recovery blocks available.
You have an excess of 5 recovery blocks.
3 recovery blocks will be used to repair.
Repair is possible.
"""

SAMPLE_CLEAN = """\
Loading "set.par2".

There are 4 recoverable files and 0 other files.
The block size used was 65536 bytes.
There are a total of 80 data blocks.
The total size of the data files is 5242880 bytes.

Verifying source files:

Target: "alpha.bin" - found.
Target: "bravo.bin" - found.
Target: "charlie.bin" - found.
Target: "delta.bin" - found.

All files are correct, repair is not required.
"""

SAMPLE_UNREPAIRABLE = """\
Loading "set.par2".

There are 4 recoverable files and 0 other files.
The block size used was 65536 bytes.
There are a total of 80 data blocks.
The total size of the data files is 5242880 bytes.

Verifying source files:

Target: "alpha.bin" - found.
Target: "bravo.bin" - missing.
Target: "charlie.bin" - found.
Target: "delta.bin" - found.

Scanning extra files:

Repair is required.
1 file(s) are missing.
3 file(s) are ok.
You have 48 out of 80 data blocks available.
You have 4 recovery blocks available.
Repair is not possible.
You need 28 more recovery blocks to be able to repair.
"""


def selftest(parfast_path=None):
    checks = []

    def ok(label, cond):
        checks.append((label, bool(cond)))

    # ---- the scenario table itself --------------------------------
    ok("ten scenarios", len(SCENARIOS) == 10)
    ok("scenario names unique", len(set(SCENARIO_NAMES)) == len(SCENARIO_NAMES))
    for s in SCENARIOS:
        n = s["name"]
        ok(f"{n}: has a purpose", s.get("purpose"))
        ok(f"{n}: intent is known",
           s["intent"] in INTENT_EXIT or s["intent"] == "checksum")
        ok(f"{n}: names a block size", block_size_of(s["create"]) > 0)
        ok(f"{n}: block size is a multiple of 4",
           block_size_of(s["create"]) % 4 == 0)
        ok(f"{n}: ui verdict matches intent", s["ui"]["verdict"] == s["intent"])
        # The checksum scenario has no block map, so an EMPTY state list is
        # its correct answer and the presence check would refuse it.
        if s["payload"] != "checksum":
            ok(f"{n}: ui names block states", s["ui"].get("block_states_present"))
        else:
            ok(f"{n}: has no block map", s["ui"]["block_states_present"] == [])
        ok(f"{n}: every damage kind is known",
           all(k in DAMAGE for k, _, _ in s["damage"]))
    ok("the plan's nine are all here, plus the checksum tenth",
       set(SCENARIO_NAMES) == {"clean", "damaged", "missing", "misnamed",
                               "moved", "unrepairable", "unicode",
                               "blocks10k", "volgaps", "checksums"})
    # The misnamed scenario's whole purpose is that misnamed is DISTINCT
    # from missing, so a state list carrying both accepts either answer and
    # can never fail. It carried both until 12 Sep 2026.
    mis = next(s for s in SCENARIOS if s["name"] == "misnamed")
    ok("misnamed does not hedge between misnamed and missing",
       "missing" not in mis["ui"]["block_states_present"])

    # ---- the parser, against captured transcripts -------------------
    d = parse_verify(SAMPLE_DAMAGED, EXIT_REPAIR_POSSIBLE)
    ok("damaged: verdict", d["verdict"] == "repairable")
    ok("damaged: block size", d["block_size"] == 65536)
    ok("damaged: source blocks", d["source_blocks"] == 80)
    ok("damaged: available", d["available_blocks"] == 77)
    ok("damaged: recovery", d["recovery_blocks"] == 8)
    ok("damaged: per file blocks",
       d["targets"]["bravo.bin"] == {"state": "damaged", "blocks_ok": 29,
                                     "blocks_total": 32})
    ok("damaged: census", (d["files_damaged"], d["files_ok"],
                           d["files_missing"]) == (1, 3, 0))

    c = parse_verify(SAMPLE_CLEAN, EXIT_SUCCESS)
    ok("clean: verdict", c["verdict"] == "complete")
    ok("clean: four found",
       all(t["state"] == "found" for t in c["targets"].values()))
    ok("clean: nothing owed", c["blocks_owed"] == 0)

    u = parse_verify(SAMPLE_UNREPAIRABLE, EXIT_REPAIR_NOT_POSSIBLE)
    ok("unrepairable: verdict", u["verdict"] == "unrepairable")
    ok("unrepairable: shortfall", u["blocks_short"] == 28)
    ok("unrepairable: owed", u["blocks_owed"] == 32)
    ok("damaged: rebuild size", d["blocks_to_rebuild"] == 3)
    ok("damaged: excess", d["recovery_excess"] == 5)
    ok("unrepairable: missing file",
       u["targets"]["bravo.bin"]["state"] == "missing")

    # A transcript with an anchor removed must REFUSE, not return a hole.
    # The Target arm drops EVERY such line rather than one: dropping one
    # leaves three, and a parser that still answers over three files is
    # behaving correctly. What must refuse is a verify that named no
    # file at all, which is the shape a moved output format produces.
    maimed = [
        ("the block size line",
         SAMPLE_CLEAN.replace("The block size used was 65536 bytes.\n", "")),
        ("every Target line",
         re.sub(r"^Target: .*\n", "", SAMPLE_CLEAN, flags=re.M)),
        ("the data block total",
         SAMPLE_CLEAN.replace("There are a total of 80 data blocks.\n", "")),
        ("the blocks available census",
         SAMPLE_DAMAGED.replace(
             "You have 77 out of 80 data blocks available.\n", "")),
    ]
    for what, text in maimed:
        try:
            parse_verify(text, EXIT_SUCCESS)
            ok(f"refuses a transcript missing {what}", False)
        except Refusal:
            ok(f"refuses a transcript missing {what}", True)

    # A census that does not add up must refuse, in both directions.
    try:
        parse_verify(
            SAMPLE_DAMAGED.replace("3 recovery blocks will be used to repair.",
                                   "9 recovery blocks will be used to repair."),
            EXIT_REPAIR_POSSIBLE)
        ok("refuses a repair size that contradicts the block census", False)
    except Refusal:
        ok("refuses a repair size that contradicts the block census", True)
    try:
        parse_verify(
            SAMPLE_UNREPAIRABLE.replace(
                "You need 28 more recovery blocks to be able to repair.",
                "You need 3 more recovery blocks to be able to repair."),
            EXIT_REPAIR_NOT_POSSIBLE)
        ok("refuses a shortfall that contradicts the block census", False)
    except Refusal:
        ok("refuses a shortfall that contradicts the block census", True)

    # A transcript with no verdict sentence at all.
    try:
        parse_verify(SAMPLE_CLEAN.replace(VERDICT_ALL_OK, ""), EXIT_SUCCESS)
        ok("refuses a verdictless transcript", False)
    except Refusal:
        ok("refuses a verdictless transcript", True)

    # ---- damage functions, on a scratch tree ------------------------
    tmp = Path(tempfile.mkdtemp(prefix="parfast-corpus-selftest-"))
    try:
        rng = random.Random(1)
        d1 = tmp / "d1"
        d1.mkdir()
        write_payload(rng, d1, [("x.bin", 16 * 64 * KIB)])
        before = (d1 / "x.bin").read_bytes()
        rec = damage_corrupt(d1, "x.bin", 3, 64 * KIB, rng)
        after = (d1 / "x.bin").read_bytes()
        ok("corrupt: same length", len(before) == len(after))
        diff = [i // (64 * KIB) for i in range(len(before))
                if before[i] != after[i]]
        ok("corrupt: exactly the named blocks",
           set(diff) == set(range(rec["blocks"][0], rec["blocks"][1] + 1)))

        d2 = tmp / "d2"
        d2.mkdir()
        write_payload(rng, d2, [("y.bin", 100 * 4096)])
        before = (d2 / "y.bin").read_bytes()
        rec = damage_corrupt_scattered(d2, "y.bin", 6, 4096, rng)
        after = (d2 / "y.bin").read_bytes()
        touched = sorted({i // 4096 for i in range(len(before))
                          if before[i] != after[i]})
        ok("scattered: six blocks", len(touched) == 6)
        ok("scattered: the named ones", touched == sorted(rec["blocks"]))
        ok("scattered: actually spread", max(touched) - min(touched) > 50)

        # manifest and check
        d3 = tmp / "d3"
        (d3 / "set").mkdir(parents=True)
        write_payload(rng, d3 / "set", [("z.bin", 4096)])
        man = manifest_of(d3)
        ok("manifest: relative posix keys", list(man) == ["set/z.bin"])
        ok("manifest: carries a digest and a size",
           set(man["set/z.bin"]) == {"sha256", "bytes"})
        (d3 / "expected.json").write_text(
            json.dumps({"schema": SCHEMA, "files": man}), encoding="utf-8")
        ok("manifest: skips expected.json itself",
           list(manifest_of(d3)) == ["set/z.bin"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # `check` on a tampered corpus must fail, and on an empty directory
    # must REFUSE rather than report a clean run over nothing.
    tmp = Path(tempfile.mkdtemp(prefix="parfast-corpus-selftest-check-"))
    try:
        root = tmp / "one"
        (root / "set").mkdir(parents=True)
        (root / "set" / "z.bin").write_bytes(b"a" * 64)
        (root / "expected.json").write_text(
            json.dumps({"schema": SCHEMA, "files": manifest_of(root)}),
            encoding="utf-8")
        ok("check: unchanged corpus is 0", check_corpus(tmp, quiet=True) == 0)
        (root / "set" / "z.bin").write_bytes(b"b" * 64)
        ok("check: tampered corpus is 1", check_corpus(tmp, quiet=True) == 1)
        empty = Path(tempfile.mkdtemp(prefix="parfast-corpus-empty-"))
        try:
            check_corpus(empty, quiet=True)
            ok("check: refuses an empty directory", False)
        except Refusal:
            ok("check: refuses an empty directory", True)
        finally:
            shutil.rmtree(empty, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    failed = [label for label, good in checks if not good]
    for label in failed:
        print(f"✗ {label}")
    print(f"\nlogic: {len(checks) - len(failed)}/{len(checks)} checks passed")

    # ---- end to end, only if there is a binary ----------------------
    e2e = "SKIPPED"
    try:
        parfast = find_parfast(parfast_path)
    except Refusal as exc:
        print(f"\nend to end: SKIPPED - {exc}".splitlines()[0])
    else:
        tmp = Path(tempfile.mkdtemp(prefix="parfast-corpus-e2e-"))
        try:
            rng = random.Random(7)
            for spec in SCENARIOS:
                if spec["name"] not in ("clean", "damaged", "unrepairable"):
                    continue
                build_scenario(spec, tmp, parfast, None, rng,
                               repair_probe=(spec["name"] == "damaged"))
            rc = check_corpus(tmp, quiet=True)
            if rc != 0:
                failed.append("end to end: a fresh corpus fails its own check")
            doc = json.loads(
                (tmp / "damaged" / "expected.json").read_text(encoding="utf-8"))
            if doc["ui"]["repair"]["verify_exit_after_repair"] != EXIT_SUCCESS:
                failed.append("end to end: the damaged scenario did not repair")
            if not (tmp / "damaged" / "set" / "set.par2").is_file():
                failed.append("end to end: the repair probe ate the corpus")
            e2e = "OK (clean, damaged, unrepairable built and checked)"
            print(f"\nend to end: {e2e}")
        except Refusal as exc:
            failed.append(f"end to end: {exc}")
            print(f"\nend to end: FAILED - {exc}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    if failed:
        print(f"\nSELFTEST FAILED ({len(failed)} check(s))")
        return 1
    if e2e == "SKIPPED":
        print("\nSELFTEST PARTIAL - the logic half passed and the end to end "
              "half did NOT run.\nBuild parfast and run it again before "
              "trusting a corpus this script produced.")
        return 0
    print("\nSELFTEST OK")
    return 0


# ---------------------------------------------------------------------

def warn(msg):
    print(f"make-corpus: {msg}", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Scenarios: " + ", ".join(SCENARIO_NAMES))
    ap.add_argument("outdir", nargs="?", help="where the corpus is written")
    ap.add_argument("--source", metavar="DIR",
                    help="build the four file scenarios out of real files from "
                         "here (never written to)")
    ap.add_argument("--scenarios", metavar="A,B",
                    help="build only these (default: all nine)")
    ap.add_argument("--parfast", metavar="PATH",
                    help="the parfast binary (default: target/release/parfast)")
    ap.add_argument("--seed", type=int, default=20260912,
                    help="payload seed, so two runs give identical bytes")
    ap.add_argument("--force", action="store_true",
                    help="overwrite an existing output directory")
    ap.add_argument("--no-repair-probe", action="store_true",
                    help="skip measuring the repair on a throwaway copy")
    ap.add_argument("--check", action="store_true",
                    help="verify a generated corpus is unchanged, then exit")
    ap.add_argument("--list", action="store_true",
                    help="print the scenarios and what each one is for")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest(args.parfast)

    if args.list:
        for s in SCENARIOS:
            print(f"{s['name']:<14} {s['intent']}")
            print(f"               {s['purpose']}")
        return 0

    if not args.outdir:
        ap.error("an output directory is required")

    if args.check:
        return check_corpus(Path(args.outdir))

    outdir = Path(args.outdir)
    if outdir.exists():
        if not args.force:
            raise Refusal(
                f"{outdir} exists. Pass --force to replace it, or pick another "
                "path. Regenerating in place would leave a half old corpus.")
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True)

    parfast = find_parfast(args.parfast)
    source = Path(args.source).resolve() if args.source else None
    if source is not None and not source.is_dir():
        raise Refusal(f"--source {source} is not a directory")

    want = SCENARIO_NAMES
    if args.scenarios:
        want = [s.strip() for s in args.scenarios.split(",") if s.strip()]
        unknown = [s for s in want if s not in SCENARIO_NAMES]
        if unknown:
            raise Refusal(f"unknown scenario(s): {', '.join(unknown)}")

    rng = random.Random(args.seed)
    built = []
    for spec in SCENARIOS:
        if spec["name"] not in want:
            continue
        t0 = time.time()
        doc = build_scenario(spec, outdir, parfast, source, rng,
                             repair_probe=not args.no_repair_probe)
        built.append(doc)
        cli = doc["cli"]
        if "verdict" in cli:
            print(f"✓ {spec['name']:<14} {cli['verdict']:<13} "
                  f"{cli['source_blocks']:>6} blocks  "
                  f"{cli['available_blocks']:>6} available  "
                  f"exit {cli['verify_exit']}  ({time.time() - t0:.1f}s)")
        else:
            # The checksum scenario has no PAR2 set and so no verdict line.
            # Its numbers are the per-row census instead.
            c = doc["ui"]["checksum"]["counts"]
            print(f"✓ {spec['name']:<14} {'checksum':<13} "
                  f"{len(doc['ui']['checksum']['entries']):>6} rows    "
                  f"{c['ok']} ok, {c['mismatch']} mismatch, {c['missing']} missing"
                  f"  ({time.time() - t0:.1f}s)")

    (outdir / "CORPUS.json").write_text(json.dumps({
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "parfast": parfast_version(parfast),
        "seed": args.seed,
        "source": str(source) if source else None,
        "scenarios": [d["scenario"] for d in built],
    }, indent=2) + "\n", encoding="utf-8")

    print(f"\n{len(built)} scenario(s) in {outdir}")
    print("Each one carries expected.json: what it is for, the measured CLI "
          "facts, and the UI states the apps are graded against.")
    print(f"Re-check it with:  {Path(__file__).name} --check {outdir}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refusal as exc:
        print(f"\nmake-corpus: REFUSING: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
