#!/usr/bin/env python3
"""Refuse file and function growth past the recorded baseline. TODO 102 / 106.

The scorecard kept measuring the same drift: TODO 43 split `serve()` to 1,819
lines and it regrew to 2,234 within days; `get_with_progress()` reached 3,942
lines - 2.5x the longest function in any competitor - without any list even
naming it. The 3 Aug offender list missed it because a naive brace counter
died on the first string literal containing a brace. This gate exists so the
§106 splits stay split.

Semantics:
  - Every `.rs` file under crates/ (fuzz dirs excluded) must stay under
    FILE_CEILING raw lines; every PRODUCTION function must stay under
    FN_CEILING lines. Test functions are reported but not gated - a table
    of cases is allowed to be long.
  - Today's offenders are allow-listed in BASELINE with their measured
    size. An entry's limit is its recorded size plus 2% slack, so ordinary
    feature work does not trip it while regrowth does. A false-refusal-prone
    gate gets switched off - that is the fmt-hook lesson.
  - The list only shrinks. When a target drops back under the ceiling the
    gate FAILS until its entry is deleted, in the same commit as the split.
    That is the ratchet.

Test scope is resolved properly (inline `#[cfg(test)]` blocks AND
`#[cfg(test)] mod foo;` making the whole of foo.rs test code) - same
resolver family as tools/lock-gate.py, same reason: naive path-based
counting has already produced one wrong scorecard round.

`--headroom` exists because `--list` cannot answer the question the recurring
split chips actually ask. It sorts by SIZE, so a function at 500 of 500 ranks
below one at 400 of 9,000, and it prints neither the limit nor which KIND of
ceiling a target is under - and those two regimes behave OPPOSITELY when you
split. A flat-ceiling file converts a split line for line into headroom; a
BASELINED one does not convert at all, because the ratchet re-centres the same
2% on the smaller number. On 31 Aug 2026 a chip paired
`tests/e2e_norar/mod.rs` (flat, 97 free - a split bought 457 lines) with
`tests/daemon.rs` (baselined, 181 free - no split can buy more than ~50, and
LESS the bigger the split) as one problem, and the second half of it was not
buildable. They were never one problem.

Usage:
    tools/size-gate.py            # gate: exit 1 on any violation
    tools/size-gate.py --list     # report the largest files and functions
    tools/size-gate.py --headroom # report what is CLOSEST to its ceiling,
                                  #   with the limit and the ceiling KIND
    tools/size-gate.py --selftest # prove the scope resolver still works
"""

import contextlib
import io
import os
import re
import sys

CRATES = "crates"
FILE_CEILING = 3000  # raw lines; the worst competitor file is ~5,400
FN_CEILING = 500  # production function lines; rustnzb ships zero over 500
SLACK = 1.02  # ordinary feature work must not trip an allow-listed entry

# Measured 4 Aug 2026 (post-v1.0.16). Delete each entry as its target is
# split - the gate refuses stale entries, so deletion is enforced, not hoped.
BASELINE_FILES = {
    # path (relative to repo root): raw lines measured
    # serve/mod.rs was here at 13,837, then 12,988, then 13,310. Phase 4
    # moved its flat free functions out to sibling modules and dispersed
    # its 4,800-line inline `mod tests`; it is 852 lines now, so its entry
    # is GONE. Nothing is left to grandfather.
    # 11,803, then 12,429 after the 8 Aug §129 burst. Two concurrent
    # sessions split it at different seams and both landed: the
    # mid-download password and prefer_external_unrar tests went to
    # tests/daemon_unpackroute/, the five M11 playback rigs to
    # tests/stream_live/. 10,678 with both, so the entry ratchets DOWN.
    # ...and 11,146 after the #34 SAB-parity round. What a credential may
    # do - the full key, the add-only nzbkey, and the bootstrap hatch
    # between them - is one subject and six tests, and moved whole to
    # tests/daemon_authkey/. 10,466. Regrown to 10,699 through the §99
    # try-order and §100 retry merges; the four passworded-archive legs -
    # set_password after the fact, the passwords file consulted at
    # completion, the ENOSPC republish, and the prompt that must not
    # leave the archive packed - are one subject and moved whole to
    # tests/daemon_password/. 10,030.
    # Still 10,030 on 29 Aug 2026 - 68 lines of margin, and the narrowest
    # of the two entries left after that day's round took the other four
    # off (research/SIZE-GATE-BASELINED-MARGINS-2026-08-29.md). Nothing
    # about 68 was safe: pool.rs went from 31 lines of margin to ONE
    # inside two hours the same day while an ordinary module landed from
    # another lane, and this file has already crossed its own ceiling by
    # MERGE ARITHMETIC between two lanes who each saw a green gate on
    # their own branch. The remaining 134 inline tests do NOT cluster by
    # name - grouping every one by its first two name segments gives a
    # long tail whose largest group is THREE - so the seam was found by
    # reading what they are ABOUT, which is how all 37 existing children
    # were found. WHAT A CLIENT SEES is one subject: the daemon carries
    # TWO client vocabularies over one queue (the SABnzbd-compatible API
    # and the NZBGet JSON-RPC one), and four of the six legs were written
    # because those two had drifted apart - which client type the user
    # happened to configure decided whether a documented verb worked at
    # all (the priority write that releases a duplicate hold,
    # `change_cat`, the idle edge a lifecycle hook listens for). The
    # other two pin the payload SHAPE each side's parser expects, key by
    # key and with the type that side sends. All six moved whole to
    # tests/daemon_facade/, byte-identical, no helper following them: the
    # fourteen top-level helpers in daemon.rs are each still reached by
    # what stayed, so nothing became dead code. 9,132, which is 182 lines
    # of margin rather than 68. THE ENTRY STAYS: the flat ceiling is
    # 3,000 and this file is three times that, so no single seam can
    # delete it - the pattern here is a subject per round, ratcheting,
    # for a long while yet. The bigger remaining seams a reading turned
    # up and this round did NOT take, named so the next lane does not
    # rediscover them as oversights: WHAT SURVIVES A RESTART (~890 lines
    # over six tests) and THE ARCHIVE SHAPES THE DAEMON MEETS (~790, four
    # of them contiguous at the zip payload posts).
    "crates/nzbfast/tests/daemon.rs": 9132,
    # 7471 when first measured; two concurrent 5 Aug sessions landed
    # test growth (one-pass rigs + the round-6 crc-retry pricing leg).
    # 7,746 by 29 Aug 2026 - 47 lines of margin, the NARROWEST in this
    # table once daemon.rs had ratcheted, and the busier of the two by a
    # long way: 29 commits touched this file on origin/main in the seven
    # days to 29 Aug. It was held off deliberately while the
    # red-e2e-ffad4ab3 red was open (two of its tests were the subject),
    # so a size split would not put two lanes in one file; that red
    # landed in b92b74927 and both formerly-failing tests were re-run
    # green before this seam was cut, rather than taking the ledger's
    # word for it.
    # Unlike daemon.rs the names here DO cluster a little - encrypted_
    # store (5), kill9_resume (4), store_rar (4), par_only (4) - but the
    # seam taken is a subject none of those spell: A POST WHOSE PAR2
    # FILES DO NOT ANNOUNCE THEMSELVES. Its recovery volumes carry no
    # `.par2` extension and no findable name, so nothing can be
    # classified from the NZB and the offset-0 magic sniff has to
    # reclassify each slot in-stream. Public issue #9 is where it starts
    # (a repairable download failed while SABnzbd repaired it), #14 is
    # the resume half (a journal-completed head never re-decodes, so run
    # 2 recognises restored volumes by reading their first bytes off
    # disk) and #23 is the coverage rule that came out of it. The last
    # three legs are the MIRROR of the same question - payload that
    # looks like PAR2 to the sniff and is not, which must be un-deferred
    # and delivered byte-exact rather than recreated from recovery
    # blocks - and belong with it rather than beside the named-PAR2 legs
    # they happened to sit next to. Nine tests and one private fixture
    # builder, 862 contiguous lines, moved whole to
    # tests/e2e_sniffedpar2/. `par2_shaped_payload_fixture` went with
    # them because it is defined AND used entirely inside the block; the
    # three helpers a reader would expect to follow - `incompressible`,
    # `sevenz_container`, `sevenz_store_container` - deliberately did
    # NOT, because e2e_resume, e2e_chaseresume, e2e_tar and e2e_zipsplit
    # reach them through `super::` and moving them would respell a path
    # in four sibling files. 6,888.
    # THE ENTRY STAYS, and the arithmetic says how long for: the flat
    # ceiling is 3,000, so 3,888 lines have still to leave, and an
    # entry's slack is 2% of ITSELF - which is the thing to understand
    # before sizing the next seam. Cutting MORE does not buy more
    # margin, it buys less (862 lines here leaves 137; a 1,600-line cut
    # would have left 123), so the only reason to cut deep is distance
    # from 3,000, never headroom. A subject per round.
    # The other seams read and NOT taken, named so the next lane does
    # not rediscover them as oversights: THE NON-RAR CONTAINERS AT THE
    # TOP LEVEL (7z and zip, ~786 contiguous lines at what is now
    # ~4,500) - a clean subject, and the reason it was passed over is
    # that its three helpers above are shared with four siblings, so the
    # block is three ranges rather than one; and THE ENCRYPTED ARCHIVES
    # (~400 contiguous plus scattered legs).
    # 6,280 by 31 Aug 2026. It had regrown from 6,888 to sit at 7,025
    # against a 7,025 limit - ZERO headroom - and that is not a margin,
    # it is a wall: a module declaration is ONE line, so the next lane to
    # add an `e2e_*` child reddens `size-gate` AND `check` on main for
    # everyone, exactly as `4839d3dd8` did on 30 Aug. Eighteen chips were
    # dispatched on 31 Aug and at least eight are in the norar/repair
    # families, so this was taken as its own claimed commit ahead of
    # them rather than left for whichever lane happened to trip it.
    # The seam is THE NON-RAR CONTAINERS AT THE TOP LEVEL - the first of
    # the two the previous round read and deliberately passed over - and
    # its subject is one question end to end: what the chase does when
    # the outermost thing on the wire is a container the RAR reader
    # cannot open. Thirteen tests over both formats: single file, byte-
    # split set (`.7z.001`, `.zip.001` and the bare-numeric hjsplit
    # shape), a store RAR wrapping a zip, the retention-cap trim and the
    # demote that must land identically when the trim cannot happen, the
    # damaged post that materializes and repairs on disk, the encrypted
    # zip the chase decrypts in stream, and the zip it DECLINES. 748
    # lines to tests/e2e_containers/, one `mod` line back.
    # THREE RANGES RATHER THAN ONE, which is why the previous round named
    # this seam and left it: `incompressible`, `sevenz_container` and
    # `sevenz_store_container` are defined INSIDE the block and are
    # reached through `super::` by e2e_chaseresume, e2e_resume, e2e_tar
    # and e2e_zipsplit, so they stayed put - moving them would respell a
    # path in four sibling files to buy about fifty lines. They now sit
    # together where the block used to be, beside the other shared
    # fixture builders.
    # A PURE MOVE: no test body changed, and the name set was compared
    # mechanically before and after - the only difference is the
    # `e2e_containers::` prefix on those thirteen.
    # THE ENTRY STAYS, and the arithmetic is unchanged from the note
    # below: the flat ceiling is 3,000, so 3,280 lines have still to
    # leave, and an entry's slack is 2% of ITSELF - cutting deeper buys
    # LESS margin, not more. A subject per round. The seam left for the
    # next round is THE ENCRYPTED ARCHIVES (~400 contiguous at what is
    # now ~5,540 - the RAR5 store and `-hp` sidecar password probes and
    # the probe miss - plus scattered legs around `enc_store`).
    "crates/nzbfast/tests/e2e.rs": 6280,
    # 7165 when first measured, 7375, then 7629 after the 8 Aug burst.
    # Two concurrent sessions emptied it in turn, both on the
    # cleanup_mode_tests pattern: `trash_tests` + `out_umask_tests` to
    # smart/, then the 3,268-line inline `mod tests` to smart/tests.rs
    # + sweep_rename_tests.rs (one file of them would have been over
    # the ceiling on its own). 3,966 with both.
    # Regrown to 4,023 by 29 Aug 2026 - 22 lines under its own limit,
    # and out of test code to move: both rounds above emptied an inline
    # `mod tests`, and what is left is production. So this round takes
    # the first of two production seams. PUTTING A FINISHED JOB WHERE IT
    # BELONGS - `move_tree`'s rename, the staged copy it falls back to
    # across filesystems, `copy_tree`, the background-I/O demotion a NAS
    # copy runs under, the two error wrappers that name the failing
    # syscall, the collision reservation and the fsync ladder - is one
    # subject end to end and moved whole to smart/movetree.rs. The
    # surviving smart.rs names exactly ONE thing in it (`move_tree`, from
    # `tv_organize`), which is what made it a seam rather than a slice;
    # the five public doors are re-exported so no caller changed, and the
    # nine items smart/tests.rs reaches took `pub(super)`. 3,370 with it,
    # still over the ceiling, so a SECOND seam went in the same commit:
    # WHAT A FINISHED JOB'S FILES END UP CALLED, AND WHERE - `tv_organize`
    # and `tv_rename`, the three doors that give a name to a payload that
    # arrived without a usable one, and the four private helpers that
    # exist only for those five - to smart/filing.rs. The two are one
    # commit rather than the one-seam-per-commit shape daemon.rs's
    # burn-down used, and the reason is mechanical: this checkout is
    # shared and there is no safe way to stage half of one file, so
    # splitting the commit would have meant a smart.rs in the index that
    # matched neither the tree nor its own baseline. What a filed episode
    # is CALLED - EpisodeTitles, FiledTail, filed_bases, the
    # length-fitting - deliberately stayed behind: that is the vocabulary
    # and the delete path reads it too.
    # 2,772 - UNDER THE 3,000 CEILING, SO ITS ENTRY IS GONE, with 228
    # lines of margin rather than the ~67 that re-baselining after either
    # seam alone would have bought. The trash half (remove_user_* through
    # `delete_to_trash`, ~850 lines) is the obvious next seam and was NOT
    # taken: it moves the `TRASH` process-global and `mod deferred_trash`
    # across a module-unit boundary, which is a tools/test-global-gate.py
    # question rather than a size one, and the entry is off without it.
    # The narrative above is kept rather than deleted with the entry,
    # exactly as serve/tasks.rs's and daemon.rs's are.
    # One repair rode along: `move_tree`'s doc comment had been stranded
    # above `MOVE_SEQ` by an earlier hoist, and it is a shape
    # tools/doc-gate.py cannot see - the two blocks ABUT with no blank
    # line between them, so its scanner reads one block, not two.
    # 7081 when first measured; peaked at 10,828 during the fault/tuner
    # campaign. TODO 113 ratchet: the payout/safety rigs moved to
    # pool/rig_tests.rs (their own child module), 10,828 -> 7,855, then
    # the session_loop split (1,084 -> 461, its fn entry deleted) paid
    # ~170 lines of extraction overhead (signatures + docs): 8,011.
    # 8,282 after the §114 consumer-steer graduation merged over the
    # split (note_decoded seam + handed/steer-inbox plumbing; its rigs
    # live in rig_tests.rs, which absorbs the test growth), 8,492 after
    # the 8 Aug burst. The remaining inline `mod tests` - 2,443 lines,
    # a third of the file - moved to pool/inline_tests.rs: 6,051.
    # That left ONE line of margin under the limit, so the very next
    # commit to touch the file (§129 3g's response fence) put it back over
    # at 6,421, then 6,483 through the merge. Out of test code to move, so
    # this round took the production seam instead: one worker's whole
    # session lifecycle - dial, pipeline, read, and the dozen ways a
    # session ends - is 1,791 contiguous lines and moved whole to
    # pool/session.rs. 4,698, which is margin measured in hundreds of
    # lines rather than one. Regrown to 5,010 through the §146 tail
    # give-up + shipped-PoolConfig merges; the M11 QueueControl handle
    # (struct + whole impl) moved bodily to pool/queue.rs: 4,224. Regrown
    # to 4,350; the tail dup race and the B3 in-flight wire budget - how
    # the pool spends EXTRA wire on an article somebody else already
    # holds, and the bound on how much wire may be in flight - are the
    # tail of `impl Shared` and moved whole to pool/hedge.rs: 3,946.
    # Regrown to 4,121. This time the whole tail of the file below
    # `fetch_all_sharded` - the worker task, the spare filler, the
    # read-stall note, and every way a run is sealed or a work item
    # requeued/failed - is one subject (sealing) and moved whole to
    # pool/runlife.rs: 3,677. Regrown to 3,745 - five lines of margin -
    # so the Providers-card cap gauge could not land without a split:
    # everything the pool REPORTS rather than does (the per-server
    # gauges, the event ring, the two refusal records) is one subject
    # and moved whole to pool/livestats.rs: 3,365. Regrown to 3,432 -
    # its whole 2% of slack, so the §166-class handoff CLAIM counter
    # (26 Aug 2026) could not land without a split: `WorkerLife`, one
    # worker's lifetime in the fleet's two head-counts, moved whole to
    # pool/runlife.rs, which already owns `worker` (holds one for its
    # whole life) and `note_server_dark` (what both of its exits call):
    # 3,389.
    # Regrown to 3,455 by 29 Aug 2026 - ONE line under the limit, so the
    # next line anyone added to it reddened main. Fifteen rounds of this
    # file have taken a BEHAVIOUR seam out of `impl Shared`; the seam
    # left is not behaviour at all. `PoolConfig` is 406 lines of struct,
    # 80 of `Default` and 57 of `shipped()` - every knob the pool has,
    # its neutral posture and the one the daemon actually runs - with no
    # method that does work and no reference to any private pool item
    # except the type names in its own fields. It moved whole to
    # pool/config.rs and is re-exported, so `pool::PoolConfig` is spelled
    # exactly as it always was. `ConnTarget` stayed behind deliberately:
    # its own doc says the target is STATE and not configuration, and a
    # module named for the second must not quietly acquire the first.
    # 2,919 - UNDER THE 3,000 CEILING, SO ITS ENTRY IS GONE, which is
    # what a 543-line seam buys and a smaller one could not: an entry's
    # slack is 2% of ITSELF, so re-baselining at 3,455 would have handed
    # the next lane 69 lines and the same tripwire. The narrative above
    # is kept rather than deleted with the entry, exactly as
    # serve/tasks.rs's and daemon.rs's are.
    # rig_tests.rs was here at 2,988 (born in the TODO 113 split of the
    # pool's payout/safety rigs), then 3,125 when the §114 consumer-steer
    # rigs replaced the pool-gate ones, then 3,372 through the §129
    # fault campaign. Cut where its own subject changes: every leg that
    # runs MORE THAN ONE fault at a time - the gauntlet matrix, the
    # fight legs, early fanout, the hedge/dup races, live-target
    # parking, the 3g fence - is pool/fault_rigs.rs now. 1,988 lines,
    # under the ceiling, so its entry is GONE. The two shared rig
    # helpers are `pub(super)` and imported by path: a sibling cfg(test)
    # mod is not in scope through `use super::*`, but it is reachable by
    # name, so no third testkit module was needed.
    # 6,192, then 6,480 after the 8 Aug burst. Its 3,018-line inline
    # `mod tests` moved out and split at its own nested-one-pass banner
    # (mod_tests.rs + nested_tests.rs, neither big enough to want an
    # entry of its own): 3,467. Regrown to 3,550 on 13 Aug by the §160
    # plain-member repair and §156.1 chase-spill appends, past the slack.
    # Its instrumentation is one subject and left whole: the latched
    # shape bits with their token/English rendering and the nested
    # prevalence tally are extract/shape.rs now (326 lines, no entry of
    # its own): 3,242. Regrown to 3,302 - four lines of margin - so §94 A's
    # slot-owned name preclaim could not land without a split: the posted
    # file-NAMING rules (release_stem, vol_sort_key, is_final_file/name and
    # their FINAL_FILE_EXTS list) are pure functions over names with no
    # extractor state, one subject, and moved whole to extract/names.rs
    # (re-exported, so no caller changed): 3,196. Three lines of margin
    # again by 22 Aug (3,261 on a merged tree), so the delivery side of
    # `impl Extractor` - the plain write-through and name claim, forwarded
    # and routed delivery, the pending-queue flushes, the header stash and
    # the tail-prefetch promote - moved whole to extract/deliver.rs as a
    # second impl block: 2,712, under the ceiling, so its entry is GONE.
    # Regrown to 2,982 by 23 Aug - eighteen lines of margin, the tripwire
    # shape again - so the half deliver.rs names in its own first sentence
    # came out next: ROUTING, meaning piece-base resolution for split
    # continuations, the intersection of an arriving span with the
    # mapper's parsed data areas, the per-entry destination decision and
    # the writer/group bookkeeping it needs, is extract/routing.rs now
    # (643 lines, a third impl block, no entry of its own): 2,357. Seven
    # of its ten methods are called from sibling modules or the parent
    # and took `pub(super)`; nothing else changed.
    # serve/tasks.rs was here at 6,400 (6,056 when first measured, then
    # 6,213 from pre-gate concurrent work) and the 8 Aug merges took it to
    # 6,723 - past the slack, the only file-level offender left on main.
    # It has no inline `mod tests` to give up, so five PRODUCTION seams
    # came out whole to serve/tasks/: the metadata lanes (enrich.rs), the
    # watch folder and its six failure states (watchfolder.rs), index
    # upkeep either side of the scan loop (indexer.rs), the stall tracker
    # + slow-job watchdog (stall.rs), and connection tuning (tuner.rs).
    # 2,684 lines now - under the ceiling, so its entry is GONE. Both of
    # its fn entries below keep their path: spawn_download_worker and
    # spawn_index_scan stayed in the parent.
    # 5946 when first measured; pre-gate concurrent sessions landed 6106,
    # and the 5 Aug session union 6231 (event taxonomy, 5ab52b20), which
    # the §129 mover lane then owed a lowering it could not safely take
    # (the boot() extraction was rewriting the file at that moment). It
    # reached 6,465 instead. Two clusters of `impl Daemon` came out to
    # SIBLING modules, so `pub(super)` still means "pub in serve" and no
    # call site moved: what a finished job is called (out_dir,
    # rename_style, job_suffix, episode_titles, resolve_identity,
    # finalize_names) is serve/naming.rs, and the Daemon half of the
    # mover (move_dest_root, mover_enqueue/process, identify_video,
    # relocate_completed) went to serve/mover.rs beside the lanes that
    # call it. 5,570 - margin measured in hundreds of lines, which is
    # the lesson of the pool.rs round. Regrown to 5,714 through the D3
    # search-log and §73 preview merges; the whole `enqueue` add path
    # moved to daemon_enqueue.rs (a daemon child, the daemon_index
    # shape): 5,266. Regrown to 5,473; two more children on that same
    # shape took every way a job is sent round again (the M32 auto-retry
    # cooldown, the manual retry, and the move-retry ladder under both)
    # to daemon_retry.rs, and the queue on disk - save_queue out,
    # load_queue back - to daemon_persist.rs: 4,910. Regrown to 5,018;
    # two more children on the same shape took what each provider has
    # COST us (bytes billed per server per UTC day, the reliability
    # tally, and the §96.5 block-account arithmetic on top of both) to
    # daemon_usage.rs, and what the daemon does with connections when
    # nothing is downloading (the warm pool, the idle-release policy,
    # and the offline switch over the top) to daemon_idle.rs: 4,630.
    # Regrown to 4,748 - past the slack this time, and caught at a merge
    # rather than in the commit that spent the margin. TWO sessions then
    # split it in parallel; the lanes turned out to be disjoint (no
    # function moved twice, and daemon.rs auto-merged), so both are kept
    # rather than one backed out. How a JOB stops running is one subject
    # end to end (will_auto_retry, the failure report, the sidecar abort,
    # the delete quarantine, park into history, note_queue_idle,
    # save_giveup) and moved whole to daemon_park.rs, a seventh child on
    # the daemon_index shape. How the DAEMON stops is the other - the
    # graceful wind-down shared by mode=shutdown and SIGTERM/SIGINT, the
    # signal handlers over it, and the pause timer that stops the queue
    # only for a while (armed, persisted, restored across a restart) -
    # and moved whole to daemon_shutdown.rs, an eighth. Those are free
    # functions rather than a second `impl Daemon`, so that one is
    # re-exported from daemon.rs and every call site still names it
    # unqualified. 3,783 with both, still over the ceiling: entry stays.
    # ...and 3,859 by 24 Aug 2026, one line over its own limit, which is
    # what a file sitting at 3,857 does the moment anyone adds a field to
    # the Daemon struct - the §282 hunt's was the two lines that tripped
    # it, and any other lane's next two would have. What the UI says
    # about a server granting no sessions (server_down_secs, the
    # ServerOutage row, row_outage's token and the server_outages census)
    # is one subject, owes nothing to the Daemon struct it was sitting
    # beside, and moved whole to outage.rs - a ninth child on the
    # daemon_index shape, re-exported so every call site still names it
    # unqualified. 3,764, so the entry ratchets DOWN.
    # ...and regrown to 3,821, which left 18 lines of headroom - under
    # one ordinary function, and the state that let this file cross on
    # 25 Aug by MERGE ARITHMETIC rather than by anyone's commit.
    # 68df57712 combined two sides at 3,837 and 3,810, BOTH legitimately
    # under the ceiling, into 3,849; every author ran this gate and saw
    # green, truthfully, on the tree they held, and no lane could have
    # seen that red from its own branch. Written up in
    # research/SIZE-GATE-DAEMON-RS-2026-08-25.md, whose sharper lesson is
    # that the gate belongs INSIDE the fetch/merge/push retry loop,
    # because on a main taking a push every ~90 s the merge that ships is
    # not the merge you tested. WHEN INDEX MAINTENANCE MAY RUN is one
    # subject asked at three ranges - the two "is this a moment for it"
    # predicates, the VACUUM disk-space verdict, and the arm/abort
    # rendezvous that stands down a statement ALREADY executing, which
    # the other two structurally cannot reach - and all three moved to
    # daemon_maint.rs, by two lanes an hour apart who could not see each
    # other (ae6d4e5a6 took the rendezvous, the follow-on took the rest
    # into the same module rather than beside it). 3,608.
    # WORTH READING BEFORE THE NEXT LANE REACHES FOR THIS LINE: an
    # entry's slack is 2% of ITSELF, so re-baselining after a split buys
    # about 70 lines and NO cohesive split of any size buys more while
    # the entry exists. Real headroom is DELETING the entry, which needs
    # the file under FILE_CEILING - about 600 lines further. The seams
    # are there and none of them is a shave: category/dir routing
    # (CatMeta, cat_list, register_cat, cat_dir, base_out_dir,
    # dir_claim), the auto-speed ceiling with the live rate and cpu
    # readings, the bounded index read pool at the top of the file, and
    # suspend/pause. Each is its own module on this same seam.
    # THAT BURN-DOWN IS UNDER WAY, one seam per commit so a lost push
    # race is re-merged on a small diff rather than a huge one. The
    # BOUNDED READ POOL went first and did not become a new child: its
    # types exist for `index_read_acquire`, which has lived in
    # daemon_index.rs since that module was split off, and nothing else
    # in the tree names `Reader`, `IndexReader` or `IndexReadState`. So
    # they moved INTO daemon_index.rs, which costs daemon.rs no `mod`
    # declaration back and makes three of the four types module-private
    # where a sibling module would have had to widen them. 3,518.
    # Then WHICH CATEGORY A JOB IS, AND WHICH DIRECTORY IT LANDS IN to
    # daemon_cats.rs - the offered set and its defaults, the
    # per-category overrides, `cat_dir`/`base_out_dir`, and the
    # `dir_claim` a candidate path is tested against. One module and not
    # two because the routing half READS the category half: a category's
    # `dir` override is the entire difference between `cat_dir` and
    # `out_dir().join(category)`, and computing the second where the
    # first was meant is what silently re-parented every renamed payload
    # out of the folder the user configured. 3,351.
    # Then HOW FAST THE LINE IS RUNNING, WHAT IT COSTS AND WHAT CEILING
    # IS IMPOSED ON IT to daemon_speed.rs - `current_speed_bps`,
    # `cpu_pct`, the `set_speed_ceiling*` door every manual/API/schedule
    # cap goes through, and `auto_speed_step` with its four constants.
    # One module because the halves are WIRED: the AIMD governor
    # deliberately bypasses `set_speed_ceiling_from` so its per-second
    # steps cannot flood the event ring or bump `queue_rev` on a hot
    # path, a claim stated twice in that method and checkable only
    # against the governor, which is now on the same screen. 3,217.
    # Then WINDING DOWN THE RUNNING TRANSFER WITHOUT ENDING THE JOB to
    # daemon_suspend.rs. Its own child and not folded into either
    # neighbour: daemon_park is how a job stops FOR GOOD, daemon_shutdown
    # is how the DAEMON stops plus the queue-wide pause timer, and this
    # is per-JOB and reversible - the job stays in the queue and resumes
    # from the article journal. Five of its seven callers (the pause
    # button, the *arr remote, the scheduler, the slow-disk hold, the
    # idle-release policy) are in neither of those files. 3,076.
    # And finally MAY A BACKGROUND INDEX PASS RUN RIGHT NOW, AND HOW
    # DOES IT SAY WHY NOT to daemon_indexgate.rs - the two per-source
    # stand-down reasons, the phrase the log prints, the cheap
    # is-a-download-imminent both reasons share, whether anything wants
    # the database open, and `begin_index_job`, which is the WRITE end
    # of the same rendezvous: it raises the very counter both reasons
    # read. 2,945.
    # UNDER THE 3,000 CEILING, SO ITS ENTRY IS GONE - which is the whole
    # point of the six commits above and the thing a further split of
    # any size could not buy. An entry's slack is 2% of ITSELF, so
    # re-baselining after a split leaves ~70 lines of headroom whatever
    # the split's SIZE, and daemon.rs spent a year regrowing into that
    # 70 and crossing again, most recently by MERGE ARITHMETIC between
    # two lanes who each saw a green gate on their own branch
    # (research/SIZE-GATE-DAEMON-RS-2026-08-25.md). It is now held to
    # the same ceiling as every other file and stops being special.
    # The narrative above is kept rather than deleted with the entry,
    # exactly as serve/tasks.rs's is: it is the record of which subject
    # went where, and the next lane reaching for this file needs it.
    # ONE FURTHER SEAM WENT THE SAME DAY, for margin rather than for the
    # entry: WHICH OF THE USER'S INDEXER ACCOUNTS A BACKGROUND LANE
    # SPEAKS TO, to daemon_indexref.rs. Crossing at 2,945 left 55 lines
    # under the ceiling, and 55 is inside the range two ordinary lanes
    # add between them - which is the merge arithmetic this whole
    # burn-down exists to stop, arriving through the plain ceiling
    # instead of through a baseline. 2,820: margin measured in hundreds,
    # which is the lesson of the pool.rs round.
    # 5,150, then 5,397 after the 8 Aug burst. The inline `mod tests`
    # (the repair math and the mapped driver) moved to
    # par2repair/inline_tests.rs, beside unit_tests.rs: 4,206. Regrown
    # to 4,337 through the 133.1 self-prove and Codex-sweep merges;
    # `impl Reconstructor` moved whole to par2repair/reconstruct.rs
    # (a child of the defining module, so the private fields stay in
    # scope): 3,791. Then extra-file adoption - the candidate walk, the
    # whole-file fast path and the sliding scan - went the same way to
    # par2repair/adopt.rs when R2 fanned it out across candidates:
    # 3,596. Still over the ceiling, so the entry stays, ratcheted.
    # Regrown to 3,662 by 29 Aug 2026 - FIVE lines under its own limit,
    # which refused an unrelated 32-line addition that day; the two
    # recovery-slice finders went to par2repair/slices.rs (cca7c1f42) to
    # get that commit in at all, and that bought ten lines. This round is
    # the fix rather than the stopgap. THE GF(2^16) ARITHMETIC - folding
    # present slices into syndromes (fold_chunk_tiled/_multi, the tile
    # geometry constants, fold_parallel, FeedBatch, fold_batches) and
    # inverting the repair matrix (invert_vandermonde and the
    # Gauss-Jordan pair behind it) - moved whole to par2repair/linalg.rs.
    # The pairing was already in the tree: `bench_fold` and `bench_invert`
    # are the crate's two benchmark doors, one per half, and
    # examples/par2_fold_bench.rs drives both; they are re-exported, so no
    # example changed. Neither half opens a file, parses a packet or knows
    # what a recovery set is.
    # WHICH ENGINE computes the syndromes stayed behind, deliberately -
    # the NTT gates, the divergence probe, `run_with_ntt_fallback` and the
    # `FAST_PAR_*` process-globals are a policy question answered before
    # any arithmetic runs, and moving them would move a contested global
    # (tools/test-global-gate.py's `FAST_PAR_TRIPPED` family) across a
    # module-unit boundary for no size reason.
    # 2,868 - UNDER THE 3,000 CEILING, SO ITS ENTRY IS GONE. The narrative
    # above is kept rather than deleted with the entry, exactly as
    # serve/tasks.rs's and daemon.rs's are.
    # rar.rs was here at 4,088 and reached 4,363 as the shatter-fold and
    # fuzz-crash rounds landed. Its inline `mod tests` (1,255 lines) moved
    # to rar/tests.rs beside v4_header_tests.rs, and the fixture writers
    # (a public module, its `nzbkit::rar::fixtures` path unchanged) to
    # rar/fixtures.rs. 2,494, under the ceiling, so its entry is GONE.
    # 3688 when first measured; the 20 Aug takedown-classifier round
    # pushed it past the slack, so `mod compress_tests` (518 lines)
    # moved whole to nntp/compress_tests.rs, the unit_tests pattern.
    # 3339 with it, so the entry ratchets DOWN.
    # By 26 Aug 2026 it had regrown into the last line of that slack -
    # 3,405 against a 3,405 limit, so the unsafe-policy ratchet (TODO 307
    # item 3) could not add a three-line `// SAFETY:` note to
    # `set_keepalive` without reddening this gate. `mod capped_read_tests`
    # (68 lines) moved out-of-line to nntp/capped_read_tests.rs, which is
    # the pattern the five `mod *_tests;` declarations at the foot of that
    # file already are. 3,349 with the note in. The baseline stays 3339:
    # it is the recorded low and only ever goes down.
    # Regrown to 3,396 by 29 Aug 2026 - NINE lines under its own limit,
    # the tightest of the six baselined files, on a file taking a couple
    # of commits a day. Both rounds above bought that margin by moving
    # TEST code, and there was no third `mod *_tests` big enough to buy
    # it again, so this one took the production seam instead: everything
    # about the TLS SESSION rather than about NNTP - the suite and
    # trust-anchor policy (aes_accelerated/is_chacha/is_aes128/
    # tls_provider), the extra-CA path and the root store, the shared
    # `ClientConfig` cache keyed on both, the handshake ladder, the
    # `probe_tls` diagnostic, and the Linux kernel offload with its
    # `probe_tls` diagnostic - moved whole to nntp/tls.rs, beside the
    # tlswire.rs that already owns the socket UNDER rustls, and the Linux
    # kernel offload with its `KtlsWire` to nntp/ktls.rs beside it.
    # `Connection` reached into that whole 776-line region exactly three
    # times (tls_full_host, mark_tls_full_host, tls_handshake), which is
    # what made it one subject rather than a slice: those three took
    # `pub(super)` and the three PUBLIC doors (set_extra_ca,
    # shared_tls_client_config, probe_tls) are re-exported, so no caller
    # anywhere changed. THE KERNEL OFFLOAD IS ITS OWN CHILD and not a
    # block inside tls.rs, which is a judgement worth keeping: it is one
    # platform and one cargo feature, so the `#[cfg]` moves to the `mod`
    # declaration and every item inside sheds its own copy - and folding
    # it in instead put `KtlsWire::new` in a file whose only other `fn
    # new` it was, which is a shape tools/cfg-symbol-gate.py mis-resolves
    # (its same-file arm does not look at the qualifier, so every
    # `OnceLock::new()` and `Arc::new()` in the file then reads as a
    # linux-only call). Reported separately; the seam here is the better
    # one either way. 2,628 -
    # UNDER THE 3,000 CEILING, SO ITS ENTRY IS GONE, which is the whole
    # point of taking a 776-line seam rather than a 400-line one: an
    # entry's slack is 2% of ITSELF, so re-baselining at 3,396 would have
    # bought 67 lines and left the next lane exactly where this one was.
    # The narrative is kept rather than deleted with the entry, exactly
    # as serve/tasks.rs's and daemon.rs's are: it is the record of which
    # subject went where.
    # release.rs was here at 3,505 and reached 3,586 as the dark-verdict
    # and year-is-an-extension rounds landed. Its inline `mod tests` was
    # 1,427 lines - nearly half the file - and moved whole to
    # release_tests.rs (the mock.rs pattern). 2,159, under the ceiling,
    # so its entry is GONE.
    # extract/crypto.rs was here at 3,365 and reached 3,502. Its inline
    # `mod tests` moved to extract/crypto_tests.rs, leaving 2,112 - under
    # the ceiling, so its entry is GONE.
    # repair.rs was here at 3,305 and reached 3,362 - nine lines of slack
    # left. The recovery-volume side-fetch driver (its own banner in the
    # module doc: the side pool, the volume consumer, the two helpers
    # that price a volume) moved to repair/sidefetch.rs with its tests,
    # leaving 2,909 - under the ceiling, so its entry is GONE too.
}

BASELINE_FNS = {
    # "path::fn_name": lines measured
    # spawn_download_worker was here at 688, then 719, then 770 from
    # pre-gate concurrent work, and reached 831 as the §154 no-servers
    # hold and the §96.5 block-account budgets landed inside it. Three
    # self-contained stretches of the loop moved to serve/tasks/runner.rs:
    # the M14g guard ladder (`download_guards`, which sleeps on the
    # caller's behalf and answers `only_force` or "do not pick"), the
    # per-job hub hand-over (`reset_hub_for_job`), and the figures read at
    # network-drain before the next iteration zeroes them
    # (`settle_job_tail`). 417 lines now - under the ceiling, so its entry
    # is GONE.
    # queue_json was here at 652, then 670 after the 8 Aug burst. `resume_at`
    # and the watch_failed row builder came out whole (609), and the lane's
    # own comment trim (61537f5d) merged over it: 604. The #34 SAB-parity
    # round then took it to 782 in one commit - it added ~30 keys to the
    # slot and ~25 to the header. Two more self-contained blocks came out:
    # the whole queue ROW (`slot_json` + the `SlotCtx` snapshot it is built
    # against - it reads no daemon state of its own), and the six notice
    # rings (`queue_notices`). 475 now - under the ceiling, so its entry
    # is GONE.
    # spawn_index_scan was here at 582 and reached 648 - the §131 spot
    # legs landed inside it. Four self-contained blocks of its pass moved
    # to serve/tasks/indexer.rs, where the rest of the index upkeep
    # already lives: the Spotnet scan + promote leg (spot_pass), the
    # category reconcile (reclassify_pending_rows), the retention prune
    # and planner-statistics refresh (retention_and_statistics), and the
    # size-cap eviction (evict_pass_and_republish). 316 lines now - under
    # the ceiling, so its entry is GONE.
}


# The two limit rules, factored out of main() so the REPORT and the VERDICT
# cannot drift apart. A report that disagrees with the gate it ships inside
# is worse than no report: it is a wrong number carrying the gate's
# authority, which is exactly the class of defect the split chips already
# hit by computing these by hand. Both return the same expression main()
# used before, unchanged, plus the name of the regime it came from.
def file_limit(path):
    """(limit, kind) for a file. kind is 'flat' or 'baselined'."""
    if path in BASELINE_FILES:
        return int(BASELINE_FILES[path] * SLACK), "baselined"
    return FILE_CEILING, "flat"


def fn_limit(key):
    """(limit, kind) for a `path::name` production function key."""
    if key in BASELINE_FNS:
        return int(BASELINE_FNS[key] * SLACK), "baselined"
    return FN_CEILING, "flat"


def split_gain(size, free, kind, ceiling):
    """Headroom a split can BUY, at its very best. None means 'line for line'.

    This is the whole point of the report and it is not symmetric.

    FLAT: the limit is a constant, so every line removed is a line of
    headroom gained, without bound. None.

    BASELINED: the house convention on every historical entry is to ratchet
    the baseline down to the file's new exact size in the same commit as the
    split (daemon.rs: 11,803 -> 11,590 -> 11,517 -> 10,466 -> 10,030 ->
    9,132). So after cutting k lines the new free is
    `int((size-k)*SLACK) - (size-k)`, which is MAXIMISED AT k=0 and falls
    from there - the gain is best for the smallest possible split, which is
    the tell that splitting is not a lever at all here. Returns that maximum
    minus what is already free, so 0 means a split buys nothing.

    The one escape is driving the target under the flat ceiling outright, at
    which point the entry is deleted and the regime changes; `to_flat` in the
    row says how many lines that is.
    """
    if kind != "baselined":
        return None
    best = int(size * SLACK) - size
    if size <= ceiling:
        # Already under the flat ceiling: the gate refuses the stale entry
        # rather than applying it, so there is nothing to model.
        return None
    return best - free


CFG_TEST = re.compile(r"\s*#\[cfg\(test\)\]")
# The `#[path = "x_tests.rs"] mod x_tests;` hook puts an attribute between
# the cfg and the mod, and the old pattern stopped dead at it - every file
# attached that way was scored as PRODUCTION code, so a long table-driven
# test in one would have tripped the fn ceiling for no reason. Tolerate any
# run of attributes in between.
CFG_TEST_MOD = re.compile(
    r"\s*#\[cfg\(test\)\]\s*(?:\n\s*)?(?:#\[[^\]]*\]\s*(?:\n\s*)?)*"
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;"
)
FN_START = re.compile(
    r"(?:^|[\s{}();])(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?"
    r"(?:async\s+)?(?:unsafe\s+)?(?:extern\s*\"[^\"]*\"\s+)?fn\s+(\w+)"
)


def strip_noise(text):
    """Blank strings and comments, preserving line structure and braces.

    A real tokenizer, not a per-line regex: the 3 Aug offender list was built
    with a per-line version and stopped dead at the first multi-line string
    with an unbalanced brace, silently dropping the biggest function in the
    repo from its own report. Handles nested block comments, escapes, raw
    strings (r#".."#, b"..", br#".."#), and char-literal-vs-lifetime.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            depth, i = 1, i + 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth += 1
                    i += 2
                elif text.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    if text[i] == "\n":
                        out.append("\n")
                    i += 1
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 1
                elif text[i] == "\n":
                    out.append("\n")
                i += 1
            i += 1
        elif c in "rb" and re.match(r'(?:r#*"|br#*"|rb#*"|b")', text[i:]):
            m = re.match(r'(?:b?r)(#*)"', text[i:])
            if m:  # raw string: ends at "### with the same hash count
                hashes = m.group(1)
                i += m.end()
                end = text.find('"' + hashes, i)
                end = n if end == -1 else end + 1 + len(hashes)
                out.extend("\n" * text.count("\n", i, end))
                i = end
            else:  # b"..." plain byte string
                i += 2
                while i < n and text[i] != '"':
                    if text[i] == "\\":
                        i += 1
                    elif text[i] == "\n":
                        out.append("\n")
                    i += 1
                i += 1
        elif c == "'":
            m = re.match(r"'(?:\\[^']*|[^'\\])'", text[i:])
            if m:  # char literal; otherwise a lifetime - keep scanning
                i += m.end()
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def test_line_mask(clean_lines):
    """True for every line inside an inline `#[cfg(test)]` block.

    A BRACE-LESS item has to end at its `;`. This scanner used to end an
    item only on braces, so `#[cfg(test)] static DUPE_ADMIT_BARRIER: ...;`
    and `#[cfg(test)] mod lane_tests;` - which open no block at all - ran
    on to the next `{` the file could offer, which is the body of whatever
    came NEXT, and masked it as test code. Measured 22 Aug 2026: 58 files
    carried a wrong mask, 24 functions were scored as test code that are
    production, and one of them was over the ceiling and hidden by it -
    `Daemon::enqueue`, 575 lines, with the brace-less static declared
    directly above its `impl` block. That is the same defect tools/
    lock-gate.py carried; both scanners are the same resolver family and
    the fix is the same one.
    """
    mask = [False] * len(clean_lines)
    i = 0
    while i < len(clean_lines):
        if CFG_TEST.match(clean_lines[i]):
            depth, started, ended, j = 0, False, False, i
            while j < len(clean_lines):
                s = clean_lines[j]
                depth += s.count("{") - s.count("}")
                if "{" in s:
                    started = True
                if started and depth <= 0:
                    ended = True
                    break
                # No block was ever opened, so this is a `static`/`const`/
                # `use`/`mod` declaration and its `;` is the whole of it.
                if not started and ";" in s:
                    ended = True
                    break
                j += 1
            if ended:
                for k in range(i, min(j + 1, len(clean_lines))):
                    mask[k] = True
                i = j + 1
                continue
        i += 1
    return mask


def functions(clean_lines):
    """Yield (name, start_line_0based, span_lines) for every fn with a body."""
    text = "\n".join(clean_lines)
    line_of = []
    ln = 0
    for ch in text:
        line_of.append(ln)
        if ch == "\n":
            ln += 1
    for m in FN_START.finditer(text):
        # Scan from the signature to the first `{` or `;`. A `;` first means
        # a trait method declaration or extern item - no body, no entry.
        j = m.end()
        while j < len(text) and text[j] not in "{;":
            j += 1
        if j >= len(text) or text[j] == ";":
            continue
        depth = 0
        k = j
        while k < len(text):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        start = line_of[m.start(1)]
        end = line_of[min(k, len(text) - 1)]
        yield m.group(1), start, end - start + 1


def collect():
    contents = {}
    for root, _dirs, files in os.walk(CRATES):
        if f"{os.sep}fuzz{os.sep}" in root + os.sep:
            continue
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(root, f)
            contents[p] = open(p, encoding="utf8", errors="replace").read()

    test_files = set()
    clean = {p: strip_noise(t).split("\n") for p, t in contents.items()}
    for p, lines in clean.items():
        for name in CFG_TEST_MOD.findall("\n".join(lines)):
            d = os.path.dirname(p)
            base = p[:-3]
            for cand in (os.path.join(d, name + ".rs"), os.path.join(base, name + ".rs")):
                if cand in contents:
                    test_files.add(cand)

    files_out = []  # (path, raw_lines)
    fns_out = []  # (path, name, line_1based, span, is_test)
    for p, text in contents.items():
        # NB: this reads one HIGHER than `wc -l` on newline-terminated
        # text, so a file `wc` calls 3,000 lines is 3,001 to the ceiling
        # test below and FAILS. Measure headroom with the gate, not with
        # wc. Undocumented until 23 Aug 2026, by which time it had cost
        # two sessions in one evening - one mid-push, one misreading the
        # cause as the `.split("\n")` in `clean` above, which yields the
        # same number but feeds `#[cfg(test)]` scope resolution and
        # never reaches the ceiling. Do not "fix" either: the scope
        # resolver is what --selftest pins.
        files_out.append((p, text.count("\n") + 1))
        whole_file_is_test = (
            f"{os.sep}tests{os.sep}" in p or f"{os.sep}benches{os.sep}" in p or p in test_files
        )
        mask = test_line_mask(clean[p])
        for name, start, span in functions(clean[p]):
            is_test = whole_file_is_test or (start < len(mask) and mask[start])
            fns_out.append((p, name, start + 1, span, is_test))
    return files_out, fns_out


def largest_prod_fns(fns):
    """{path::name: (span, line)} for production fns - main()'s own reduction.

    A name can appear more than once in a file (two `impl` blocks, a cfg
    pair); main() gates the LARGEST, so the report must score the largest
    too or it would report a margin the gate does not use.
    """
    out = {}
    for p, name, line, span, is_test in fns:
        if is_test:
            continue
        key = f"{p}::{name}"
        if span > out.get(key, (0, 0))[0]:
            out[key] = (span, line)
    return out


def _row(label, size, limit, kind, ceiling):
    free = limit - size
    return {
        "label": label,
        "size": size,
        "limit": limit,
        "free": free,
        "kind": kind,
        "gain": split_gain(size, free, kind, ceiling),
        # Lines that would have to come off for a baselined target to drop
        # under the flat ceiling, which DELETES its entry and changes the
        # regime. None where that does not apply.
        "to_flat": (size - ceiling) if kind == "baselined" and size > ceiling else None,
    }


def headroom_rows(files, fns):
    """(file_rows, fn_rows), each sorted by free ASCENDING.

    Ascending, so line 1 is the thing about to redden main. `--list` sorts
    by SIZE, which ranks a 500-of-500 function below a 400-of-9,000 one.
    """
    frows = [_row(p, n, *file_limit(p), FILE_CEILING) for p, n in files]
    nrows = []
    for key, (span, line) in largest_prod_fns(fns).items():
        p, name = key.rsplit("::", 1)
        nrows.append(_row(f"{p}:{line}  {name}", span, *fn_limit(key), FN_CEILING))
    # Deterministic: tightest first, then biggest, then by name.
    def keyf(r):
        return (r["free"], -r["size"], r["label"])

    return sorted(frows, key=keyf), sorted(nrows, key=keyf)


HEADROOM_LEGEND = """  The two ceilings are different IN KIND, not in degree. Read this before
  pricing any split, and never pair a tight flat row with a tight baselined
  one as though they were one problem.
  flat      = the {ceiling:,}-line ceiling. A split converts LINE FOR LINE into
              headroom: take N lines out and there are N more.
  baselined = the limit is the recorded baseline x {slack}, and the house ratchet
              re-centres that same 2% on the new size, so a split does NOT
              convert. The `^` note under each such row is the MOST any split
              can buy, and it SHRINKS as the split grows - the gain is
              maximised by the smallest possible split, which is the tell that
              splitting is not a lever here. {remedy}"""

FILE_REMEDY = (
    "Send new rows to a child\n              module instead (tests/daemon.rs already has 39), or drive the\n"
    "              file under the flat ceiling outright, which deletes the entry."
)
FN_REMEDY = (
    "Lift self-contained stretches out to\n              sibling functions until the body is under the flat ceiling, which\n"
    "              deletes the entry."
)


def narrowest_line(frows, nrows):
    """The tightest file and the tightest production fn, as one line.

    The gate is PASS/FAIL, so its clean line said nothing about how close
    anything was - and this class recurred five times in the four days to
    31 Aug 2026, twice reddening main outright, every instance found by a
    human running `--list` and doing the subtraction by hand. Nobody runs
    `--list` on a push; everybody runs the gate. So the number rides on the
    line the gate ALREADY prints.

    It is deliberately NOT a warn tier. A refusal at some threshold is a
    real judgement with a real trade - a gate red for a reason nobody can
    act on gets loosened until it means nothing, and a warning nobody must
    act on decays the same way - and that decision is not this patch's to
    make. This is a number on a line that was already there.
    """
    bits = []
    for tag, rows in (("file", frows), ("fn", nrows)):
        if not rows:
            continue
        r = rows[0]
        # The fn label is column-padded for the table; collapse it inline.
        label = " ".join(r["label"].split())
        bits.append(f"{tag} {label} {r['free']:,} free of {r['limit']:,}")
    if not bits:
        return None
    return "  narrowest: " + "; ".join(bits) + "  (`--headroom` for the rest)"


def print_headroom(title, rows, top, ceiling, remedy):
    print(f"=== {title} (headroom ascending) ===")
    print("     free      size     limit  used  ceiling")
    shown = rows[:top]
    # A baselined target is the one this report exists to distinguish, and it
    # does NOT reliably rank near the top: its free is up to 2% of a large
    # size, so on 31 Aug 2026 neither baselined FILE was in the tightest
    # twelve while every flat row above them was under 100 lines. Cutting
    # them off at the fold would hide exactly the class the reader came for.
    cut = [r for r in rows[top:] if r["kind"] == "baselined"]
    for r in shown + cut:
        # FLOOR, never round: 2,990 of 3,000 rounds to 100% and reads as
        # "at the limit" when there are ten lines left. Only an exact 100%
        # may print 100.
        used = int(100 * r["size"] / r["limit"]) if r["limit"] else 0
        print(
            f"  {r['free']:7,}  {r['size']:8,}  {r['limit']:8,}  {used:3d}%  "
            f"{r['kind']:<9}  {r['label']}"
        )
        if r["kind"] == "baselined":
            gain = "buys nothing" if not r["gain"] else f"buys at most +{r['gain']:,}, and less the bigger it is"
            flat = (
                f"; {r['to_flat']:,} lines takes it under the {ceiling:,} ceiling and deletes the entry"
                if r["to_flat"]
                else ""
            )
            print(f"             ^ a split+ratchet {gain}{flat}")
    if cut:
        print(f"  ({len(cut)} baselined row(s) shown from below the fold - see the legend)")
    print(HEADROOM_LEGEND.format(ceiling=ceiling, slack=SLACK, remedy=remedy))


def report_headroom(top=25):
    files, fns = collect()
    frows, nrows = headroom_rows(files, fns)
    # Failing to find is failing: an inert scanner shows a zero rather than
    # a clean-looking report. Both corpora are in the thousands on this tree.
    if not frows or not nrows:
        print(
            f"size-gate: --headroom reached {len(frows)} file(s) and {len(nrows)} production "
            "fn(s) - run it from the repo root; a report over nothing is not a report.",
            file=sys.stderr,
        )
        return 1
    print_headroom("files closest to their ceiling", frows, top, FILE_CEILING, FILE_REMEDY)
    print()
    print_headroom("production fns closest to their ceiling", nrows, top, FN_CEILING, FN_REMEDY)
    print(f"\n  ({len(frows):,} files, {len(nrows):,} production fns scored)")
    return 0


# (name, fn name, expected is_test, source). The BRACE-LESS cases are the
# ones that motivated the fix in test_line_mask: each of them scores
# is_test=True against the brace-only scanner this gate shipped with, which
# exempts a production function from FN_CEILING outright.
SELFTEST = [
    (
        "a plain production fn",
        "big",
        False,
        "fn big() {\n    let x = 1;\n}\n",
    ),
    (
        "a fn inside a real #[cfg(test)] mod block",
        "counts",
        True,
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn counts() {\n        assert!(true);\n    }\n}\n",
    ),
    (
        "a production fn AFTER a #[cfg(test)] mod block, which must not be swallowed",
        "big",
        False,
        "#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n\nfn big() {\n    let x = 1;\n}\n",
    ),
    (
        "daemon_enqueue's shape: a brace-less #[cfg(test)] static above an impl",
        "enqueue",
        False,
        "#[cfg(test)]\n"
        "pub(in crate::serve) static DUPE_ADMIT_BARRIER: Mutex<\n"
        "    Option<(String, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,\n"
        "> = Mutex::new(None);\n"
        "\n"
        "impl Daemon {\n"
        "    fn enqueue(&self) -> Result<String> {\n"
        "        Ok(String::new())\n"
        "    }\n"
        "}\n",
    ),
    (
        "the same, for a `#[cfg(test)] mod foo;` child declaration",
        "dest_root",
        False,
        "#[cfg(test)]\nmod lane_tests;\n\nfn dest_root() -> u8 {\n    0\n}\n",
    ),
    (
        "a brace-less #[cfg(test)] use, which is also test scope itself",
        "prod",
        False,
        "#[cfg(test)]\nuse std::sync::Barrier;\n\nfn prod() {\n    let x = 1;\n}\n",
    ),
]

# The tokenizer half. `strip_noise` is what kept the 3 Aug offender list
# honest, and a brace inside a string or a comment is the thing that broke
# the version before it - so both are asserted here rather than assumed.
SELFTEST_NOISE = [
    (
        "a brace inside a string literal does not open a block",
        'fn f() {\n    let s = "}{";\n    let y = 1;\n}\nfn g() {\n    let z = 1;\n}\n',
        {"f": 4, "g": 3},
    ),
    (
        "a brace inside a raw string does not open a block",
        'fn f() {\n    let s = r#"} { "#;\n}\nfn g() {\n    let z = 1;\n}\n',
        {"f": 3, "g": 3},
    ),
    (
        "a brace inside a comment does not open a block",
        "fn f() {\n    // }\n    let y = 1;\n}\nfn g() {\n    let z = 1;\n}\n",
        {"f": 4, "g": 3},
    ),
]


# Floors for the --headroom real-tree pin below. Comfortably under the tree
# as measured 31 Aug 2026 (775 files, 6,674 production fns) and enormously
# over zero: what this refuses is a report that has quietly stopped reaching
# anything, which reads as a clean tree forever.
HEADROOM_FILE_FLOOR = 500
HEADROOM_FN_FLOOR = 4000

# Fixture corpus for the headroom row builder: (path, raw lines) plus the
# baselines to score it against. Sizes are chosen so both regimes appear and
# so ordering is unambiguous.
HEADROOM_FIXTURE_FILES = [
    ("crates/a/flat_tight.rs", 2990),  # flat, 10 free
    ("crates/a/flat_roomy.rs", 100),  # flat, 2,900 free
    ("crates/a/based.rs", 9184),  # baselined 9,132 -> limit 9,314, 130 free
]
HEADROOM_FIXTURE_BASE = {"crates/a/based.rs": 9132}

# Number of assertions in selftest_headroom(). Printed on a green run so a
# case deleted to quiet a mutation shows up in the output - the count is the
# only thing that can report an arm removed rather than fixed.
HEADROOM_CASES = 27

# Same convention, for selftest_argv() below.
ARGV_CASES = 6


def selftest_headroom():
    """Pin the --headroom report: the arithmetic, the asymmetry, the counts.

    The arithmetic cases are deliberately written against LITERAL expected
    numbers rather than against the module's own expressions - a pin that
    recomputes what it is pinning proves nothing.
    """
    bad = 0
    ran = 0

    def check(ok, msg):
        """One assertion. Counted whether it passes or fails, so HEADROOM_CASES
        below can refuse a case that was DELETED rather than fixed."""
        nonlocal bad, ran
        ran += 1
        if not ok:
            print(f"  selftest FAIL: {msg}", file=sys.stderr)
            bad += 1

    def fail(msg):
        nonlocal bad, ran
        ran += 1
        print(f"  selftest FAIL: {msg}", file=sys.stderr)
        bad += 1

    # 1. The two limit rules, both regimes, both tables.
    saved_f, saved_n = dict(BASELINE_FILES), dict(BASELINE_FNS)
    try:
        BASELINE_FILES.clear()
        BASELINE_FILES.update({"crates/a/based.rs": 9132})
        BASELINE_FNS.clear()
        BASELINE_FNS.update({"crates/a/x.rs::big": 700})
        check(
            file_limit("crates/a/flat.rs") == (3000, "flat"),
            f"file_limit on an unlisted file gave {file_limit('crates/a/flat.rs')}, wanted (3000, 'flat')",
        )
        check(
            file_limit("crates/a/based.rs") == (9314, "baselined"),
            f"file_limit on a baselined file gave {file_limit('crates/a/based.rs')}, wanted (9314, 'baselined')",
        )
        check(
            fn_limit("crates/a/x.rs::small") == (500, "flat"),
            f"fn_limit on an unlisted fn gave {fn_limit('crates/a/x.rs::small')}, wanted (500, 'flat')",
        )
        check(
            fn_limit("crates/a/x.rs::big") == (714, "baselined"),
            f"fn_limit on a baselined fn gave {fn_limit('crates/a/x.rs::big')}, wanted (714, 'baselined')",
        )

        # 2. THE ASYMMETRY, which is the whole reason this mode exists.
        # Flat converts line for line, so there is no bound to model.
        check(
            split_gain(2990, 10, "flat", FILE_CEILING) is None,
            "split_gain on a flat target must be None (line for line), not a number",
        )
        # Baselined: size 9,184 with 130 free can reach int(9184*1.02)-9184 =
        # 183 by ratcheting alone, so a split buys at most 53.
        check(
            split_gain(9184, 130, "baselined", FILE_CEILING) == 53,
            f"split_gain(9184, 130, baselined) gave "
            f"{split_gain(9184, 130, 'baselined', FILE_CEILING)}, wanted 53",
        )
        # ...and it SHRINKS as the split grows. This is the falsifiable form
        # of the finding: a bigger split is a WORSE outcome, which is why
        # splitting a baselined target is not a lever at all. Each split is
        # modelled by ratcheting the baseline to the post-split size, which
        # is what every historical entry in BASELINE_FILES actually did.
        gains = [int((9184 - k) * SLACK) - (9184 - k) for k in (0, 500, 1000, 2000)]
        check(
            gains[0] > gains[1] > gains[2] > gains[3],
            f"the split-gain curve must FALL as the split grows; measured {gains}",
        )
        # A baselined target already under the flat ceiling has a stale entry
        # the gate refuses outright, so there is nothing to model.
        check(
            split_gain(100, 2, "baselined", FILE_CEILING) is None,
            "split_gain on a baselined target under the flat ceiling must be None",
        )

        # 3. The row builder, over a fixture corpus with EXACT counts and
        # EXACT order - ascending by free, so line 1 is the urgent one.
        BASELINE_FILES.clear()
        BASELINE_FILES.update(HEADROOM_FIXTURE_BASE)
        BASELINE_FNS.clear()
        fixture_fns = [
            ("crates/a/x.rs", "tight", 10, 497, False),
            ("crates/a/x.rs", "roomy", 90, 20, False),
            ("crates/a/x.rs", "a_test", 200, 900, True),  # test fns are not gated
            # The same name twice: main() gates the LARGEST, so the report
            # must score the largest too or it reports a margin nothing uses.
            ("crates/a/y.rs", "dup", 10, 100, False),
            ("crates/a/y.rs", "dup", 400, 480, False),
        ]
        frows, nrows = headroom_rows(HEADROOM_FIXTURE_FILES, fixture_fns)
        check(len(frows) == 3, f"headroom_rows built {len(frows)} file rows over a 3-file fixture")
        check(
            [r["label"] for r in frows]
            == ["crates/a/flat_tight.rs", "crates/a/based.rs", "crates/a/flat_roomy.rs"],
            f"file rows are not sorted by free ascending: {[r['label'] for r in frows]}",
        )
        check(
            [(r["free"], r["kind"]) for r in frows] == [(10, "flat"), (130, "baselined"), (2900, "flat")],
            f"file row free/kind wrong: {[(r['free'], r['kind']) for r in frows]}",
        )
        check(frows[1]["to_flat"] == 6184, f"to_flat on the baselined row is {frows[1]['to_flat']}, wanted 6184")
        check(len(nrows) == 3, f"headroom_rows built {len(nrows)} fn rows over a fixture with 3 production fns")
        check(
            nrows[0]["free"] == 3 and "tight" in nrows[0]["label"],
            f"tightest fn row is {nrows[0]['label']} at {nrows[0]['free']} free, wanted tight at 3",
        )
        dup = [r for r in nrows if "dup" in r["label"]]
        check(
            len(dup) == 1 and dup[0]["size"] == 480,
            f"a duplicated fn name must score its LARGEST span; got {[r['size'] for r in dup]}",
        )
        check(
            not any("a_test" in r["label"] for r in nrows),
            "a test fn reached the headroom report - only production fns are gated",
        )

        # 4. A baselined row BELOW the fold is still printed. It does not
        # reliably rank near the top (its free is up to 2% of a large size -
        # on 31 Aug 2026 neither baselined FILE was in the tightest twelve),
        # so cutting it off at the fold hides the class the reader came for.
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_headroom("t", frows, 1, FILE_CEILING, FILE_REMEDY)
        text = buf.getvalue()
        check("crates/a/based.rs" in text, "a baselined row below the fold was dropped from the report")
        check("flat_roomy" not in text, "a FLAT row below the fold was printed - only baselined rows are rescued")
        check("buys at most +53" in text, "the baselined row printed no split-gain note")

        # 5a. The narrowest line the GATE itself prints. This is the only
        # margin most lanes ever see - nobody runs --list on a push.
        line = narrowest_line(frows, nrows)
        check(
            line is not None and "crates/a/flat_tight.rs 10 free of 3,000" in line,
            f"narrowest_line did not name the tightest file: {line!r}",
        )
        check(
            line is not None and "fn crates/a/x.rs:10 tight 3 free of 500" in line,
            f"narrowest_line did not name the tightest production fn: {line!r}",
        )
        check(narrowest_line([], []) is None, "narrowest_line over nothing must be None, not a line about nothing")

        # 5. used% must FLOOR: 2,990 of 3,000 is 99, never 100. Rounded up it
        # reads as "at the limit" with ten lines still to spend.
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_headroom("t", [frows[0]], 5, FILE_CEILING, FILE_REMEDY)
        check("100%" not in buf.getvalue(), "used% rounded 2,990 of 3,000 up to 100 - it must floor")
    finally:
        BASELINE_FILES.clear()
        BASELINE_FILES.update(saved_f)
        BASELINE_FNS.clear()
        BASELINE_FNS.update(saved_n)

    # 6. The real tree. A report that has quietly stopped reaching anything
    # reads as a clean tree forever, so floor what it reaches and require
    # every baselined entry to appear as a row of its own.
    try:
        files, fns = collect()
    except OSError as e:
        fail(f"could not read the tree for the headroom pin ({e}) - run from the repo root")
        return bad
    frows, nrows = headroom_rows(files, fns)
    check(
        len(frows) >= HEADROOM_FILE_FLOOR,
        f"--headroom reached {len(frows)} files, floor is {HEADROOM_FILE_FLOOR} - run from the repo root",
    )
    check(
        len(nrows) >= HEADROOM_FN_FLOOR,
        f"--headroom reached {len(nrows)} production fns, floor is {HEADROOM_FN_FLOOR}",
    )
    # A floor of zero is an assertion about nothing, which is how a floor
    # stops being a floor. Found by mutation: lowering HEADROOM_FILE_FLOOR to
    # 0 was the one arm-mutation the rest of this selftest could not see.
    check(
        HEADROOM_FILE_FLOOR > 0 and HEADROOM_FN_FLOOR > 0,
        f"the headroom floors must be positive; they are "
        f"{HEADROOM_FILE_FLOOR} and {HEADROOM_FN_FLOOR}",
    )
    labelled = {r["label"] for r in frows if r["kind"] == "baselined"}
    check(
        labelled == set(BASELINE_FILES),
        f"baselined file rows {sorted(labelled)} do not match BASELINE_FILES {sorted(BASELINE_FILES)}",
    )
    # The case count itself, so an arm DELETED to quiet a mutation is a
    # failure rather than a quieter green.
    if ran != HEADROOM_CASES:
        print(
            f"  selftest FAIL: headroom ran {ran} cases, HEADROOM_CASES says {HEADROOM_CASES} - "
            "a case was added or deleted without moving the count",
            file=sys.stderr,
        )
        bad += 1
    return bad


def selftest_argv():
    """Pin argument recognition: an unknown flag must be a REFUSAL, never a
    silent skip that falls through to the ordinary clean verdict about a
    request nobody honoured. Reproduced 31 Aug 2026 against origin/main:
    `tools/size-gate.py --this-flag-does-not-exist` printed the clean gate
    line at exit 0."""
    bad = 0
    ran = 0

    def check(ok, msg):
        nonlocal bad, ran
        ran += 1
        if not ok:
            print(f"  selftest FAIL: {msg}", file=sys.stderr)
            bad += 1

    check(
        unrecognised_argv(["--this-flag-does-not-exist"]) == "--this-flag-does-not-exist",
        "an unknown flag must be reported, not silently ignored",
    )
    check(unrecognised_argv([]) is None, "no args must not be treated as unrecognised")
    check(unrecognised_argv(["--list"]) is None, "--list must still be recognised")
    check(unrecognised_argv(["--headroom"]) is None, "--headroom must still be recognised")
    check(unrecognised_argv(["--headroom=10"]) is None, "--headroom=N must still be recognised")
    check(unrecognised_argv(["--selftest"]) is None, "--selftest must still be recognised")

    if ran != ARGV_CASES:
        print(
            f"  selftest FAIL: argv ran {ran} cases, ARGV_CASES says {ARGV_CASES} - "
            "a case was added or deleted without moving the count",
            file=sys.stderr,
        )
        bad += 1
    return bad


def selftest():
    bad = 0
    for name, fn_name, want_test, src in SELFTEST:
        clean = strip_noise(src).split("\n")
        mask = test_line_mask(clean)
        got = None
        for n, start, _span in functions(clean):
            if n == fn_name:
                got = start < len(mask) and mask[start]
        if got is None:
            print(f"  selftest FAIL: never found fn {fn_name} in {name}", file=sys.stderr)
            bad += 1
        elif got != want_test:
            scored = "test" if got else "production"
            wanted = "test" if want_test else "production"
            print(f"  selftest FAIL: scored {fn_name} as {scored}, wanted {wanted} - {name}", file=sys.stderr)
            bad += 1
    for name, src, spans in SELFTEST_NOISE:
        got = {n: span for n, _start, span in functions(strip_noise(src).split("\n"))}
        if got != spans:
            print(f"  selftest FAIL: {name} measured {got}, wanted {spans}", file=sys.stderr)
            bad += 1
    # The point of the brace-less fix: assert the OLD brace-only scanner
    # really does swallow the next item, so nobody simplifies it back.
    src = SELFTEST[3][3]
    clean = strip_noise(src).split("\n")
    if not _brace_only_mask(clean)[5]:
        print(
            "  selftest FAIL: the brace-less fixture is not actually brace-less -\n"
            "    the old scanner does not swallow it, so it proves nothing.",
            file=sys.stderr,
        )
        bad += 1
    bad += selftest_headroom()
    bad += selftest_argv()
    if bad:
        print(f"\nsize-gate: {bad} selftest case(s) failed - the gate is not doing its job.", file=sys.stderr)
        return 1
    print(
        f"size-gate: selftest ok ({len(SELFTEST)} scope cases, {len(SELFTEST_NOISE)} tokenizer cases, "
        f"{HEADROOM_CASES} headroom cases, {ARGV_CASES} argv cases)"
    )
    return 0


def _brace_only_mask(clean_lines):
    """The scanner this gate shipped with, kept ONLY for the selftest above."""
    mask = [False] * len(clean_lines)
    i = 0
    while i < len(clean_lines):
        if CFG_TEST.match(clean_lines[i]):
            depth, started, j = 0, False, i
            while j < len(clean_lines):
                s = clean_lines[j]
                depth += s.count("{") - s.count("}")
                if "{" in s:
                    started = True
                if started and depth <= 0:
                    break
                j += 1
            if started:
                for k in range(i, min(j + 1, len(clean_lines))):
                    mask[k] = True
                i = j + 1
                continue
        i += 1
    return mask


KNOWN_FLAGS = {"--selftest", "--headroom", "--list"}


def unrecognised_argv(argv):
    """First arg outside the known set (bare, or `--headroom=N`), or None."""
    for a in argv:
        if a in KNOWN_FLAGS or a.startswith("--headroom="):
            continue
        return a
    return None


def main():
    if "--selftest" in sys.argv:
        return selftest()

    # An unrecognised flag is a REFUSAL naming it, never a silent skip - a
    # stale checkout running a flag this script has not learned yet must not
    # read as a clean verdict about a request nobody honoured. Reproduced
    # 31 Aug 2026: `--this-flag-does-not-exist` fell through every check
    # below and printed the ordinary clean gate at exit 0.
    bad_arg = unrecognised_argv(sys.argv[1:])
    if bad_arg is not None:
        print(
            f"size-gate: unrecognised argument {bad_arg!r} - known flags are "
            "--list, --headroom[=N], --selftest, or no args for the gate. "
            "A stale checkout may be missing a flag this script now supports "
            "- merge origin/main.",
            file=sys.stderr,
        )
        return 1

    for a in sys.argv[1:]:
        # `--headroom=N` for a longer or shorter fold; the default 25 matches
        # --list's. A junk N is a refusal rather than a silent default - a
        # report that quietly ignores what was asked for is how a reader ends
        # up trusting a number nobody produced.
        if a == "--headroom":
            return report_headroom()
        if a.startswith("--headroom="):
            n = a.split("=", 1)[1]
            if not n.isdigit() or int(n) < 1:
                print(f"size-gate: --headroom={n} is not a positive count", file=sys.stderr)
                return 1
            return report_headroom(int(n))

    files, fns = collect()

    if "--list" in sys.argv:
        print("=== largest files (raw lines) ===")
        for p, n in sorted(files, key=lambda x: -x[1])[:25]:
            print(f"  {n:7,}  {p}")
        print("\n=== longest production functions ===")
        prod = [f for f in fns if not f[4]]
        for p, name, line, span, _ in sorted(prod, key=lambda x: -x[3])[:25]:
            print(f"  {span:7,}  {p}:{line}  {name}")
        print("\n=== longest test functions (not gated) ===")
        test = [f for f in fns if f[4]]
        for p, name, line, span, _ in sorted(test, key=lambda x: -x[3])[:10]:
            print(f"  {span:7,}  {p}:{line}  {name}")
        # At the FOOT on purpose: three handoffs and two chip queues pipe
        # this mode through `head -4` / `head -6`, so nothing may move above
        # the first rows.
        print(
            "\n  (this mode sorts by SIZE and prints no limit - to price a split, use\n"
            "   --headroom, which sorts by what is CLOSEST to its ceiling and says\n"
            "   which KIND of ceiling that is. The two kinds do not split alike.)"
        )
        return 0

    errors = []

    seen_files = {p: n for p, n in files}
    for p, n in sorted(files):
        limit, _kind = file_limit(p)
        if n > limit:
            errors.append(
                f"file {p} is {n:,} raw lines (limit {limit:,})"
                + (" - it has REGROWN past its baseline" if p in BASELINE_FILES else "")
            )
    for p, base in sorted(BASELINE_FILES.items()):
        if p not in seen_files:
            errors.append(f"baseline entry for missing file {p} - delete the entry")
        elif seen_files[p] <= FILE_CEILING:
            errors.append(
                f"{p} is now {seen_files[p]:,} lines, under the {FILE_CEILING:,} ceiling - "
                "delete its baseline entry (the list only shrinks)"
            )

    prod_fns = largest_prod_fns(fns)
    for key, (span, line) in sorted(prod_fns.items()):
        limit, _kind = fn_limit(key)
        if span > limit:
            p, name = key.rsplit("::", 1)
            errors.append(
                f"fn {name} ({p}:{line}) is {span:,} lines (limit {limit:,})"
                + (" - it has REGROWN past its baseline" if key in BASELINE_FNS else "")
            )
    for key, base in sorted(BASELINE_FNS.items()):
        if key not in prod_fns:
            errors.append(f"baseline entry for missing fn {key} - delete the entry")
        elif prod_fns[key][0] <= FN_CEILING:
            errors.append(
                f"{key} is now {prod_fns[key][0]:,} lines, under the {FN_CEILING:,} ceiling - "
                "delete its baseline entry (the list only shrinks)"
            )

    if not errors:
        n_files = sum(1 for p in BASELINE_FILES)
        n_fns = sum(1 for k in BASELINE_FNS)
        print(
            f"size-gate: clean ({len(files)} files, {len(prod_fns)} production fns; "
            f"{n_files} file + {n_fns} fn baseline entries still to burn down)"
        )
        line = narrowest_line(*headroom_rows(files, fns))
        if line:
            print(line)
        return 0

    print(f"size-gate: {len(errors)} violation(s):\n", file=sys.stderr)
    for e in errors:
        print(f"  {e}", file=sys.stderr)
    print(
        "\n  New code must stay under the ceilings. If a listed target was just\n"
        "  split, delete its baseline entry in the same commit. Do not raise a\n"
        "  baseline number to make this pass - the splits are TODO 106 and the\n"
        "  numbers only go down.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
