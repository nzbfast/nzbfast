# parfast-ffi: the JSON contract

Every shape here is `research/PLAN-PARFAST-GUI-2026-09-12.md` section
4.5. This file is the working copy: it records what the plan said, what
was ADDED, and what a host must know that the plan could not say
because it was written before the core existed.

**The rule that governs this file.** A field may be ADDED and an enum
value may be ADDED; nothing may be renamed or removed. Two UI lanes are
coding against section 4.5 right now, so an addition costs them nothing
and a rename costs them a release. Every addition below is marked
**ADDED** with the reason.

Every string is UTF-8. Every path is absolute. Every size is bytes.
Every duration is milliseconds. Every JSON is an object at the top
level.

---

## Memory, threading and errors

- Every `char *` returned is the CALLER's and is released with
  `pf_string_free`. Nothing else frees one; a pointer from any other
  allocator must never be passed to it.
- Every `int` is `PF_OK` (0) on success, and negative otherwise:
  `PF_ERR_ARG` (-1) a null or non-UTF-8 argument, `PF_ERR_JSON` (-2)
  JSON that did not parse or did not carry the shape asked for,
  `PF_ERR_NOT_FOUND` (-3) an id nothing answers or a state change the
  job's state forbids, `PF_ERR_REFUSED` (-4) understood and refused.
  `pf_last_error` then holds `{"code":"...","message":"..."}` for the
  last failure on that session; reading it does not clear it.
- `pf_job_submit` answers a job id, which is always >= 1, or one of the
  negative codes above.
- The session is thread-safe; every function may be called from any
  thread.
- **The wake callback carries no data and may fire on any thread.** The
  host marshals to its UI thread and then polls. The session never
  holds a lock across the callback, so a wake handler may call straight
  back in - which is exactly what a host that polls from its wake does.
- A function that answers a `char *` answers NULL on failure, with
  `pf_last_error` set.

## Lifetime

`pf_session_new(NULL)` is the defaults. `pf_session_free` cancels every
job the session holds and does NOT wait for the workers: a worker sees
the cancel at its next honouring point (below) and the session's own
memory is released when the last of them lets go. Do not call any other
`pf_*` function on a session concurrently with freeing it.

Freeing the session also REMOVES the wake, so no worker still winding
down can ring it. That is not the same as a promise that no callback is
running: one already inside your function when the free happens keeps
running to its end. So a host that frees the wake's `ctx` must first
either remove the wake (`pf_session_set_wake(s, NULL, NULL)`) or free the
session, and then make sure no callback is still in flight - both shipped
wrappers clear the callback before the free and marshal the callback onto
their UI thread, which does exactly that. A `ctx` that outlives the
process, or one owned by the callback itself, needs none of this.

Settings that do not parse are NOT a refusal to start. A corrupt
preferences file must be an app that launches and complains, never an
app that will not launch, so `pf_session_new` falls back to the
defaults.

---

## JobSpec (`pf_job_submit`)

As section 4.5, in full. Notes on what the core does with it:

### create

```json
{"kind":"create","create":{
  "sources":[{"path":"/abs/a.bin"},{"path":"/abs/dir","recursive":true}],
  "path_mode":"basename|relative","base_path":"/abs",
  "block":{"size":1048576} | {"count":2000},
  "recovery":{"percent":10.0} | {"count":100} | {"size":104857600},
  "output":"/abs/name.par2",
  "volumes":{"scheme":"none"} | {"scheme":"uniform","files":7} |
            {"scheme":"uniform","blocks_per_file":100} |
            {"scheme":"uniform","file_size":10485760} | {"scheme":"pow2"} |
            {"scheme":"pow2_limit","limit":"largest_source"} |
            {"scheme":"pow2_limit","limit":{"blocks":512}} |
            {"scheme":"pow2_limit","limit":{"size":10485760}},
  "first_recovery_block":0,"comment":"","overwrite":false,
  "std_naming":false,"unicode":"auto|never|always",
  "perf":{"threads":null,"memory_mb":null,"low_priority":false}}}
```

- A directory source contributes the files directly in it, or the whole
  tree under it when `recursive`. Dot-files and `.par2` files are never
  members - the reference's own rule.
- A source that is not on disk is an ERROR (`missing_source`), not a
  silent omission: a job that quietly protects four of five named files
  is the worst outcome available. A named source that is neither a
  folder nor an ordinary file - a pipe, a socket, a device - is an
  ERROR too (`unsupported_source`, **ADDED** 17 Sep 2026): there is
  nothing there to hash, and opening a fifo for reading blocks until a
  writer appears, forever, inside a call no Cancel can reach.
- **A WALK NEVER LEAVES THE FOLDER IT WAS GIVEN** (17 Sep 2026). A link
  found while walking is not followed and not protected, and neither is
  anything that is not an ordinary file. That is the reference's own
  rule, measured: par2cmdline over a folder holding a directory link, a
  file link and a fifo beside one real file reports
  `Source file count: 1`. Before this, a `loop -> .` inside a source
  folder was re-entered until the kernel's symlink limit stopped it -
  one file became 95 members, 30 of them a file from a folder the user
  never chose. A source the user NAMED is still followed as spelled,
  link or not: `/tmp` is a link on macOS and a path somebody typed is a
  path they meant.
- **What a walk could not take in is REPORTED, never a refusal.** A
  folder `read_dir` refuses, a link not followed, an item that is not an
  ordinary file: each reaches `warnings` on the preview - FIRST in the
  list, ahead of the arithmetic's own notes - and `result.warnings` on
  the finished job. Unreadable folders are NAMED, up to three; the other
  two kinds are counted. It is deliberately not fatal: one unreadable
  `.Trashes` or `.Spotlight-V100` must not refuse a create over the
  volume that holds it. Before this the whole subtree vanished and the
  plan reported success over what was left.
- **`overwrite:false` PROTECTS THE WHOLE SET, and does it at the open**
  (17 Sep 2026). Every file of the set is protected, not just the
  `output` index: a set whose `.par2` had been deleted, or one written
  under a different `first_recovery_block`, still has its recovery
  volumes on disk, and those are files a create destroys. A clash is a
  failed job with `error.code = "exists"` naming the path.

  The guarantee is the ENGINE's, not a look-before-you-write: the create
  opens every file with `O_EXCL` (`parfast c --no-clobber`, reaching
  `par2gen::CreatePlan::no_clobber`), so two creates started together on
  one base cannot both win and a set that appears after the check is
  refused rather than truncated. A host may rely on it: with
  `overwrite:false`, a job that reports `done` destroyed nothing.
  `overwrite:true` is par2cmdline's own behaviour and the default of the
  `parfast` command line, which is why it is what the CLI does when
  nothing asks otherwise.
- `recovery.percent` is rounded to a WHOLE percent, because that is
  what the reference's `-r` takes. The preview says so in `warnings`.
  Use `{"count":n}` for finer control.
- The `uniform` scheme takes ONE of `files`, `blocks_per_file` or
  `file_size`; if more than one is given the first in that order wins
  and the preview warns.
- `pow2_limit` takes all three ceilings. `"largest_source"` is the
  reference's `-l`; an explicit `{"blocks":n}` is exact; `{"size":n}`
  is resolved to a block count at the block size the spec settles on
  (one recovery slice costs its own bytes plus 68) and the preview
  says which number it became. A volume also carries a copy of the
  set's critical packets, so a file is a little larger than a `size`
  ceiling - that is a floor division and never a breach of the count.
- `std_naming` is carried: the volumes are named `set.vol12-22.par2`,
  the PAR2 spec's own first-and-LAST-exponent form, rather than
  par2cmdline's `set.vol12+11.par2`. The preview's `files` list carries
  whichever spelling the create will write.
- `unicode` is accepted and currently IGNORED - see the capability
  table. A host hides the control while `unicode_policy` is false.
- `comment` is WRITTEN, as the spec's optional `CommASCI` / `CommUni`
  text packet, and read back on load (12 Sep 2026; `pf_capabilities
  .comment` is now true). An empty string is the absence of a comment
  and writes no packet. What may be IN one is not free-form: a comment
  carrying a control character other than newline, carriage return or
  tab is REFUSED, and so is one over 16 KiB of UTF-8 - the engine
  refuses to write what it refuses to read back, rather than storing a
  comment that returns as something else. The preview says so in
  `warnings` before the create runs, so a host that lets a user paste
  arbitrary text should surface that warning rather than assume every
  value is writable. A pure-ASCII comment takes the ASCII packet alone
  and anything above U+007F takes the Unicode one alone; that policy is
  `unicode: "auto"`, which is why `unicode_policy` stays false.

### verify / repair

```json
{"kind":"verify","verify":{"par2":"/abs/x.par2","extra_dirs":["/abs/other"],
  "options":{"rename_only":false,"data_skipping":false,"skip_leaway":64,
             "fast_solver":null,"threads":null}}}

{"kind":"repair","repair":{ ...same fields...,"purge":false,"keep_damaged":true}}
```

- `extra_dirs` are the bare arguments after the recovery-set name on
  the command line: extra data files and donor directories the engine
  may adopt blocks from.
- `skip_leaway` without `data_skipping` is DROPPED rather than sent to
  a parser that would refuse the whole line (the reference refuses
  `-S` without `-N`).
- `keep_damaged` defaults to **true**, not to JSON's `false`: the
  `<name>.1` copy of a damaged original is the only thing standing
  between a wrong repair and a lost file.
- **`-B` is not supported on repair.** A repair whose data directory is
  not the recovery set's directory fails with the CLI's own refusal.
  Verify honours it in full, because it only reads.

### checksum_create / checksum_verify

```json
{"kind":"checksum_create","checksum_create":{"sources":[...],
  "format":"sfv|md5|sha1|sha256","output":"/abs/x.sfv","relative":true}}
{"kind":"checksum_verify","checksum_verify":{"file":"/abs/x.sfv"}}
```

The FORMAT of a file being verified is decided by its CONTENT and not
by its name: an SFV saved as `.md5` is an SFV, because where the digest
sits is what a checker has to know. A file that mixes the two shapes is
refused at the line that mixes them.

---

## JobSnapshot (`pf_job_snapshot`)

As section 4.5, with these additions:

| Field | Status | Why |
|---|---|---|
| `state: "interrupted"` | **ADDED** enum value | Section 5.5 requires a job that was running when the app quit to come back marked *Interrupted* and re-runnable. Reached only by loading a persisted queue. |
| `result.checksum.entries` | **ADDED** | One row per checksum entry, in the file's own order: `{"name","expected","actual","status"}` with `status` one of `ok` / `mismatch` / `missing`. Section 5.4's Verify table is *Name \| Expected \| Status* per file and the three counts cannot draw it. `actual` is what the file on disk came to, and is empty for a `missing` row. Omitted for a checksum CREATE, which has nothing to compare. |
| `result.exit_code` | **ADDED** | The process exit code the equivalent `parfast` line would have returned. The CLI's dialect is the one thing a script user already knows, and a GUI that hides it makes its own behaviour unreproducible from a terminal. |
| `result.warnings` | **ADDED** (17 Sep 2026) | What the job could not take in: a folder that could not be read, a link a walk did not follow, an item that is not an ordinary file. Omitted when empty. On the RESULT and not only on the preview because the walk happens AGAIN when the job runs, over a tree that may have changed - a folder that became unreadable since the pane was drawn would otherwise reach nobody. Never an error: show it beside Done. It matters most on a checksum CREATE, where what is not in the manifest is not checked and the verify that reads it back reports CLEAN over the gap. |
| `command` | **ADDED** | The `parfast` command line equivalent to this job, for the Advanced pane's "show the equivalent command". Empty for the two checksum kinds, which have no CLI equivalent. |

`eta_ms`, `rate_bytes_per_s`, `survey`, `result` and `error` are OMITTED
when they have no value rather than sent as `null`. A host decodes them
as optional.

`progress` is 0.0 to 1.0 and never goes backwards within a phase. It
is only meaningful while the phase can measure itself - see the
capability table: during a fold there is no in-engine progress, so the
bar stays where the hashing left it and `phase_text` says what is
happening. A bar that sat at a number would be a claim.

---

## Survey

As section 4.5. `block_runs` is `[state, length]` pairs over the source
blocks in SET order: **0** pending, **1** present, **2** damaged,
**3** missing, **4** misnamed, **5** hashing. Adjacent runs of one
state are merged INCLUDING across a file boundary - the map is one
strip, not one strip per file. The codes are wire format and are never
renumbered.

Two things a host must know:

1. **Misnamed and adopted are different mechanisms and are drawn
   differently.** A member whose bytes are sitting in the directory
   under a DIFFERENT name is `misnamed`, carries `found_as`, and its
   blocks draw state 4 - a rename would fix it and no parity is spent.
   A member whose individual blocks turn up elsewhere (or at a shifted
   offset inside itself) has those blocks already `present` (state 1),
   because the engine's rolling scan found them. Nothing adds the two
   together.

   **A misnamed member is NOT complete, and still owes its blocks.**
   Its `blocks_ok` is 0 - `blocks_ok` counts blocks at the member's OWN
   name, and its bytes are under the one in `found_as` - and its blocks
   are counted in `recovery_needed`, exactly as the reference counts
   them ("1 file(s) are missing", exit 1). The set needs an action: a
   repair, or `-O`'s rename. State 4 is there to say that the action is
   cheap, not that it is unnecessary. This paragraph exists because the
   model said `complete` here until 12 Sep 2026, which showed as a
   confident green over a set the CLI repairs.
2. **A repair's own survey has accurate per-FILE counts and
   count-derived block POSITIONS.** The engine's pre-fold survey
   reports how many of a member's blocks are present, not which, so the
   present ones are drawn first. A VERIFY job draws the real positions;
   run one for the map. When a repair completes, the strip is redrawn
   as one present run, which is then exact.

`verdict` is the CLI's own two predicates, CALLED and not restated, in
the order `parfast::verify::print_verdict` applies them to produce its
exit code. So the mapping is exact and a host may rely on it:

| `survey.verdict` | `result.exit_code` |
|---|---|
| `complete` | 0 - `!Survey::damaged()` |
| `repairable` | 1 - damaged, and `Survey::repairable()` |
| `unrepairable` | 2 - damaged, and not repairable |

`repaired` and `failed` are a REPAIR job's verdicts and do not appear on
a verify; `verifying` is the pass in flight. Those predicates are what
the conformance table pins against par2cmdline, and a picture that
disagreed with the exit code beside it would be worse than no picture -
which is precisely what shipped for a day: a `misnamed` set answered
`complete` with `exit_code: 1` in the same object. The invariant is now
a test that builds real sets and asserts the mapping over clean,
misnamed and damaged.

---

## PlanPreview (`pf_plan_preview`)

As section 4.5, plus:

| Field | Status | Why |
|---|---|---|
| `source_bytes` | **ADDED** | The padding percentage is unreadable without it. |
| `source_files` | **ADDED** | Same. |

`pf_plan_preview` accepts BOTH the whole job spec
(`{"kind":"create","create":{...}}`) and the bare create object: a pane
building a spec has the first, a pane previewing while the kind is
implicit has the second, and refusing either would make every host wrap
its object for one call.

The file SIZES are exact - they come from `nzbkit::par2gen::plan_files`,
which builds the critical block the creator would build and adds up the
packets the writer would write, and the engine's own test asserts them
byte for byte against a real create. The one thing the preview cannot
promise is the volume COUNT under memory pressure: the engine widens a
plan whose volumes would not fit the accumulator budget, and that
budget depends on what else is creating at that moment. Present the
count as what an idle machine would write.

The volume NAMES in the preview are par2cmdline's, measured field widths
and all (`vol00+1` for a thirteen-slice set, not `vol000+001`). This
paragraph said the opposite until 12 September 2026 - that the preview
showed the engine's own fixed `vol000+001` and the CLI renamed afterwards
- and that WAS true, and was a defect: the pane named files the user
would never see, for every set whose widths the rename narrowed.
`planner::preview` maps the plan through
`parfast::create::final_volume_names`, which is the same rule
`rename_volumes` applies to the bytes on disk, so the pane and
`result.written` agree. The first field is as wide as
`first_recovery_block + recovery_blocks`; the second is as wide as the
largest COUNT in the set, or the first field's width under
`std_naming`, where both fields are exponents.

`warnings` is advisory and never a refusal: a preview that refused
would be a pane that cannot be filled in from left to right.

---

## Capabilities (`pf_capabilities`)

A host HIDES any control whose capability is false.

```json
{"version":"1.6.0","engine":"nzbkit 1.0.0","cpu":"aarch64",
 "kernel":"neon",
 "std_naming":true,"volume_limit_explicit":true,
 "unicode_policy":false,"comment":true,
 "data_skipping":true,"fast_solver":true,
 "pause":true,"pause_in_fold":true,"cancel_in_fold":true,
 "progress_in_fold":true,"low_priority":false}
```

| Key | Status | What it means today |
|---|---|---|
| `std_naming` | plan 4.5 | **true** (12 Sep 2026). `"std_naming":true` writes the spec's own `set.vol12-22.par2` - first and LAST exponent - instead of par2cmdline's `set.vol12+11.par2`. A rename after the writer finishes, so the bytes are identical either way; some tools read only the spec form. |
| `volume_limit_explicit` | **ADDED** | **true** (12 Sep 2026). All three `pow2_limit` ceilings are carried. `largest_source` is the reference's `-l`; `{"blocks":n}` and `{"size":n}` reach `par2gen::CreatePlan::max_blocks_per_volume` through parfast's own `--volume-blocks=N` long option. The preview and the create resolve the ceiling through one function, so the layout the pane draws is the layout that gets written. |
| `unicode_policy` | plan 4.5 | **false, and looked at properly on 12 Sep 2026 - it should STAY false.** The plumbing would be cheap (a `Copy` policy on `CreatePlan`, five `critical_packets` call sites); what is at the end of it is not worth writing. The spec's `UniFileN` packet exists because the FileDesc name field is a byte string with no declared encoding, so a writer with a non-ASCII name had no way to say what its bytes meant. `par2gen` already writes UTF-8 there and par2cmdline does the same, so `never` and `auto` are both exactly today's behaviour and `always` would emit a UTF-16 copy of a name the reader has already read - redundant, not corrective, and it would cost the byte-identity-with-par2cmdline claim that `crates/parfast/tests/integration/creator_packet.rs` pins. Checked end to end: a member named `Ünïcøde 日本語.bin` creates and verifies today, `Target: "Ünïcøde 日本語.bin" - found.` Hide the control. |
| `comment` | **ADDED** | **true since 12 Sep 2026.** `par2gen` writes the spec's `CommASCI` / `CommUni` text packet when a comment is given and `par2::Par2Set::comment` reads one back, so the Comment field is SHOWN. It was false until that day and the field was hidden. The create REFUSES a comment carrying a control character other than newline, carriage return or tab, and one over 16 KiB of UTF-8; the preview carries that as a `warnings` line, so show the warning rather than assuming every value the field accepts is writable. |
| `data_skipping` | plan 4.5 | true. `-N` / `-S` reach the CLI options unchanged. |
| `fast_solver` | plan 4.5 | true. `--fast`, the EXPERIMENTAL joint solve. |
| `pause` | plan 4.5 | true, with the limits below. |
| `pause_in_fold` | **ADDED** | **true since 12 Sep 2026**, with ONE stated exception - a REPAIR's solve. A create has none since later that same day; see below. |
| `cancel_in_fold` | **ADDED** | **true since 12 Sep 2026.** See below. |
| `progress_in_fold` | **ADDED** | **true since 12 Sep 2026.** See below. |
| `low_priority` | plan 4.5 | **false.** The flag is carried in the snapshot for the host to act on (a host can lower its own process priority); nothing in the engine reads it. |

### What cancel, pause and progress actually reach

This is the most important paragraph in this file for a UI lane.

| Job | Progress | Pause | Cancel |
|---|---|---|---|
| verify | per member, with ETA and rate | between members | between members |
| checksum create / verify | per file | between files | between files |
| repair | **four phases, each a rising fraction that lands on full** | **inside all of them except the solve** | **inside all of them** |
| create | **hashing and the fold as one rising fraction across every fold batch, then the volume writes** | **inside all of them, to within one transform stripe** | **inside all of them, and it leaves NOTHING on disk** |

**The repair row changed on 12 Sep 2026** (plan section 4.2 item 1
landed). It used to read "to the end of the verify half, then stops
moving" and "at the pre-fold handshake only". A host built against that
row is still CORRECT - nothing was removed - but it is now hiding or
qualifying controls the engine honours, and the three capability keys
are how it finds out.

**The create row changed later the same day** (claim
`par2gen-create-control`). It used to read "phase text only" and
"before it starts", twice. Three things a host should know about it:

- **The bar is TWO phases sharing one span, not four in a row.** A
  create hashes the members on one thread while the fold reads the same
  payload on another, and on one arm the fold's own reader does the
  hashing, so the hash phase never reports at all. The session maps
  both onto 0-90% and takes whichever is further; the volume writes are
  the last 10%. `phase` still says which of the two last reported, so a
  host that wants a sentence has one.

  **Two corrections to that span, 17 Sep 2026** (claim
  `gh88-gui-create-bar-batch-frame`), which change the figures a host
  draws on a MEMORY-CAPPED create and leave every other create's
  unchanged. Such a create folds the set a batch of volumes at a time
  and the engine re-sizes the fold phase at each, so the 0-90% span is
  now cut into one segment per batch: the fold walks its own segment,
  and the hashing, which reads the payload once beside the FIRST batch,
  may not push the bar past the end of that batch. Without both, an
  18-batch create reached 90% during batch 1 and stayed there.
  Second, **the volume writes now wait for the fold to finish with the
  bar.** They genuinely overlap it on two of the engine's arms, and
  drawing them as they arrived put the bar into the last 10% within the
  first batch and flipped `phase_text` between *Building the recovery
  blocks* and *Writing the recovery volumes* for the whole overlap. A
  host therefore sees the writes once, at the end, and the last tenth
  can cross quickly on an arm where the writing was done alongside the
  folding. Nothing was added or removed: the same two fields carry it.
- **A cancelled create leaves nothing.** Not "nothing since the last
  volume" - nothing: the engine unlinks the index and every volume the
  run wrote. That is the only honest outcome, because a volume is
  written to its FINAL name with its critical packets patched in LAST,
  so a partial set names no member and verifies against nothing. A set
  the run was EXTENDING keeps every volume it already had; its index,
  which every create rewrites, goes with the rest and a re-run writes
  it again. So a host must not offer to clean up after a Cancel, and
  must not report the partial files it can no longer see.

  **A job reports `cancelled` only when the engine actually unwound,
  and that is what makes the promise above usable** (12 Sep 2026). A
  create is atomic and says which way it went in its exit status:
  success means the whole set is sealed on disk, and a create that
  honoured a cancel returns a failure code having removed every file it
  wrote. A Cancel can therefore LOSE - the engine takes its last poll
  immediately before sealing the volumes - and until that date the
  session read the cancel flag ahead of the exit code, so a create that
  had already finished reported `cancelled` with no `written` list at
  all. A complete, valid recovery set then sat on disk that the job
  named none of and that this very paragraph forbade the host to offer
  to clean up. A lost Cancel now reports `done` with the files named.
  The user pressed Cancel and sees the job finished, which is what
  happened; the alternative was a contract no host could act on.
- **The capability keys did not move for this.** `cancel_in_fold`,
  `progress_in_fold` and `pause_in_fold` were already true from the
  repair's landing and now cover the create too; there is no per-kind
  key, which is why this table exists.

**The four phases**, in the order they run, each reported as a fraction
of its own whole. The session maps them onto one bar and one sentence,
so a host draws `progress` and `phase_text` and does not need to know
them; they are here because the sentence names them.

| Phase | `phase` in the snapshot | What its fraction is over | Share of the bar |
|---|---|---|---|
| verify | `hashing` | bytes of the members it hashes | 0 - 45% |
| fold | `solving` | bytes of good blocks fed to the solve | 45 - 85% |
| solve | `solving` | the back-substitution's own work | 85 - 95% |
| write | `writing` | bytes written to the repaired targets | 95 - 100% |

Those weights are a LABELLING choice taken once in the session so the
two apps cannot disagree, not a prediction. The bar is monotone across
phases as well as within one.

**On a memory-capped repair the middle two shares are PER SWEEP**
(17 Sep 2026, same claim). Such a repair sweeps the payload once per
slab and the engine re-enters the fold and the solve at every one, so
45 - 95% is cut into one segment per sweep and the 40/10 weighting sits
inside each segment rather than spanning the repair. A repair that does
not slab, which is the ordinary one, draws exactly the table above.
Before this the bar read 95% for every sweep after the first while the
sentence under it went on counting, which is the defect the daemon's
own bar had until 16 Sep 2026.

**Cancel** is polled per member, per fed block, per fold unit and per
written block, so it ends a repair from wherever it is. **What a
cancelled repair leaves on disk**, which a host should be able to tell a
user:

- Cancelled before the patch (the hashing, the fold, the solve): nothing
  was written at all. The directory is exactly as the survey found it.
- Cancelled DURING the patch: every temp-staged member is removed and
  none is renamed in; an in-place patched member has some subset of its
  missing blocks filled. The patch only ever writes blocks the verify
  pass found missing, so it is monotone - the member is no worse than it
  was. Nothing is purged and no backup is consumed.
- Either way a re-run re-verifies from disk and repairs from the same
  recovery data. A host may say "you can run this again".

**Pause** parks in the hashing loop, the feed and the patch. **The solve
is the exception**: its work grid is a shared work-stealing queue and a
worker that parked holding a cell would hold work every other worker is
looking for, so a Pause pressed during the solve takes effect at the end
of it. On a structured repair - a set whose recovery volumes are intact,
which is nearly all of them - the solve is seconds at every size the
format allows. On an unstructured one it can be minutes, and a host that
wants to be exact can say "pausing after the current step" while
`phase_text` reads *Rebuilding the missing blocks*.

A CREATE has no equivalent exception, and the reason is worth a
sentence because the row above said it did until 12 Sep 2026. Its
recovery arithmetic runs on the same shape of worker pool as the solve,
and the first read of that pool put it in the same class. But a create's
transform is not a stage between other stages the way a solve is - it is
essentially the whole job (10.73 s of a measured 12.85 s run), so
"takes effect at the end of it" meant a create could not be paused at
all: it went to Paused and then wrote its complete set with Resume never
pressed. The workers now park between two stripes rather than while
holding one, which is the same rule read one line further up. The grain
is one stripe - measured at 24 ms of thread time at a 1 MiB block and
211 ms at a 64 KiB block near the PAR2 slice ceiling - so a host may
show Pause on a create without qualifying it.

A control that cannot be honoured is still RECORDED - the job goes to
`cancelled` when it finishes - so a host never shows a button that does
nothing.

---

## Settings (`pf_settings_get` / `pf_settings_set`)

**THE SHAPE IS GROUPED. A FLAT OBJECT IS REFUSED.** This is the one
place a host has already lost a field to a wrong guess, so the whole
object is written out below rather than described. Ask a fresh session
with `pf_settings_get` and you get exactly this, defaults filled in:

```json
{"general":{"open_par2":"verify","purge_after_repair":false,
            "keep_damaged_copies":true,"notifications":true,
            "auto_close_progress":false,"language":"en"},
 "create":{"block_allocation":"count","block_count":2000,"block_size":0,
           "recovery_allocation":"percent","recovery_percent":5.0,
           "recovery_count":0,"recovery_size":0,"scheme":"pow2",
           "std_naming":false,"unicode":"auto","overwrite":false},
 "performance":{"threads":null,"memory_mb":null,"fast_solver":false,
                "low_priority":false,"pair_large_creates":true,
                "digest_cache":false},
 "integration":{"handle_par2":true,"handle_sfv":false,"handle_md5":false,
                "handle_sha256":false,"shell_menu":true},
 "advanced":{"show_command":true,"log_level":0,"log_folder":null},
 "concurrency":1,"post_queue_action":"none","log_tail_lines":500}
```

Five groups, three top-level scalars. Every key is optional on the way
in, so a partial object is fine and what you leave out keeps its
default.

**What happens to a key the core does not place:**

| The key | What happens |
|---|---|
| A member name sent at the TOP level (`{"notifications":false}`) | **Refused**, `PF_ERR_JSON`, with `pf_last_error.code` = `misplaced_key` and a message naming the group it belongs to. Nothing of that write lands. |
| A top-level key this build does not know at all | Accepted and IGNORED - that is the forward-compatible case. The write returns `PF_OK` and `pf_last_error` is set to `{"code":"settings_ignored_keys",...}` listing them. |

That second row is the one surprise in this file: **`pf_last_error` can
be set after a call that SUCCEEDED.** Read the code, not the presence of
a record. The alternative was to keep dropping unknown keys in silence,
which is exactly how `notifications` went missing for a day on the
Windows lane (12 Sep 2026): it was sent flat, `concurrency` in the same
write really is top-level so it landed, and half a write vanishing with
`PF_OK` returned is indistinguishable from the core dropping a field it
was given.

**`general.open_par2` is the canonical key** for plan 5.6's "opening a
`.par2` -> verify only / verify then repair". Values `"verify"` and
`"verify_then_repair"`. The plan's prose calls the setting *on open*,
and there is no `on_open` and no `auto_repair_on_open` field - if your
serializer produces one from a derived property, it will now be refused
as a misplaced key or ignored, so mark such a property "do not
serialize".

`integration` is REMEMBERED and never acted on: registering a file
handler is a platform call in each app. `performance` is the three
process-GLOBAL engine knobs; above concurrency 1 the last job to start
wins, and the pane says so.

**`pf_digest_cache_clear`** (added 15 Sep 2026) is the "Clear remembered
checksums" button under `performance.digest_cache`. It deletes every
record in the per-user store that setting fills
(`~/Library/Caches/parfast/digests`, `%LOCALAPPDATA%\parfast\digests`)
and answers how many files went, 0 where there is no store. A failure is
`PF_ERR_REFUSED` with the folder in `pf_last_error`. It is safe while a
job runs - a record that vanishes is a miss, never a wrong checksum - and
it does not change the setting.

---

## Queue (`pf_queue_snapshot`)

```json
{"paused":false,"concurrency":1,"post_action":"none",
 "post_action_due":false,"jobs":[snapshot...]}
```

| Field | Status | Why |
|---|---|---|
| `settings.performance.pair_large_creates` | **ADDED** (15 Sep 2026), default **true** | Start a second large single-file create beside a running one when the machine has the cores and the memory for both, WHATEVER `concurrency` says. A create over one large file is bound by one serial MD5 chain and leaves most of a big machine idle: two measured 11.5 s against 11.4 s for one on an M3 Ultra, so a queue of them finishes in about half the time. It makes NO single job faster - say that in any copy that mentions it. The rule (`parfast-session`'s `pairing` module): both jobs are one-file creates from exponent 0 with the same `performance` knobs; the running one's fold pacer has settled; half the machine less a core for each chain leaves each fold above the pacer's floor of two (so a 4-core machine, or `NZBFAST_CPU_WORKERS=4`, never pairs); a core for each chain plus the settled fold width twice over fits; and the engine says the second create still takes the paced single-file route in the memory budget the first has left. A create the rule refuses stays `queued` rather than starting and blocking, at any concurrency. From a spinning disk it buys nothing: under a one-disk read cap of 200 and 120 MB/s the pair tied the serial queue (0.98-1.00x of its wall, addendum 8 of `research/PARFAST-SINGLE-FILE-MD5-HEADROOM-2026-09-13.md`), and head seek, which that cap could not model, can only make it worse, so turn it off there. The paired job's `log_tail` carries a line saying it started beside another. |
| `post_action_due` | **ADDED** | The queue has drained and the action has not been carried out. The session REPORTS the action; the HOST performs it, because sleeping or shutting down a machine is a platform call and a decision a human has to be able to stop. Call `pf_queue_clear_post_action` once you have dealt with it; it will not fall due again until a new job is submitted. |

Two functions outside section 4.5:

| Function | Status | Why |
|---|---|---|
| `pf_queue_clear_post_action` | **ADDED** | The other half of `post_action_due`. |
| `pf_job_run_next` | **ADDED** | Section 5.5's "Run now": take this QUEUED job before anything else waiting, whatever its id. Refused for a job already running or finished. It does NOT interrupt what is running and does NOT raise the concurrency - on a serial queue the effect is that this job is started next. Raising the concurrency instead starts every job queued ahead of it too; resuming the selected job only lets the scheduler reach it in its own turn. |
| `pf_queue_open_store` | **ADDED** | Persist the queue to a path the HOST names - it knows where an app's data directory is on its own platform and the core does not. Answers the number of jobs loaded. A store that cannot be parsed is reported and never deleted. A job that was `running` when the file was written comes back `interrupted`. |

Jobs are listed in submission order. `pf_job_remove` accepts only a
FINISHED job (`done`, `failed`, `cancelled`, `interrupted`); a running
or queued one is refused, so a misclick cannot throw away work.
