# Opt-in indexing

> **Path note.** This document was written when the daemon was one
> `crates/nzbfast/src/serve.rs`. It is a module tree under
> `crates/nzbfast/src/serve/` now (`mod.rs`, `http.rs`, `job.rs`,
> `settings.rs`, `assets.rs`, `api/`, ...). The function and mode
> names below are unchanged; only the file they live in moved.

## The problem

nzbfast's indexer never indexed anything on its own: `index_groups`
ships empty and an empty list means no scan. That much was already
right. Two things were missing.

1. There was no way to say WHAT you wanted without already knowing
   newsgroup names. The group browser is excellent for someone who knows
   that `alt.binaries.moovee` is films; it is useless as a first
   question.
2. The one shortcut that filled the gap - a button reading "Start
   indexing TV & movies" - subscribed `alt.binaries.teevee` and
   `alt.binaries.moovee` on the user's behalf. Small, but it is a topic
   choice the user never made, in the one part of the product where
   that matters most.

The requirement: ask, never assume. If the question goes unanswered,
nothing is indexed, and there is no fallback list anywhere behind it.

## The shape

An **interest** is a plain-language choice ("Sport", "Linux and other
freely distributable software") that stands for a short, named list of
newsgroups. Stored as `index_interests`, a comma list of stable keys, in
settings.json. Empty (or absent) means nothing.

Curated lists, not keyword search or "the busiest groups in this
category". Both of those were tried against the real catalogue and both
fail the same way: ranked by volume, "sport" is
`alt.binaries.wtfnzb.golf` (4.5 billion posts of deliberately scrambled
names) long before `alt.binaries.multimedia.sports`, and "software" is
`alt.binaries.warez`. A curated list is also the only kind that can be
PRINTED, which is the point - every surface that offers an interest
shows the exact groups it will scan, before the user agrees.

Definitions live in `crates/nzbfast-core/src/interests.rs`. A test asserts no
offered group name contains warez/pw-required/encrypt/erotica: an
interest has to be defensible in public.

## Resolution

Interests are chosen before the daemon has ever connected (the setup
wizard runs first), so the choice and its resolution are separate steps:

- `apply_interests` (serve.rs) resolves interests to groups against the
  provider's own catalogue, keeping only what that provider carries, and
  merges them into `index_groups`.
- It runs when the setting changes, at startup once a cached catalogue
  is loaded, and in the success arm of a catalogue fetch - which is the
  first-run path.
- `index_interests_applied` records what has already been applied, so a
  catalogue refresh never re-adds a group the user has since removed by
  hand.
- Unticking removes exactly the groups that ticking added. A group the
  user typed in themselves is never touched.

## Where it is asked

- **`nzbfast setup`** (the CLI wizard), right after the first server.
  Prints every option with its groups; Return means nothing. The answer
  is written to settings.json, and the menu grows an `i` entry so it can
  be changed later.
- **Settings -> Indexing**, the same options as checkboxes, each with
  the groups it stands for underneath, and with what the provider
  actually carries once that is known.
- **The first-run checklist** step 3 points at that card. The step is
  satisfied by an interest OR by hand-picked groups, so neither route
  nags the other.

The "Start indexing TV & movies" button is gone. There is now no path
in the product that picks a topic on a user's behalf.

## The first-run API key trap

The setup wizard is a SEPARATE PROCESS from the daemon, so its answer
lands in settings.json before the daemon has ever started - and the
first-run API key test keyed off exactly that file's existence. Writing
the answer would have left the daemon unkeyed, silently reopening the
hole that test exists to close.

`settings_beyond_setup_answers` fixes it: a settings.json containing
nothing but wizard answers (`SETUP_ANSWER_KEYS`) is still a first run.
An empty object is deliberately NOT - it carries no answer to explain
itself, so the old rule stands. Pinned by tests in both
`crates/nzbfast/tests/firstrun_key.rs` and serve.rs's own unit tests.

## Tests

`crates/nzbfast/tests/interests.rs` drives the real daemon with a seeded
catalogue cache (the same `groups.tsv` a fetch writes), so resolution is
testable without a provider:

- an install nobody answered for scans nothing, ever;
- a stored answer becomes exactly the groups that provider carries, and
  never a group nobody asked for;
- ticking and unticking are symmetric, and an unrecognised answer
  resolves to nothing rather than to something.
