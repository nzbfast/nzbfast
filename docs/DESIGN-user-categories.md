# User-definable categories (TODO 24D)

> **Path note.** This document was written when the daemon was one
> `crates/nzbfast/src/serve.rs`. It is a module tree under
> `crates/nzbfast/src/serve/` now (`mod.rs`, `http.rs`, `job.rs`,
> `settings.rs`, `assets.rs`, `api/`, ...). The function and mode
> names below are unchanged; only the file they live in moved.

The parser only knew `Movie | Tv | Software | Other`, so sport,
motorsport, wrestling, podcasts, audiobooks and comics all landed in
Movie or Other. That is the same root cause as the F1 dupe bug fixed in
`279f787`: `Formula1.2026.Round11...` parsed as Movie{"Formula1", 2026}
and every session of a season collapsed to one identity. Users can now
define their own categories and the rules that fill them.

## The shape

A category is stored in `settings.json` under `custom_categories`, an
ordered array (order = priority, first match wins - same convention as
Smart Folders):

```json
[{"slug": "formula-1", "name": "Formula 1",
  "match": "^formula\\.?1\\.", "not_match": "",
  "base": "movie"}]
```

- **slug** - the stored `kind` value and the API filter value.
  Lowercase `[a-z0-9-]`, validated against the reserved built-ins
  (`movie`/`tv`/`software`/`other`), no duplicates. The dashboard
  derives it from the name on first save and then pins it
  (`data-slug`), so renaming the display name never re-keys indexed
  rows.
- **match / not_match** - the Smart Folders rule syntax, verbatim:
  case-insensitive regex with a keyword-substring fallback. There is
  exactly ONE matching engine in the tree: `nzbkit::categories::
  pat_match`, which `smart.rs` now delegates to. One deliberate
  difference: an empty `match` is a catch-all in a Smart Folder rule
  but is REJECTED for a category (a catch-all category would swallow
  the whole index).
- **base** - the explicit answer to the finalize_names coupling, see
  below. `movie` | `tv` | `none`; default `none`.

Types live in `crates/nzbkit-base/src/categories.rs`
(`CustomCategory`, `BaseBehavior`, `classify`, `apply_custom`,
`base_of`, `validate`, `slugify`, `config_hash`). `release::Kind` gained
a `Custom(String)` variant carrying the slug; `parse_release` itself
never produces it - only `categories::classify` rewrites a parse, so the
pure parser stays rule-free and every existing parser test is
untouched.

## Decision: base-behavior inheritance (the finalize_names coupling)

`finalize_names` gated junk-sweep/keep-media-only and auto-rename on
`Kind::Movie | Kind::Tv`. A kind that is silently neither loses both
behaviors - that produced bugs twice in the week this was designed. Now
the gate is EXPLICIT: every kind resolves to a `BaseBehavior` via
`categories::base_of`:

- built-in Movie/Tv map to themselves; Software/Other to `None`;
- a custom kind maps to the base its category DECLARED;
- a custom kind whose category has since been deleted maps to `None`
  (files untouched is the only safe read).

Semantics: `movie`-base gets junk-sweep/keep-media-only and the
"Title (Year)" rename (which still declines event posts whose identity
lives after the year - the F1 guard in `movie_name` is unchanged);
`tv`-base gets junk-sweep and episode rename / Season filing; `none`
gets nothing. `none` is the default because keep-media-only DELETES
non-media files - for a comics or audiobook category that is the
payload, so inheritance must be opt-in, never guessed.

## Decision: dedupe keys (the F1 lesson)

A custom release's `title_key` is rebuilt so date/event releases can
never collapse by title+year:

- season-marked or daily-dated posts group by title, like TV:
  `c:<slug>:<title>` (episodes/dates distinguish within the card);
- everything else keeps every identity-bearing fact the parse found:
  `c:<slug>:<title>[:<year>][:<extra…>]`, where `extra` is the
  identity tail after the year ("round11 hungary qualifying") that the
  built-in movie key throws away.

So the two real F1 posts from the bug report key as
`c:formula-1:formula1:2026:round11 hungary qualifying f1tv` vs
`…:round11 hungary post qualifying show f1tv` - distinct cards, distinct
downloads, while two qualities of one session still share a key
(furniture never differentiates). The `c:` prefix keeps custom keys
disjoint from `m:`/`t:`/`s:`/`o:` space; `pretty_key` renders them
readably.

## Decision: classification and re-classification

Classification happens at ingest (`Index::ingest` runs
`categories::classify` via the `custom` list the daemon installs with
`Index::set_custom`) and at finalize (`finalize_names` classifies the
job name the same way). The ingest gate (`Gates::allows_with`) sees the
classified kind, so `"kinds": ["movie", "formula-1"]` does what it
reads as, and custom releases pass the DEFAULT gate (user-defined is
the opposite of junk).

When the config changes, stored rows are reconciled by
`Index::reclassify_custom` - a chunked pass copied from the junk_v7
migration shape (10k-row transactions, persisted `kv` cursor,
write-only-on-change) so it can run against a live db without starving
parallel scanners. The current config's fingerprint is stamped in `kv`
(`custom_cats_cfg`), so the pass is a no-op unless something actually
changed; an interrupted pass resumes from the cursor. Triggers: the
settings API sets `Daemon::reclassify_pending`, the scan loop consumes
it before the next pass; the flag also starts set so daemon startup
reconciles rows a CLI scan (which classifies built-in-only) or a
hand-edited settings.json left behind. Deleting a category re-runs the
pass and rows return to their built-in kinds.

`junk_score` treats a custom kind as wanted content: no "evidence-free
media" or tiny-post penalty (comics and podcasts are legitimately
tiny). The executable-in-media hammer (score 85) still applies to
custom kinds - malware protection wins; a category of intentionally
executable content is not supported in v1.

## Decision: *arr / SAB API compatibility

Untouched by construction. The SAB-compatible `cat`/`category` field is
the user's output-subfolder string (`Job.category`, `d.cats`), fully
independent of `kind`; Sonarr/Radarr round-trips (addfile with `cat=`,
queue/history echo) never touch the classifier. The newznab facade's
numeric categories are also unchanged by this work - custom kinds fall
in its existing "other" bucket. (The facade's own 4000/PC defect, listed
under Follow-ups, was fixed separately; the job-category strings the M26
certification matched on were not touched either way.) Nothing here
changes the M26 certification surface.

## Enumeration sites (every place that lists kinds, and what happened)

Compiler-checked (the `Kind::Custom` variant forces the match):
- `nzbkit::index::kind_str` - maps `Custom(slug)` to the slug (now
  returns `&str`, borrowed from the Kind).
- `nzbfast::wall::lookup` - custom is never enriched keylessly.
- `nzbfast::gates::allows_with` - consolidated onto `kind_str`.
- `serve.rs mode=index_search` - consolidated onto `kind_str` +
  `classify`.

String/SQL sites (swept by hand, per the grep map):
- **Gates kinds filter** (`gates.rs`): slug is a first-class `kinds`
  value; default gate passes customs. Tested.
- **finalize_names / keep_media_only / sweep_junk** (`serve.rs`): gated
  on `base_of`, see above.
- **Wall chips** (`web/wall.html`): tabs are now dynamic - the served
  `cats` array (on `wall2` and `index_browse` responses) renders one
  chip per category between the built-ins and Other; section headers,
  list-view chips and card badges show the category name; an orphaned
  active tab falls back to All.
- **wall2 / index_browse `cat=` param** (`serve.rs`): accepts built-ins
  plus any slug shape (`is_kind_slug`); the filter is a bound SQL
  parameter.
- **BrowseQuery.kind / browse_cards** (`index.rs`): pass-through
  equality, works with slugs unchanged. `index_browse` rows now
  classify with the custom set so the row's `key` matches the stored
  `title_key` (info sheet opens the right card).
- **Category grouping order** (`index.rs` `group_prefix` CASE): customs
  cluster between movies and software, each custom kind contiguous
  (secondary `MAX(r.kind)` sort) so one header per category renders.
- **seed_missing_titles** (`index.rs`): widened from
  `IN ('movie','tv')` to `NOT IN ('software','other','')` so custom
  cards get titles rows. The enricher is SAFE for them: the lane maps
  unknown kind strings to `Kind::Other`, which short-circuits to "no
  lookup" before any provider (a wrong TMDB poster for "Formula 1
  Round 11" would be worse than none).
- **junk_score** (`index.rs`): custom arm added, see above.
- **Eviction / index size cap**: NOT in this tree (the engine lives in
  the rescue patches, TODO 24A/24G). Contract for whoever lands it:
  the protected-kinds set must be the DYNAMIC kind set - treat any
  kind that is none of the built-in four as user-defined and protected
  unless explicitly opted out; the list is available from
  `get_config.custom_categories` and `Daemon::custom_categories`.
- **Watchlist** (`watchlist.rs`): DONE (follow-up landed). An item's
  `kind` may be a slug; `watchlist_pass` classifies every candidate
  through `categories::classify` with the user's list, so the watcher
  and ingest share one rule engine and a release answers to exactly one
  item kind (a film a category claimed is no longer grabbable by a
  "movie" item). Slot shape: an episode marker tracks per episode as TV
  does, and everything else tracks on the classified identity key
  (`c:<slug>:…`), so two sessions of one season never collapse into one
  slot. Year pins and season/episode scopes both apply, since a
  category can be either shape. The language gate is skipped for custom
  kinds - a Bundesliga category would otherwise match nothing. The
  daily-dated collision this section used to list as a known limit is
  closed: `Parsed` carries the episode date, the key above folds it in,
  and a bare-season post now fills that season's pack slot rather than
  none (the M23e pack preference rule: with nothing of a season in
  hand a pack is taken; against episodes already grabbed it must match
  the best single's quality and bring at least two missing episodes,
  and at least as many as it repeats).
  Index protection resolves the tailed keys through
  the index by prefix, the way a year-less film already did.
- **wall_search / wall_fix** (`serve.rs`): still movie/tv only - the
  fix-match flow is about metadata identity, which custom kinds don't
  have. Unchanged, documented.

## Non-video content: what the corpus test found

The watchlist follow-up was validated against a corpus of real post
names across music, football, motorsport, combat sports, wrestling,
podcasts, audiobooks, comics, cycling and anime. Three things were
broken for everything that is not a film or an episode, and are now
fixed:

1. **Titles.** The parser can only isolate a title when the stem has
   recognisable furniture to cut at. For everything else the "title" is
   most of the stem ("metallica 72 seasons cd flac 2023", "ufc 310 jones
   vs miocic ppv", "one piece 1085"), so exact title equality matched
   NOTHING - a music or UFC watch item looked wired up and grabbed
   nothing forever. A custom item now matches by word-boundary
   containment against the raw stem (the same text the category rule
   matched), and an empty title means the whole category. Built-in movie
   and TV items still compare exactly.
2. **Dated events.** The parser kept no date, so `EPL.2026.08.15.
   Arsenal.vs.Chelsea` and every other fixture of the season shared one
   identity. `Parsed` now carries `date` (yyyymmdd, both conventions)
   plus the identity tail after it, and a custom key is
   `c:<slug>:<title>:<date>:<event>`. A matchday is no longer one thing
   to grab.
3. **Queue-side identity.** `dupe_key`'s daily arm discarded everything
   after the date, so a second fixture of one Saturday was admitted
   PAUSED at priority -3 and only ever promoted if the first FAILED, and
   the watchlist adopted it as a slot it already owned. The daily arm now
   keeps the identity tail exactly as the movie-year arm does, and the
   watchlist only adopts a completed history entry that actually fills
   the slot in question.

Also fixed, one layer down: `keep_media_only` guarded non-video payload
by refusing to run on a job with no video, which a category declaring
base Movie breaks the moment one bonus .mp4 ships beside fifty .cbz
files. Payload extensions (audio, books, comics, cue/log) are now named
in `PAYLOAD_EXTS` and kept.

Known and left alone, with reasons:

- A daily post reposted the same day under a different description reads
  as a second event. The alternative collapses real same-day events,
  which is silent loss; a duplicate is visible and recoverable.
- `base: Tv` only files releases that carry a season/episode marker.
  Event posts have no marker and therefore no filing target; they are
  left as posted whatever the base says.
- The BUILT-IN keys are untouched: a daily show is still one wall card
  (`t:<title>`), and an event season without a category is still
  `m:<title>:<year>`. Defining a category is what turns a competition
  into per-event identities.
- `dupe_key` returns None for a yearless, non-episodic post (most music
  and numbered events), so those get no duplicate hold at all. That is
  pre-existing and belongs to a `dupe_key` change, not this one.
- The quality ladder is resolution-shaped, so every music/book release
  ranks 0. Harmless (first copy grabbed, no upgrade churn) but it means
  a resolution floor on such an item matches nothing.

## API / settings surface

- `mode=config&name=custom_categories&value=<json>` - validated as a
  whole (reserved/duplicate/invalid slug or empty match rejects the
  save and leaves the stored list untouched); listed in
  LOGGABLE_SETTINGS (rules are not credentials).
- `mode=get_config` → `config.nzbfast.custom_categories`.
- `wall2` / `index_browse` responses carry `cats:[{slug,name}]`.
- Startup load re-validates (a hand-edited settings.json can't smuggle
  a reserved slug).

## UI

Settings card "Your categories" (`web/dashboard.html`), modeled on the
Smart folders card: name / match / but-not / treat-as rows,
add + apply, focus-guarded read-back. The wall (`web/wall.html`) grows
its tabs, section headers, chips and badges from the served set;
category names are user text and render as-is (`data-i18n-skip`).

## i18n

14 new keys (`set.cats.*`), inline English defaults, extracted into
`en.reference.json`. `web/i18n/check.py` now reports `missing 14` for
each of the 26 non-English locales - translations are the sanctioned
follow-up. Category names themselves are user data and are never
translated.

## Follow-ups

- Translate the 14 `set.cats.*` keys (26 locales).
- ~~Watchlist custom-kind items~~ - landed; see above. Its three UI
  keys (`watch.kind.custom`, `browse.watch.cat`, `toast.wlAddedCat`)
  ship translated in all 27 locales.
- Eviction integration when 24A/24G land (contract above).
- Optional per-category enrichment (a category that IS a TV show could
  opt into TVmaze); deliberately out of v1.
- The pre-existing defects the sweep surfaced, none of which this
  change created: `kind='software'` rows unreachable from the wall's
  hardcoded tabs; ~~newznab `cat=4000` maps to `other` and misses
  software rows~~ (FIXED: 4000 is software in both directions, and the
  ids we carry no kind for return an empty feed instead of `other`;
  regression test `newznab_categories_follow_the_standard_tree`);
  `wall.cat.*` keys unscrapable by extract.js (KINDLBL passes variables
  to `t()`).
