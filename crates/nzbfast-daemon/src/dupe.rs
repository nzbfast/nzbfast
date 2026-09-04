//! What counts as a duplicate at add time, and what the add reply says
//! about it.
//!
//! Three questions that are really one: does this stem collide with a
//! release already known (`dupe_collision`), does it collide through an
//! enriched ALIAS of the same show rather than a matching string
//! (`dupe_alias_collision`), and did the job we just added end up parked
//! as a held alternative rather than queued (`held_as_duplicate`, which
//! is read back because `enqueue`'s signature is shared by sixteen call
//! sites).
//!
//! Split out of `crates/nzbfast-daemon/src/daemon.rs` whole (TODO 106 size gate) - the code
//! is verbatim, only its home changed. `pub(super)` and `pub(crate)`
//! mean here exactly what they meant there: this file is another child
//! of the daemon crate root, which is what `serve` was when both lived
//! in the bin.

use super::*;

impl Daemon {
    /// Where an equivalent release already lives, if anywhere: `("queue" |
    /// "history", that job's name)`. This is the M14f identity check,
    /// lifted out of `enqueue` so the UI can ASK before it adds rather
    /// than only discovering the hold afterwards - a wall Play that
    /// silently became a paused duplicate looked, from the outside, like
    /// a download that simply never started.
    ///
    /// PROPERs are never duplicates, and a stem with no derivable key is
    /// never one either. Same rules the hold itself applies, because it
    /// is the same code.
    ///
    /// `cfg(any(feature = "indexer", test))` because the only PRODUCTION
    /// caller is `m_index_dupe`, and `api/index.rs` is gated on
    /// `indexer` whole - so with the indexer off this wrapper is dead in
    /// the bin build. Both arms are load-bearing and the second is the
    /// one that is easy to get wrong: it is NOT dead in the slim TEST
    /// build, because `a_deleted_release_is_not_a_duplicate_until_the_mark_is_spent`
    /// calls it and is not itself gated, so a bare `indexer` cfg here
    /// stops the slim test build compiling. `enqueue` reaches the same
    /// scans through `dupe_collision_except` and is unconditional; what
    /// is conditional is only this ASK-before-you-add door.
    ///
    /// Not `#[expect(dead_code)]`: `dead_code` is a rustc lint judged in
    /// every configuration, so an expectation that is fulfilled slim
    /// goes UNFULFILLED in the default build - see CLAUDE.md's
    /// FIFTEENTH gate entry.
    #[cfg(any(feature = "indexer", test))]
    pub fn dupe_collision(&self, stem: &str) -> Option<DupeCollision> {
        self.dupe_collision_except(stem, None)
    }

    /// [`Self::dupe_collision`] with one record forgiven.
    ///
    /// `except` is a row this add is REPLACING, so colliding with it is
    /// not a duplicate (§290, Codex F-09). It is applied inside both
    /// scans rather than to the answer, because these scans report the
    /// FIRST hit: filtering afterwards would let the forgiven row mask
    /// an unrelated live copy sitting behind it in the queue.
    fn dupe_collision_except(&self, stem: &str, except: Option<&str>) -> Option<DupeCollision> {
        if is_proper(stem) {
            return None;
        }
        // The user deleted this release and is asking for it again. That
        // is not a duplicate, it is the same instruction twice, and the
        // hold used to answer it by parking the re-add paused behind
        // whatever else still carried the identity - a leftover twin
        // record, an *arr's own re-grab, an older copy of the episode -
        // with no way out but a control they had to go and find. A
        // deleted record is one the user has said they do not have,
        // whatever is still sitting on disk; see `note_releases_deleted`
        // for what stamps the mark and `clear_delete_mark` for what
        // spends it.
        if let Some(was) = self.deleted_recently(stem) {
            info!(
                target: "queue",
                "{stem:?} is not held as a duplicate - you deleted {was:?} \
                 recently, so this add is the re-download you asked for"
            );
            return None;
        }
        // dupe_scope = "exact" (#41): only a re-add of the same release
        // name is a duplicate, compared through `exact_dupe_key` so
        // separator styles still meet. The smart key stays on the job
        // either way - held alternatives keep auto-promoting by
        // identity, this only narrows what collides at add time.
        let exact = self.dupe_scope.lock_ok().as_str() == "exact";
        let smart_k = dupe_key(stem);
        let exact_k = exact_dupe_key(stem);
        if exact {
            if exact_k.is_empty() {
                return None;
            }
        } else {
            smart_k.as_ref()?;
        }
        let hit = |g: &Job| {
            if exact {
                exact_dupe_key(&g.name) == exact_k
            } else {
                g.dupe_key == smart_k
            }
        };
        let queued = self.queue.lock_ok().iter().find_map(|j| {
            let g = j.lock_ok();
            (Some(g.nzo_id.as_str()) != except && hit(&g)).then(|| DupeCollision {
                where_: "queue",
                name: g.name.clone(),
                nzo_id: g.nzo_id.clone(),
            })
        });
        if queued.is_some() {
            return queued;
        }
        let done = self.history.lock_ok().iter().find_map(|j| {
            let g = j.lock_ok();
            (Some(g.nzo_id.as_str()) != except && hit(&g) && g.state == JobState::Completed).then(
                || DupeCollision {
                    where_: "history",
                    name: g.name.clone(),
                    nzo_id: g.nzo_id.clone(),
                },
            )
        });
        if done.is_some() {
            return done;
        }
        if exact {
            return None;
        }
        self.dupe_alias_collision(stem, &smart_k?, except)
    }

    /// The alias arm of the smart duplicate check: the SAME episode of
    /// the SAME show, posted under a different spelling of the show's
    /// name ("Show.S01E06" vs "Show.The.Full.Subtitle.S01E06"). The two
    /// spellings flatten to different dupe keys, so the key comparison
    /// above can never meet them - Gary downloaded one episode twice on
    /// 14 Aug 2026 exactly this way.
    ///
    /// "Same show" is never guessed from the strings. A prefix or
    /// containment rule would also match a spin-off whose name extends
    /// its parent's, and a false duplicate silently SKIPS a wanted
    /// download - strictly worse than the duplicate it prevents. The
    /// only accepted witness is the index's enrichment record: both
    /// title keys resolved, independently, to the same TVmaze show id.
    /// No index, no enrichment yet, or either title unresolved → not a
    /// duplicate, same as before this arm existed.
    fn dupe_alias_collision(
        &self,
        stem: &str,
        smart_k: &str,
        except: Option<&str>,
    ) -> Option<DupeCollision> {
        // Only the SxxEyy identity. Movie years and daily dates carry
        // their own aliasing questions; this arm answers the one that
        // bit.
        let (head, ep) = smart_k.rsplit_once('/')?;
        let digits = ep.strip_prefix('s')?;
        let (s, e) = digits.split_once('e')?;
        if s.is_empty()
            || e.is_empty()
            || !s.bytes().all(|c| c.is_ascii_digit())
            || !e.bytes().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        // A job is a candidate when its key names the same episode of a
        // DIFFERENT title.
        let same_ep = |g: &Job| {
            g.dupe_key
                .as_deref()
                .and_then(|k| k.rsplit_once('/'))
                .is_some_and(|(h, other)| other == ep && h != head)
        };
        // Four gates, all conjunctive, ordered by what they cost rather
        // than by when they were written. The ANSWER is unchanged - each
        // one alone is enough to make this arm say "not a duplicate" -
        // but the walk that ALLOCATES is now last, behind the two O(1)
        // string tests and behind an existence walk that clones nothing.
        //
        // It was the other way round, and on a long queue that mattered:
        // the arm built a `DupeCollision` (two String clones) for every
        // row naming this episode before asking whether the add was even
        // a TV release, so a queue of one show's season paid 2N
        // allocations on every add to reach a `None` two string
        // comparisons could have given (audit round 21's quadratic add
        // path; this is its third term, behind the same-post arm and
        // `save_queue`).
        let parsed = nzbkit::release::parse_release(stem);
        if parsed.kind != nzbkit::release::Kind::Tv {
            return None;
        }
        // The existence question, allocation-free, and BEFORE the index
        // read: no candidate rows means no lookup, so an add against a
        // queue that names no other spelling of this episode still costs
        // this arm nothing but the walk.
        let any_cand = self.queue.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            Some(g.nzo_id.as_str()) != except && same_ep(&g)
        }) || self.history.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            Some(g.nzo_id.as_str()) != except && same_ep(&g) && g.state == JobState::Completed
        });
        if !any_cand {
            return None;
        }
        // The add's own show id gates everything: unresolved means no
        // candidate can be proven the same show, so no lookups run at
        // all and the ordinary add pays nothing here.
        let my_id = self.tv_show_id(&parsed.key)?;
        // Only now, with a candidate known to exist and the add's show
        // resolved, is the candidate LIST worth building. Collected
        // under the queue/history locks (cheap clones only - the index
        // reads below must not run under either).
        let mut cands: Vec<DupeCollision> = self
            .queue
            .lock_ok()
            .iter()
            .filter_map(|j| {
                let g = j.lock_ok();
                (Some(g.nzo_id.as_str()) != except && same_ep(&g)).then(|| DupeCollision {
                    where_: "queue",
                    name: g.name.clone(),
                    nzo_id: g.nzo_id.clone(),
                })
            })
            .collect();
        cands.extend(self.history.lock_ok().iter().filter_map(|j| {
            let g = j.lock_ok();
            (Some(g.nzo_id.as_str()) != except && same_ep(&g) && g.state == JobState::Completed)
                .then(|| DupeCollision {
                    where_: "history",
                    name: g.name.clone(),
                    nzo_id: g.nzo_id.clone(),
                })
        }));
        cands.into_iter().find(|c| {
            let q = nzbkit::release::parse_release(&c.name);
            // The whole (provider, id) pair, never the number alone: one
            // column carries TVmaze, AniList and TMDB numbering, all of
            // them small and dense, so an equal number across two
            // namespaces means nothing at all (Codex sweep 7, H2).
            q.kind == nzbkit::release::Kind::Tv && self.tv_show_id(&q.key).as_ref() == Some(&my_id)
        })
    }

    /// The whole of `enqueue_as`'s duplicate question: nothing for an
    /// add that may not be held ([`DupeExempt::Anybody`] - the wall's
    /// asked-and-said-yes, or a spare, where the caller already decided
    /// its fate), else name identity first and §292's message-id arm
    /// behind it. Both arms yield the same `DupeCollision`, so the
    /// ladder downstream - pause/discard/fail, `held_for`, park
    /// promotion - treats the two identically.
    ///
    /// [`DupeExempt::Row`] forgives ONE record and asks both arms
    /// anyway, which is what the hunt's replacement needs and what a
    /// bool could not say: a copy that replaces a failed row is still
    /// an ordinary duplicate of every OTHER live copy of that release.
    pub(super) fn add_collision(
        &self,
        stem: &str,
        mine: &spare::PostIds,
        total_bytes: u64,
        exempt: DupeExempt<'_>,
    ) -> Option<DupeCollision> {
        if matches!(exempt, DupeExempt::Anybody) {
            return None;
        }
        let except = exempt.row();
        self.dupe_collision_except(stem, except)
            .or_else(|| self.dupe_post_collision(mine, total_bytes, except))
    }

    /// §292: the SAME-POST arm of the duplicate question, consulted by
    /// `enqueue_as` only when the name arm found nothing. Two grabs of
    /// one post from two indexers routinely carry different names - an
    /// obfuscated stem on each, or one indexer's re-title of the
    /// other's row - and no name key can ever meet them; the
    /// message-id set can. The identity is spare.rs's own §282
    /// admission question pointed the other way (`post_ids` /
    /// `post_covers`), directional and conservative for the reason
    /// written at `SAME_POST_COVERAGE`.
    ///
    /// QUEUE rows only, on purpose: a history arm means parsing a
    /// spooled NZB for every completed row on every add, and the waste
    /// this exists to stop is two indexers grabbing one post around
    /// the same time - two live queue rows. Rows that are themselves
    /// held (`held_for` non-empty - a §282 spare, or an already-held
    /// duplicate) are not collision targets: holding a user's explicit
    /// add behind a row that is itself paused inverts who asked for
    /// what, and a spare is CHOSEN disjoint from its primary anyway.
    /// Tombstoned rows are mid-delete and out for the same reason the
    /// stands re-check exists.
    ///
    /// The spool parses run OUTSIDE the queue lock, against a snapshot
    /// of candidate rows - the #38 lesson, same as the alias arm above:
    /// nothing slow runs under that lock. A declared-size prefilter
    /// keeps the parse count to rows that could possibly be the same
    /// post; the one shape it can miss (an add that is a SMALL slice
    /// of a much larger queued post, more than 4x apart in declared
    /// bytes) is judged not worth parsing every spool on every add.
    ///
    /// And since 3 Sep 2026 a row is parsed at most ONCE, not once per
    /// add: [`Daemon::post_ids`] memoises what the parse produced, so
    /// the walk below is a map lookup and `mine.len()` hash probes per
    /// row rather than a file read. It has to be, because the parses
    /// were the whole of audit round 21's quadratic add path - a
    /// 5,000-job build through `mode=addfile` took 1,162.6 s and the
    /// per-add cost ROSE with the queue (44.6 ms/add over the first
    /// 500, 232.5 ms/add as the mean), which is this arm's shape and
    /// not the name arm's. `mine` arrives hashed for the same reason:
    /// the add's own ids are wanted twice (here, and as this row's memo
    /// entry at the publish) and are worth hashing once.
    ///
    /// `except` forgives ONE row, for the reason written at
    /// [`Self::dupe_collision_except`]: the record a hunted replacement
    /// is replacing is not a duplicate of itself, and every other row
    /// still is. Applied in the scan and not to the answer, so a
    /// forgiven row cannot mask the one behind it.
    pub(crate) fn dupe_post_collision(
        &self,
        mine: &spare::PostIds,
        total_bytes: u64,
        except: Option<&str>,
    ) -> Option<DupeCollision> {
        let prefilter = |bytes: u64| {
            if total_bytes == 0 || bytes == 0 {
                return true;
            }
            let (lo, hi) = if bytes < total_bytes {
                (bytes, total_bytes)
            } else {
                (total_bytes, bytes)
            };
            hi <= lo.saturating_mul(4)
        };
        // Pass one, under the queue lock: answer every row the memo
        // already knows, and collect ONLY the rows it does not. A row
        // the memo answers costs a map lookup and `add.len()` hash
        // probes; on a queue this daemon built itself the memo knows
        // all of them, so the pass allocates nothing at all.
        //
        // The scan still stops at the FIRST covering row in queue
        // order, which is why an answered hit does not end it on its
        // own: an UNANSWERED row ahead of it could cover too, and pass
        // two settles those first. Rows behind the hit cannot win, so
        // the walk breaks there.
        let mut misses: Vec<(String, String, PathBuf)> = Vec::new();
        let mut hit: Option<DupeCollision> = None;
        {
            let q = self.queue.lock_ok();
            let memo = self.post_ids.lock_ok();
            for j in q.iter() {
                let g = j.lock_ok();
                if !g.held_for.is_empty() || g.tombstone || Some(g.nzo_id.as_str()) == except {
                    continue;
                }
                if !prefilter(g.total_bytes) {
                    continue;
                }
                match memo.get(&g.nzo_id) {
                    Some(ids) => {
                        if spare::post_covers(ids, mine) {
                            hit = Some(DupeCollision {
                                where_: "queue",
                                name: g.name.clone(),
                                nzo_id: g.nzo_id.clone(),
                            });
                            break;
                        }
                    }
                    // Nothing slow under this lock (the #38 lesson): the
                    // spool read and the parse happen below, against a
                    // snapshot, exactly as they did before the memo.
                    None => misses.push((g.nzo_id.clone(), g.name.clone(), g.nzb_path.clone())),
                }
            }
        }
        for (nzo_id, name, path) in misses {
            let Some(row) = spare::nzb_at(&path) else {
                // An unreadable spool is not knowing, and not knowing is
                // not cached: the next add asks the file again. Same
                // answer this arm gave before the memo existed.
                continue;
            };
            let ids = Arc::new(spare::post_ids(&row));
            self.post_ids
                .lock_ok()
                .insert(nzo_id.clone(), Arc::clone(&ids));
            if spare::post_covers(&ids, mine) {
                hit = Some(DupeCollision {
                    where_: "queue",
                    name,
                    nzo_id,
                });
                break;
            }
        }
        self.evict_post_ids();
        if let Some(c) = &hit {
            info!(
                target: "queue",
                "same post as {:?} ({}) by message-id identity - \
                 the duplicate ladder decides what this add becomes",
                c.name, c.nzo_id
            );
        }
        hit
    }

    /// Drop memo entries for rows that have left the queue.
    ///
    /// Membership, not age: the memo describes queued rows and nothing
    /// else, so the live queue is the whole of the eviction rule. It is
    /// only consulted when the map has outgrown the queue by more than
    /// the slack below, because the retain itself is a walk of both and
    /// an add that leaves the map the right size must not pay for one.
    ///
    /// A survivor of a missed eviction is harmless - see the field: the
    /// memo never decides membership - so this is a memory bound and not
    /// a correctness one.
    pub(crate) fn evict_post_ids(&self) {
        let qlen = self.queue.lock_ok().len();
        if self.post_ids.lock_ok().len() <= 2 * qlen + 64 {
            return;
        }
        let live: std::collections::HashSet<String> = self
            .queue
            .lock_ok()
            .iter()
            .map(|j| j.lock_ok().nzo_id.clone())
            .collect();
        self.post_ids.lock_ok().retain(|id, _| live.contains(id));
    }

    /// Does the collision `dupe_collision` picked still exist?
    ///
    /// Admission holds `add_lock`, but deletion does not - a queue
    /// delete takes the queue lock and a history delete the history
    /// lock, and neither asks the adder's permission. So the original
    /// an add chose to hold against can be gone by the time that add
    /// publishes, and the alternative lands paused with `held_for`
    /// naming a record nobody will ever fail: park promotion is what
    /// releases a hold, and a job that no longer exists never parks.
    ///
    /// By id and by STORE, exactly as the pick was made: a history hit
    /// only counts while it is still `Completed` (a record retried back
    /// into the queue is no longer the finished copy that made this a
    /// duplicate). See `enqueue`, which re-asks this under the queue
    /// lock it publishes with.
    pub(super) fn dupe_collision_stands(&self, c: &DupeCollision) -> bool {
        if c.where_ == "queue" {
            self.queue
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == c.nzo_id)
        } else {
            self.history.lock_ok().iter().any(|j| {
                let g = j.lock_ok();
                g.nzo_id == c.nzo_id && g.state == JobState::Completed
            })
        }
    }

    // `enqueue` lives in daemon_enqueue.rs (TODO 106 size-gate split),
    // a child module declared at the top of this file.

    /// Truth-audit I: did this job park as a held ALTERNATIVE instead of
    /// joining the queue to run? Read back rather than returned out of
    /// `enqueue`, whose signature sixteen call sites share; the job is in
    /// the queue by the time any caller can ask, and reading it here also
    /// answers correctly for the paths that add through
    /// `enqueue_fetched`.
    ///
    /// Without this the add reply said "Added to the queue" for a job that
    /// is paused at Duplicate priority and will not download until the
    /// original fails - the single most confusing thing the add flow could
    /// say, because the row then sits there doing nothing with no
    /// explanation the user asked for.
    pub fn held_as_duplicate(&self, nzo_id: &str) -> bool {
        self.queue.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            g.nzo_id == nzo_id && g.paused && g.priority == DUPE_PRIORITY
        })
    }
}

/// One release the USER deleted, kept just long enough to stop the
/// duplicate machinery arguing with them about it.
///
/// Both keys, because both are what a hold is decided by: `exact` is the
/// same-release-again comparison (`dupe_scope = "exact"`), `smart` the
/// same-episode/film identity. A mark matches an add when EITHER meets
/// it - the mark only ever releases a hold, never creates one, so the
/// generous side is the safe side.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct DeleteMark {
    /// What the deleted record was called. Not used for matching - it is
    /// what the log line says, and a key alone names nothing a person
    /// would recognise.
    pub name: String,
    pub exact: String,
    pub smart: Option<String>,
    pub at: i64,
}

/// How long the user's delete speaks for them. Long enough to cover
/// "delete, restart the machine to shake the file lock loose, add it
/// again" - the exact loop a refused Trash sends people round - and
/// short enough that a mark cannot sit there for a week releasing holds
/// nobody remembers asking for.
const DELETE_MARK_SECS: i64 = 24 * 3600;

impl Daemon {
    /// Remember that the user deleted these releases.
    ///
    /// One call per delete REQUEST, not per record: a bulk history sweep
    /// is one save, not five hundred.
    pub fn note_releases_deleted(&self, names: &[String]) {
        if names.is_empty() {
            return;
        }
        {
            let now = unix_now();
            let mut m = self.deleted_recent.lock_ok();
            m.retain(|d| now - d.at < DELETE_MARK_SECS);
            for name in names {
                let exact = exact_dupe_key(name);
                let smart = dupe_key(name);
                // A release deleted twice is one mark, re-stamped: the
                // second delete is the fresher statement of intent.
                m.retain(|d| !mark_meets(d, &exact, &smart));
                m.push_back(DeleteMark {
                    name: name.clone(),
                    exact,
                    smart,
                    at: now,
                });
            }
            while m.len() > 64 {
                m.pop_front();
            }
        }
        self.save_deleted_recent();
    }

    /// Did the user delete this release recently? A peek - see
    /// `clear_delete_mark` for the half that spends it.
    ///
    /// Read by `dupe_collision`, so every caller of the duplicate check
    /// agrees: the queue hold, the wall's "you already have this"
    /// question and the *arr-facing add reply all stop claiming a
    /// release the user has just told us they no longer have.
    pub fn deleted_recently(&self, stem: &str) -> Option<String> {
        let (exact, smart) = (exact_dupe_key(stem), dupe_key(stem));
        let now = unix_now();
        self.deleted_recent
            .lock_ok()
            .iter()
            .find(|d| now - d.at < DELETE_MARK_SECS && mark_meets(d, &exact, &smart))
            .map(|d| d.name.clone())
    }

    /// Spend the mark: this release has now been re-added, so the user's
    /// delete has been honoured and the NEXT copy is an ordinary
    /// duplicate of the one just queued.
    ///
    /// Without this the window would leave the identity unprotected for
    /// a whole day - two adds of one release would both queue and both
    /// download, which is the thing the hold exists to stop.
    pub fn clear_delete_mark(&self, stem: &str) {
        let (exact, smart) = (exact_dupe_key(stem), dupe_key(stem));
        let spent = {
            let mut m = self.deleted_recent.lock_ok();
            let before = m.len();
            m.retain(|d| !mark_meets(d, &exact, &smart));
            m.len() < before
        };
        if spent {
            self.save_deleted_recent();
        }
    }

    /// Persist the marks to `.spool/deleted-recent.json`.
    ///
    /// They outlive the process for the same reason the kept-files
    /// notice does, and in the same story: the advice for a delete the
    /// Trash refused is to try again in a few minutes, and restarting
    /// the daemon (or the machine) is what people actually do in
    /// between. A mark lost at that restart is a hold the user then has
    /// to force their way past - which is exactly the round trip this
    /// exists to end.
    ///
    /// Lock held across the write, like `save_delete_kept`, so two
    /// writers cannot land in the opposite order to the states they
    /// carry. It is a leaf: no queue or history lock is held by any
    /// caller of `note_releases_deleted`.
    pub fn save_deleted_recent(&self) {
        let path = self.spool.join("deleted-recent.json");
        let m = self.deleted_recent.lock_ok();
        if let Ok(text) = serde_json::to_string_pretty(&*m) {
            let _ = crate::persist::write_atomic(&path, text.as_bytes());
        }
    }
}

/// Does this mark speak for the release these keys describe?
///
/// An empty `exact` never matches (a name that normalises to nothing
/// would otherwise meet every other one), and a `None` smart key never
/// matches for the same reason - `dupe_key` returns None when the name
/// carries no episode or year to be identified by, and two unidentified
/// releases are not the same release.
fn mark_meets(mark: &DeleteMark, exact: &str, smart: &Option<String>) -> bool {
    (!exact.is_empty() && mark.exact == *exact)
        || (smart.is_some() && mark.smart.is_some() && mark.smart == *smart)
}
