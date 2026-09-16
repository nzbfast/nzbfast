//! THE ONE COPY of every default the desktop apps show.
//!
//! Two apps, two languages, one set of defaults. The macOS app and the
//! Windows app each render the Settings pane of
//! `research/PLAN-PARFAST-GUI-2026-09-12.md` section 5.6, and if either
//! carried its own literal for "10% recovery" the two would disagree
//! the first time one of them was corrected. So neither carries any: a
//! fresh session answers `pf_settings_get` from [`Settings::default`]
//! and the panes render what comes back.
//!
//! # The shape is GROUPED, and a flat write is refused
//!
//! Section 5.6's five groups are five nested objects - `general`,
//! `create`, `performance`, `integration`, `advanced` - plus three
//! top-level scalars (`concurrency`, `post_queue_action`,
//! `log_tail_lines`). Keys are snake_case and every one of them is
//! OPTIONAL on the way in ([`serde(default)`]), so a host that sends a
//! partial object gets the defaults for whatever it left out.
//!
//! Unknown keys are IGNORED rather than refused, so a host built
//! against a different build of this crate is never stopped by a field
//! only one side has learned. THAT TOLERANCE HAD A HOLE IN IT, found
//! by the Windows lane on 12 Sep 2026 driving the real FFI from C#: it
//! sent `{"notifications": false, ..., "concurrency": 3}` FLAT, and
//! because `concurrency` really is top-level while `notifications`
//! belongs to `general`, half the write landed and half of it vanished
//! without a word. A host cannot tell that from a rejected write, and
//! `pf_settings_get` afterwards just shows the old value - which reads
//! as the core dropping a field it was given.
//!
//! So the tolerance is now NARROWED to what it was for. A top-level key
//! this build does not know is still ignored (that is the
//! forward-compatible case, and [`Settings::from_json_reporting`] lists
//! them so a host can log what was dropped). A top-level key that is a
//! MEMBER NAME OF ONE OF THE GROUPS is REFUSED, naming the group it
//! belongs to, because there is no future in which that is a new field
//! rather than a misplaced one. The two are told apart from the
//! SERIALIZED DEFAULT object at runtime, not from a hand list, so a
//! field added to any group is covered the day it is added.

use serde::{Deserialize, Serialize};

/// What opening a `.par2` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OpenAction {
    /// Verify and stop, which is what every rival does.
    #[default]
    Verify,
    /// Verify, and repair without asking if it is damaged and
    /// repairable.
    VerifyThenRepair,
}

/// How a create job allocates blocks when the pane has not been touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlockAllocation {
    /// A block SIZE in bytes.
    Size,
    /// A block COUNT, which is the reference's own default (`-b`).
    #[default]
    Count,
}

/// How a create job allocates recovery data when the pane has not been
/// touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAllocation {
    /// A percentage of the source block count, the reference's default.
    #[default]
    Percent,
    /// A recovery block count (`-c`).
    Count,
    /// A target size in bytes (`-r<c><n>`).
    Size,
}

/// What the queue does after its last job finishes. The SESSION never
/// sleeps or shuts down a machine: it reports the action and the host
/// performs it, because only the host knows how to ask the platform and
/// only the host can put a confirmation in front of a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PostQueueAction {
    #[default]
    None,
    Notify,
    Sleep,
    Shutdown,
}

impl PostQueueAction {
    /// The wire spelling `pf_queue_set_post_action` takes.
    pub fn parse(s: &str) -> Option<PostQueueAction> {
        match s {
            "none" => Some(PostQueueAction::None),
            "notify" => Some(PostQueueAction::Notify),
            "sleep" => Some(PostQueueAction::Sleep),
            "shutdown" => Some(PostQueueAction::Shutdown),
            _ => None,
        }
    }

    /// The same spelling, back out.
    pub fn as_str(self) -> &'static str {
        match self {
            PostQueueAction::None => "none",
            PostQueueAction::Notify => "notify",
            PostQueueAction::Sleep => "sleep",
            PostQueueAction::Shutdown => "shutdown",
        }
    }
}

/// Section 5.6's General group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct General {
    pub open_par2: OpenAction,
    /// `-p`: delete the recovery files and the backups once a repair
    /// has completed. OFF, as the reference has it - the switch exists
    /// because deleting is not the safe default.
    pub purge_after_repair: bool,
    /// Keep the `<name>.1` copy of each damaged original. ON, because
    /// the copy is the only thing standing between a wrong repair and
    /// a lost file, and the reference keeps it too.
    pub keep_damaged_copies: bool,
    pub notifications: bool,
    /// Close the progress sheet on a clean finish.
    pub auto_close_progress: bool,
    /// v1 ships English only; the popup exists so the setting has
    /// somewhere to land when the 16 locales arrive.
    pub language: String,
}

impl Default for General {
    fn default() -> General {
        General {
            open_par2: OpenAction::default(),
            purge_after_repair: false,
            keep_damaged_copies: true,
            notifications: true,
            auto_close_progress: false,
            language: "en".to_string(),
        }
    }
}

/// Section 5.6's Create defaults group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CreateDefaults {
    pub block_allocation: BlockAllocation,
    /// The reference's own default block count, read from `parfast`
    /// rather than written again here.
    pub block_count: u64,
    pub block_size: u64,
    pub recovery_allocation: RecoveryAllocation,
    /// The reference's default redundancy, likewise read from
    /// `parfast`.
    pub recovery_percent: f64,
    pub recovery_count: u64,
    pub recovery_size: u64,
    /// Which of the five volume schemes a fresh Create pane offers.
    /// `pow2` is the engine's and the reference's default split.
    pub scheme: String,
    /// Spec-style `vol12-22` volume names rather than par2cmdline's
    /// `vol12+11`. OFF: every tool in the field reads the reference's
    /// spelling, and this is the one that some do not.
    pub std_naming: bool,
    pub unicode: String,
    pub overwrite: bool,
}

impl Default for CreateDefaults {
    fn default() -> CreateDefaults {
        CreateDefaults {
            block_allocation: BlockAllocation::default(),
            block_count: parfast::help::DEFAULT_BLOCK_COUNT,
            block_size: 0,
            recovery_allocation: RecoveryAllocation::default(),
            recovery_percent: f64::from(parfast::help::DEFAULT_REDUNDANCY_PCT),
            recovery_count: 0,
            recovery_size: 0,
            scheme: "pow2".to_string(),
            std_naming: false,
            unicode: "auto".to_string(),
            overwrite: false,
        }
    }
}

/// Section 5.6's Performance group. Every field here is a
/// process-GLOBAL knob in the engine, which is why the pane says so and
/// why the queue takes its lock before setting them - see
/// [`crate::runner`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Performance {
    /// `None` is `nzbkit::mem::cpu_workers()`, the one place this
    /// workspace derives a pool width from.
    pub threads: Option<usize>,
    pub memory_mb: Option<u64>,
    /// The EXPERIMENTAL joint solve (`--fast`). Off, as the CLI has it.
    pub fast_solver: bool,
    pub low_priority: bool,
    /// "Remember checksums of large files": the CLI's `--digest-cache`,
    /// the per-user store of validated whole-file digests
    /// (`nzbkit::digest_cache`). OFF, and opt-in only: a repeat create or
    /// full check of an unchanged large file re-proves its content with
    /// BLAKE3 and then skips the one-core MD5 pass. Published per job by
    /// [`crate::runner`], in both directions.
    pub digest_cache: bool,
    /// Start a second large single-file create beside a running one when
    /// the machine has the cores and the memory for both, whatever
    /// `concurrency` says - see [`crate::pairing`] for the rule. ON: such a
    /// create is bound by one serial MD5 chain and leaves most of a big
    /// machine idle, so a queue of them finishes in about half the time.
    /// It makes no single create faster, and from a spinning disk it buys
    /// nothing: with the source disk's reads capped at 200 and 120 MB/s the
    /// pair tied the serial queue (0.98-1.00x of its wall, addendum 8 of
    /// `research/PARFAST-SINGLE-FILE-MD5-HEADROOM-2026-09-13.md`), because
    /// the two creates split one disk's speed. Head seek, which that
    /// read cap could not model, can only make it worse, which is what
    /// turning it off is for.
    pub pair_large_creates: bool,
}

impl Default for Performance {
    fn default() -> Performance {
        Performance {
            threads: None,
            memory_mb: None,
            fast_solver: false,
            low_priority: false,
            digest_cache: false,
            pair_large_creates: true,
        }
    }
}

/// Section 5.6's Integration group. Nothing in this crate ACTS on any
/// of it: registering a file handler is a platform call in each app,
/// and the session only remembers what the human asked for so both apps
/// read one answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Integration {
    pub handle_par2: bool,
    pub handle_sfv: bool,
    pub handle_md5: bool,
    pub handle_sha256: bool,
    /// Finder Quick Action on macOS, Explorer context menu on Windows.
    pub shell_menu: bool,
}

impl Default for Integration {
    fn default() -> Integration {
        Integration {
            handle_par2: true,
            handle_sfv: false,
            handle_md5: false,
            handle_sha256: false,
            shell_menu: true,
        }
    }
}

/// Section 5.6's Advanced group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Advanced {
    /// Show the equivalent `parfast` command line on every pane that
    /// has one.
    pub show_command: bool,
    /// `verbose - quiet`, exactly as the two counters are seen on the
    /// command line: 0 is the reference's default, -2 is silence, 1
    /// adds the per-kernel trace.
    pub log_level: i32,
    pub log_folder: Option<String>,
}

impl Default for Advanced {
    fn default() -> Advanced {
        Advanced {
            show_command: true,
            log_level: 0,
            log_folder: None,
        }
    }
}

/// The whole settings object, as `pf_settings_get` returns it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub general: General,
    pub create: CreateDefaults,
    pub performance: Performance,
    pub integration: Integration,
    pub advanced: Advanced,
    /// How many jobs run at once. 1 is "Run one at a time", which is
    /// the default because every job here is already parallel inside
    /// and two of them mostly contend for the same disk.
    pub concurrency: u32,
    pub post_queue_action: PostQueueAction,
    /// How many log lines a snapshot carries. The drawer scrolls what
    /// the host has already collected; this bounds what one snapshot
    /// costs, not what the host may keep.
    pub log_tail_lines: usize,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            general: General::default(),
            create: CreateDefaults::default(),
            performance: Performance::default(),
            integration: Integration::default(),
            advanced: Advanced::default(),
            concurrency: Settings::DEFAULT_CONCURRENCY,
            post_queue_action: PostQueueAction::default(),
            log_tail_lines: Settings::DEFAULT_LOG_TAIL,
        }
    }
}

/// Why a settings object was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsError {
    /// `json` for text that did not parse, `misplaced_key` for a group
    /// member sent at the top level.
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// The object's real shape, read off the SERIALIZED DEFAULT rather than
/// from a hand list: `(top-level keys, member name -> the groups that
/// own it)`.
///
/// Derived and not written, so a field added to any group is known here
/// the day it is added and cannot be forgotten. A member name that is
/// ALSO a top-level key is not a misplacement and is left out of the
/// second map.
fn shape() -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeMap<String, Vec<String>>,
) {
    let mut top = std::collections::BTreeSet::new();
    let mut owners: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let Ok(serde_json::Value::Object(root)) = serde_json::to_value(Settings::default()) else {
        // Unreachable: `Settings` derives `Serialize` over plain data.
        // A refusal here would be worse than the hole it closes, so an
        // empty shape simply means "nothing is misplaced".
        return (top, owners);
    };
    for (k, v) in &root {
        top.insert(k.clone());
        if let serde_json::Value::Object(group) = v {
            for member in group.keys() {
                owners.entry(member.clone()).or_default().push(k.clone());
            }
        }
    }
    owners.retain(|member, _| !top.contains(member));
    (top, owners)
}

impl Settings {
    /// The default concurrency, named so a reader of `queue.rs` does
    /// not have to guess whether `1` there is a default or a floor.
    pub const DEFAULT_CONCURRENCY: u32 = 1;
    /// The default log tail depth.
    pub const DEFAULT_LOG_TAIL: usize = 500;

    /// Parse a settings object, filling in every key the caller left
    /// out. An empty object is [`Settings::default`].
    pub fn from_json(json: &str) -> Result<Settings, SettingsError> {
        Ok(Settings::from_json_reporting(json)?.0)
    }

    /// [`Settings::from_json`], plus the top-level keys this build did
    /// not know and therefore IGNORED.
    ///
    /// The list is what makes a silently dropped field visible: a host
    /// that logs it sees at once that it sent something the core threw
    /// away. A genuinely misplaced key - one that belongs to a group -
    /// is an error rather than an entry here; see the module docs.
    pub fn from_json_reporting(json: &str) -> Result<(Settings, Vec<String>), SettingsError> {
        let value: serde_json::Value = serde_json::from_str(json).map_err(|e| SettingsError {
            code: "json",
            message: e.to_string(),
        })?;
        let mut ignored = Vec::new();
        if let serde_json::Value::Object(sent) = &value {
            let (top, owners) = shape();
            for key in sent.keys() {
                if top.contains(key) {
                    continue;
                }
                if let Some(groups) = owners.get(key) {
                    return Err(SettingsError {
                        code: "misplaced_key",
                        message: format!(
                            "\"{key}\" is a key of the {} group, not a top-level one; send                              {{\"{}\":{{\"{key}\":...}}}}. The settings object is grouped -                              see pf_settings_get for its shape.",
                            groups.join(" or the "),
                            groups[0],
                        ),
                    });
                }
                ignored.push(key.clone());
            }
        }
        let settings = serde_json::from_value(value).map_err(|e| SettingsError {
            code: "json",
            message: e.to_string(),
        })?;
        Ok((settings, ignored))
    }

    /// The object `pf_settings_get` hands back.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_object_is_the_defaults() {
        let s = Settings::from_json("{}").expect("empty object parses");
        assert_eq!(s, Settings::default());
        assert_eq!(s.concurrency, Settings::DEFAULT_CONCURRENCY);
        assert_eq!(s.log_tail_lines, Settings::DEFAULT_LOG_TAIL);
    }

    /// THE WINDOWS LANE'S REPORT, 12 Sep 2026, pinned as it was sent.
    ///
    /// A FLAT object lands `concurrency` (which really is top-level) and
    /// loses `notifications` (which belongs to `general`), and before
    /// this refusal a host had no way at all to tell: the write
    /// returned success and `pf_settings_get` showed the old value, so
    /// it read as the core dropping a field it was given. It must now
    /// be an error that names the group.
    #[test]
    fn a_group_member_sent_at_the_top_level_is_refused_by_name() {
        let e = Settings::from_json(r#"{"notifications":false,"concurrency":3}"#)
            .expect_err("a flat write is refused");
        assert_eq!(e.code, "misplaced_key");
        assert!(e.message.contains("notifications"), "{}", e.message);
        assert!(e.message.contains("general"), "{}", e.message);
        // And nothing of a refused write lands: it is all or nothing,
        // which is the whole difference from what was reported.
        assert!(e.message.contains("pf_settings_get"), "{}", e.message);
    }

    /// The refusal is derived from the SERIALIZED DEFAULT, so it covers
    /// every group and every member without a hand list to go stale.
    /// One member of each of the five groups, by way of proof.
    #[test]
    fn every_group_is_covered_by_the_misplacement_refusal() {
        for (key, group) in [
            ("purge_after_repair", "general"),
            ("block_allocation", "create"),
            ("fast_solver", "performance"),
            ("handle_par2", "integration"),
            ("show_command", "advanced"),
        ] {
            let json = format!(r#"{{"{key}":null}}"#);
            let e = Settings::from_json(&json).expect_err("{key} misplaced");
            assert_eq!(e.code, "misplaced_key", "{key}");
            assert!(e.message.contains(group), "{key}: {}", e.message);
        }
    }

    /// Failing to find is failing: if the shape reader ever stopped
    /// seeing the groups it would silently accept every misplacement
    /// again, and the test above would still pass on an empty map only
    /// if it were written the other way round. So pin the map itself.
    #[test]
    fn the_shape_reader_actually_finds_the_five_groups_and_three_scalars() {
        let (top, owners) = shape();
        for g in [
            "general",
            "create",
            "performance",
            "integration",
            "advanced",
        ] {
            assert!(top.contains(g), "top level lost {g}: {top:?}");
        }
        for scalar in ["concurrency", "post_queue_action", "log_tail_lines"] {
            assert!(top.contains(scalar), "top level lost {scalar}");
            assert!(
                !owners.contains_key(scalar),
                "{scalar} is top-level and must never be reported misplaced"
            );
        }
        assert!(owners.len() >= 25, "only {} member(s) mapped", owners.len());
        assert_eq!(
            owners.get("notifications").map(Vec::as_slice),
            Some(&["general".to_string()][..])
        );
    }

    /// A host that sends one key gets the defaults for the rest, and a
    /// key it has not learned yet is ignored rather than refused - the
    /// property that lets the two UI lanes ship against different
    /// builds of this crate. It is REPORTED, though, which is the half
    /// that was missing.
    #[test]
    fn an_unknown_top_level_key_is_ignored_but_reported() {
        let (s, ignored) =
            Settings::from_json_reporting(r#"{"something_from_2027":42,"concurrency":2}"#)
                .expect("an unknown key is not a refusal");
        assert_eq!(s.concurrency, 2);
        assert_eq!(ignored, vec!["something_from_2027".to_string()]);
    }

    #[test]
    fn a_partial_object_keeps_every_other_default_and_ignores_what_it_does_not_know() {
        let s = Settings::from_json(
            r#"{"general":{"purge_after_repair":true},"something_from_2027":42}"#,
        )
        .expect("partial object parses");
        assert!(s.general.purge_after_repair);
        assert!(s.general.keep_damaged_copies, "untouched key keeps default");
        assert_eq!(
            s.create.recovery_percent,
            CreateDefaults::default().recovery_percent
        );
    }

    #[test]
    fn settings_round_trip_through_json() {
        let mut s = Settings::default();
        s.performance.threads = Some(4);
        s.post_queue_action = PostQueueAction::Sleep;
        let back = Settings::from_json(&s.to_json()).expect("round trip");
        assert_eq!(back, s);
    }

    /// The create defaults are the REFERENCE's, read out of `parfast`
    /// rather than written again - so a probe that corrects either
    /// number in `parfast::help` corrects the GUI in the same commit.
    #[test]
    fn the_create_defaults_come_from_parfast_and_are_not_a_second_literal() {
        let d = CreateDefaults::default();
        assert_eq!(d.block_count, parfast::help::DEFAULT_BLOCK_COUNT);
        assert_eq!(
            d.recovery_percent,
            f64::from(parfast::help::DEFAULT_REDUNDANCY_PCT)
        );
    }

    #[test]
    fn the_post_queue_actions_round_trip_through_their_wire_spellings() {
        for a in [
            PostQueueAction::None,
            PostQueueAction::Notify,
            PostQueueAction::Sleep,
            PostQueueAction::Shutdown,
        ] {
            assert_eq!(PostQueueAction::parse(a.as_str()), Some(a));
        }
        assert_eq!(PostQueueAction::parse("hibernate"), None);
    }
}
