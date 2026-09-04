// Slim builds compile out wall.rs (providers, enrichment, browse), but
// core filing/rename/queue code reaches the release-name parser and the
// eplist cache blob shape through `crate::wall::`. This shim keeps those
// paths alive; EpInfo mirrors wall.rs verbatim. Declared as `mod wall`
// via `#[path]` from both crate roots (main.rs and lib.rs).
pub use nzbkit::release::{
    Kind, NameStyle, Parsed, movie_name, norm_title, parse_release, quality_label, quality_suffix,
};

/// One episode from a TVmaze episode list (M23d airdate calendar).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EpInfo {
    pub season: u32,
    pub episode: u32,
    pub name: String,
    /// "YYYY-MM-DD"; empty when TVmaze doesn't know yet.
    #[serde(default)]
    pub airdate: String,
    /// The episode synopsis. TVmaze sends one for essentially every
    /// aired episode and we used to throw all of them away, which is
    /// what made "what have I watched, what is next" unanswerable.
    /// `#[serde(default)]` on every field added here: episode lists are
    /// cached as JSON in `kv`, and a blob written before a field existed
    /// must still deserialize rather than emptying the calendar.
    #[serde(default)]
    pub summary: String,
    /// Episode still (medium crop), empty when TVmaze has none.
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub rating: f64,
    /// Minutes; 0 when unknown.
    #[serde(default)]
    pub runtime: u32,
}
