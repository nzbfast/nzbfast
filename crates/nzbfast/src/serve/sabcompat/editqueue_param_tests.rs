//! The `editqueue` `Param` slot, in every shape NZBGet's own clients put
//! it in. See [`super::editqueue_param`] for why reading it as a string
//! alone dropped a move offset and mis-rung a priority write in silence.

use super::{editqueue_param, nzbget_priority};
use serde_json::{Value, json};

/// v13+ `[Command, Param, IDs]` with the param written as a JSON NUMBER,
/// which is what a JSON-RPC client does with an integer argument. This is
/// the shape the string-only read could not see at all.
#[test]
fn a_numeric_param_is_read_as_its_digits() {
    let p: Vec<Value> = json!(["GroupMoveOffset", -3, [7, 8]])
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(editqueue_param(&p), "-3");
    assert_eq!(editqueue_param(&p).trim().parse::<i64>().unwrap_or(0), -3);
}

/// And the consequence the caller cares about: a numeric NZBGet priority
/// must reach `nzbget_priority` as itself, not as the 0 an empty string
/// parses to - 0 is Normal, so a client asking for Force got Normal and
/// was answered `true`.
#[test]
fn a_numeric_priority_does_not_collapse_to_normal() {
    let p: Vec<Value> = json!(["GroupSetPriority", 900, [1]])
        .as_array()
        .unwrap()
        .clone();
    let prio = nzbget_priority(editqueue_param(&p).trim().parse::<i64>().unwrap_or(0));
    assert_eq!(prio, 2, "900 is Force on NZBGet's scale");
    assert_ne!(prio, nzbget_priority(0), "and Force is not Normal");
}

/// The v13+ string spelling every current client uses stays exactly as it
/// was - this is the shape the whole facade was written against.
#[test]
fn a_string_param_still_wins() {
    let p: Vec<Value> = json!(["GroupSetName", "The.Name", [4]])
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(editqueue_param(&p), "The.Name");
}

/// The legacy `[Command, Offset, Text, IDs]` shape, where the offset is a
/// number at index 1 and `Text` at index 2 is empty. The string-only read
/// found the EMPTY string and moved nothing.
#[test]
fn the_legacy_offset_shape_finds_its_offset_past_an_empty_text() {
    let p: Vec<Value> = json!(["GroupMoveOffset", 5, "", [2]])
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(editqueue_param(&p), "5");
}

/// ...and when that legacy `Text` is a real one it is still what the
/// text subcommands mean, offset or no offset beside it.
#[test]
fn a_non_empty_legacy_text_beats_the_offset_beside_it() {
    let p: Vec<Value> = json!(["GroupSetName", 0, "Renamed", [2]])
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(editqueue_param(&p), "Renamed");
}

/// No param at all - `[Command, IDs]` - is empty, not a panic and not the
/// id array read as a number.
#[test]
fn no_param_at_all_is_empty() {
    let p: Vec<Value> = json!(["GroupPause", [1, 2, 3]]).as_array().unwrap().clone();
    assert_eq!(editqueue_param(&p), "");
}

/// The command itself is never the param, even when a subcommand name
/// would parse: index 0 is skipped by construction.
#[test]
fn the_command_is_never_read_as_the_param() {
    let p: Vec<Value> = json!(["12", [1]]).as_array().unwrap().clone();
    assert_eq!(editqueue_param(&p), "");
}
