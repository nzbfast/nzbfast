//! §192: the NZBGet contract as SHAPE. Everything here is a pin on a
//! third party's vocabulary rather than on our behaviour, which is why
//! it is worth testing at all: a chain that runs perfectly while
//! spelling `NZBPP_SCRIPTSTATUS` as `NZBPP_SCRIPT_STATUS` breaks every
//! script that reads it, silently, and no end-to-end assertion about
//! files on disk would notice.

use super::*;

#[test]
fn the_exit_code_vocabulary_is_nzbgets_and_not_a_rearrangement_of_it() {
    // 93 SUCCESS, 94 ERROR, 95 NONE. These three get transposed in
    // half the summaries of NZBGet's contract on the internet, and a
    // transposition turns "the script declined this job" into "the
    // script failed" for every extension in the catalogue.
    assert_eq!(analyse_exit(Some(93), true).0, ScriptStatus::Success);
    assert_eq!(analyse_exit(Some(94), true).0, ScriptStatus::Failure);
    assert_eq!(analyse_exit(Some(95), true).0, ScriptStatus::None);
    // 0 is a SUCCESS here and a FAILURE in NZBGet, deliberately: the
    // same hook runs SABnzbd-contract scripts, which say "fine" with 0.
    assert_eq!(analyse_exit(Some(0), true).0, ScriptStatus::Success);
    // Anything else, and the deadline kill, are failures.
    assert_eq!(analyse_exit(Some(1), true).0, ScriptStatus::Failure);
    assert_eq!(analyse_exit(None, true).0, ScriptStatus::Failure);
    // 92 asks for a par-check we have already done inside the download.
    let (st, why) = analyse_exit(Some(92), true);
    assert_eq!(st, ScriptStatus::Failure);
    assert!(why.contains("one-pass"), "{why}");
}

#[test]
fn the_chain_status_folds_the_way_nzbget_folds_it() {
    use ScriptStatus::*;
    // Failure overrides anything.
    assert_eq!(Success.fold(Failure), Failure);
    assert_eq!(Failure.fold(Success), Failure);
    assert_eq!(Failure.fold(None), Failure);
    // Success only upgrades a chain still at NONE, and a later NONE
    // never demotes it: (SUCCESS, NONE) is SUCCESS, which is the case a
    // "last one wins" fold would get wrong.
    assert_eq!(None.fold(Success), Success);
    assert_eq!(Success.fold(None), Success);
    assert_eq!(None.fold(None), None);
    assert_eq!(ScriptStatus::default(), None);
    assert_eq!(Success.as_str(), "SUCCESS");
    assert_eq!(Failure.as_str(), "FAILURE");
    assert_eq!(None.as_str(), "NONE");
}

#[test]
fn a_chain_splits_on_comma_and_semicolon_and_drops_the_null_choice() {
    let got = script_chain(" sort.py , notify.py ;/opt/x/mark.sh ");
    assert_eq!(
        got,
        vec![
            PathBuf::from("sort.py"),
            PathBuf::from("notify.py"),
            PathBuf::from("/opt/x/mark.sh"),
        ]
    );
    // "None" is SAB's null choice and must never become a filename, in
    // any casing, anywhere in the list.
    assert_eq!(script_chain("None"), Vec::<PathBuf>::new());
    assert_eq!(
        script_chain("a.py,none,b.py"),
        vec![PathBuf::from("a.py"), PathBuf::from("b.py")]
    );
    // Empty entries from a trailing separator or a stray double comma
    // are not a script called "".
    assert_eq!(script_chain(",, a.py ,,"), vec![PathBuf::from("a.py")]);
    assert_eq!(script_chain("   "), Vec::<PathBuf>::new());
    assert_eq!(chain_str(&script_chain("a.py ; b.py")), "a.py,b.py");
}

#[test]
fn the_command_channel_is_parsed_and_unknown_commands_are_reported() {
    let lines: Vec<String> = [
        "[INFO] this one is not kept by the sieve at all",
        "[NZB] FINALDIR=/media/tv/Show S01E01",
        "[NZB] NZBPR_sorted=yes",
        "[NZB] NZBPR_stage=one",
        "[NZB] MARK=BAD",
        "[NZB] SOMETHINGELSE=1",
        "[NZB] nocommandhere",
        "[ERROR] the mover refused",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let c = NzbCommands::parse(&lines);
    assert_eq!(c.final_dir.as_deref(), Some("/media/tv/Show S01E01"));
    assert_eq!(
        c.params,
        vec![
            ("sorted".to_string(), "yes".to_string()),
            ("stage".to_string(), "one".to_string()),
        ]
    );
    assert!(c.mark_bad);
    assert_eq!(c.unknown, vec!["SOMETHINGELSE=1", "nocommandhere"]);
    // Anything not on the `[NZB] ` channel that the sieve kept is a log
    // message, and it must reach the daemon log rather than vanish.
    assert_eq!(
        c.messages,
        vec![
            "[INFO] this one is not kept by the sieve at all",
            "[ERROR] the mover refused",
        ]
    );
}

#[test]
fn the_sieve_keeps_command_lines_wherever_they_appear_and_is_bounded() {
    let mut s = LineSieve::default();
    // The realistic shape: a wall of ordinary output, then the command
    // on the LAST line. A head-keeping capture would miss it, which is
    // the whole reason this is a sieve.
    for _ in 0..5_000 {
        s.push(b"ordinary progress output\n");
    }
    s.push(b"[NZB] FINALDIR=/x");
    s.finish();
    assert_eq!(s.kept, vec!["[NZB] FINALDIR=/x"]);

    // Split across reads: a pipe hands over arbitrary chunks, so the
    // line assembly cannot assume a read ends on a newline.
    let mut s = LineSieve::default();
    s.push(b"[NZB] FIN");
    s.push(b"ALDIR=/y\nnoise\n[ERR");
    s.push(b"OR] boom\r\n");
    assert_eq!(s.kept, vec!["[NZB] FINALDIR=/y", "[ERROR] boom"]);

    // Bounded: a script in a loop cannot spend the daemon's memory.
    let mut s = LineSieve::default();
    for _ in 0..10_000 {
        s.push(b"[NZB] NZBPR_x=1\n");
    }
    assert_eq!(s.kept.len(), SIEVE_LINES);
    assert_eq!(s.dropped, 10_000 - SIEVE_LINES);

    // An overlong line is dropped, not truncated: half a FINALDIR is a
    // wrong path, not a partial one.
    let mut s = LineSieve::default();
    s.push(b"[NZB] FINALDIR=");
    s.push(&vec![b'z'; SIEVE_LINE_MAX + 10]);
    s.push(b"\n");
    s.finish();
    assert!(s.kept.is_empty(), "{:?}", s.kept);
}

#[test]
fn every_option_is_exported_under_both_of_nzbgets_spellings() {
    let mut cmd = std::process::Command::new("true");
    set_env_special(&mut cmd, "NZBOP", "ControlIP", "127.0.0.1");
    set_env_special(&mut cmd, "NZBPR", "drone", "abc-123");
    // An option name that already normalises to itself gets ONE var,
    // exactly as NZBGet's `SetEnvVarSpecial` does.
    set_env_special(&mut cmd, "NZBOP", "VERSION", "21.0");
    let envs: Vec<(String, String)> = cmd
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.unwrap_or_default().to_string_lossy().into_owned(),
            )
        })
        .collect();
    // Windows environment names are case-insensitive, and `Command`'s env
    // map is keyed that way, so the two spellings collapse into ONE entry
    // there. Nothing is lost - a script reading either name still gets the
    // value, because the OS resolves the lookup case-insensitively - but
    // the map cannot show both, so the lookup below is case-insensitive on
    // Windows and exact everywhere else. Each platform is then asserted on
    // the guarantee it actually makes, and the four assertions stay.
    // (Windows-only CI red on main, 19 Aug 2026.)
    #[cfg(windows)]
    let has = |k: &str, v: &str| {
        envs.iter()
            .any(|(a, b)| a.eq_ignore_ascii_case(k) && b == v)
    };
    #[cfg(not(windows))]
    let has = |k: &str, v: &str| envs.iter().any(|(a, b)| a == k && b == v);
    assert!(has("NZBOP_ControlIP", "127.0.0.1"), "{envs:?}");
    assert!(has("NZBOP_CONTROLIP", "127.0.0.1"), "{envs:?}");
    assert!(has("NZBPR_drone", "abc-123"), "{envs:?}");
    assert!(has("NZBPR_DRONE", "abc-123"), "{envs:?}");
    assert_eq!(
        envs.iter().filter(|(k, _)| k.contains("VERSION")).count(),
        1,
        "{envs:?}"
    );
}
