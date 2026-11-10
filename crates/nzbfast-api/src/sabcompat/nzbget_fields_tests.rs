//! Issue #118: NZBClient on iOS could not connect, failing with a bare
//! "APIError error 2" against a facade that answered every call it
//! made. Its decoder is strict, and `status`, `listgroups` and
//! `history` each lacked keys real NZBGet always sends, so one missing
//! field rejected the whole reply.
//!
//! The lists below are NZBGet's own, read out of its
//! `daemon/remote/XmlRpc.cpp` (`StatusXmlCommand`, `ListGroupsXmlCommand`,
//! `HistoryXmlCommand` and the `AppendNzbInfoFields` /
//! `AppendPostInfoFields` both of the latter carry). A key that leaves a
//! reply is what this test refuses; extra keys are allowed.

use super::*;

const NZBINFO: &[&str] = &[
    "NZBID",
    "NZBName",
    "NZBNicename",
    "Kind",
    "URL",
    "NZBFilename",
    "DestDir",
    "FinalDir",
    "Category",
    "ParStatus",
    "ExParStatus",
    "UnpackStatus",
    "MoveStatus",
    "ScriptStatus",
    "DeleteStatus",
    "MarkStatus",
    "UrlStatus",
    "FileSizeLo",
    "FileSizeHi",
    "FileSizeMB",
    "FileCount",
    "MinPostTime",
    "MaxPostTime",
    "TotalArticles",
    "SuccessArticles",
    "FailedArticles",
    "Health",
    "CriticalHealth",
    "DupeKey",
    "DupeScore",
    "DupeMode",
    "Deleted",
    "DownloadedSizeLo",
    "DownloadedSizeHi",
    "DownloadedSizeMB",
    "DownloadTimeSec",
    "PostTotalTimeSec",
    "ParTimeSec",
    "RepairTimeSec",
    "UnpackTimeSec",
    "MessageCount",
    "ExtraParBlocks",
    "Parameters",
    "ScriptStatuses",
    "ServerStats",
];

const LISTGROUPS: &[&str] = &[
    "FirstID",
    "LastID",
    "RemainingSizeLo",
    "RemainingSizeHi",
    "RemainingSizeMB",
    "PausedSizeLo",
    "PausedSizeHi",
    "PausedSizeMB",
    "RemainingFileCount",
    "RemainingParCount",
    "MinPriority",
    "MaxPriority",
    "ActiveDownloads",
    "Status",
    "PostInfoText",
    "PostStageProgress",
    "PostStageTimeSec",
    "Log",
];

const HISTORY: &[&str] = &[
    "ID",
    "Name",
    "RemainingFileCount",
    "RetryData",
    "HistoryTime",
    "Status",
    "Log",
];

const STATUS: &[&str] = &[
    "RemainingSizeLo",
    "RemainingSizeHi",
    "RemainingSizeMB",
    "ForcedSizeLo",
    "ForcedSizeHi",
    "ForcedSizeMB",
    "DownloadedSizeLo",
    "DownloadedSizeHi",
    "DownloadedSizeMB",
    "MonthSizeLo",
    "MonthSizeHi",
    "MonthSizeMB",
    "DaySizeLo",
    "DaySizeHi",
    "DaySizeMB",
    "ArticleCacheLo",
    "ArticleCacheHi",
    "ArticleCacheMB",
    "DownloadRate",
    "DownloadRateLo",
    "DownloadRateHi",
    "AverageDownloadRate",
    "AverageDownloadRateLo",
    "AverageDownloadRateHi",
    "DownloadLimit",
    "ThreadCount",
    "ParJobCount",
    "PostJobCount",
    "UrlCount",
    "UpTimeSec",
    "DownloadTimeSec",
    "ServerPaused",
    "DownloadPaused",
    "Download2Paused",
    "ServerStandBy",
    "PostPaused",
    "ScanPaused",
    "QuotaReached",
    "FreeDiskSpaceLo",
    "FreeDiskSpaceHi",
    "FreeDiskSpaceMB",
    "TotalDiskSpaceLo",
    "TotalDiskSpaceHi",
    "TotalDiskSpaceMB",
    "FreeInterDiskSpaceLo",
    "FreeInterDiskSpaceHi",
    "FreeInterDiskSpaceMB",
    "TotalInterDiskSpaceLo",
    "TotalInterDiskSpaceHi",
    "TotalInterDiskSpaceMB",
    "ServerTime",
    "ResumeTime",
    "FeedActive",
    "QueueScriptCount",
    "NewsServers",
];

fn missing(row: &Value, want: &[&[&str]]) -> Vec<String> {
    want.iter()
        .flat_map(|l| l.iter())
        .filter(|k| row.get(**k).is_none())
        .map(|k| k.to_string())
        .collect()
}

fn job(d: &Arc<Daemon>, id: &str, state: &str) -> Arc<Mutex<Job>> {
    let name = format!("Some.Release.{id}");
    Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": format!("SABnzbd_nzo_{id}"), "name": name,
            "out_dir": crate::naming::out_dir(d).join(&name).to_string_lossy(),
            "nzb_path": format!("/nowhere/{name}.nzb"), "state": state,
            "total_bytes": 5u64 << 30,
        }))
        .expect("job"),
    ))
}

#[test]
fn every_reply_carries_every_field_nzbget_sends() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nzbget-fields-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::testutil::test_daemon(&dir);
    d.queue.lock_ok().push_back(job(&d, "41", "Queued"));
    d.history.lock_ok().push(job(&d, "42", "Completed"));

    let status = jr_status(&d);
    assert_eq!(missing(&status, &[STATUS]), Vec::<String>::new(), "status");

    let groups = jr_listgroups(&d);
    let row = &groups.as_array().expect("listgroups is an array")[0];
    assert_eq!(
        missing(row, &[LISTGROUPS, NZBINFO]),
        Vec::<String>::new(),
        "listgroups"
    );
    // FirstID/LastID are the group's first and last FILE ids, in
    // `listfiles`' namespace (TODO 358 sweep E1 - they were the NZBID,
    // which no `listfiles` range reaches). This job's spool is absent,
    // so it has no files and both are 0, NZBGet's answer for an empty
    // group; nzbget_lists_tests.rs pins the populated case. The 64-bit
    // size split is carried on the gap-filled half too.
    assert_eq!(row["FirstID"], json!(0));
    assert_eq!(row["FileCount"], json!(0));
    assert_eq!(row["NZBFilename"], json!("Some.Release.41.nzb"));
    assert_eq!(row["FileSizeHi"], json!(1));

    let hist = jr_history(&d, &[]);
    let row = &hist.as_array().expect("history is an array")[0];
    assert_eq!(
        missing(row, &[HISTORY, NZBINFO]),
        Vec::<String>::new(),
        "history"
    );
    // A builder's own answer wins over the gap filler's default.
    assert_ne!(row["MoveStatus"], Value::Null);
    assert_eq!(row["ID"], json!(42));

    let _ = std::fs::remove_dir_all(&dir);
}
