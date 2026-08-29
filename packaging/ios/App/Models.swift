// API models for the SABnzbd-compatible daemon API. Numeric fields
// arrive as strings in SAB-compat responses, so decoding is lenient.
import Foundation

/// Decodes a value that may arrive as a JSON string or number.
struct Stringly: Codable, Equatable {
    let raw: String

    init(_ raw: String) { self.raw = raw }

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let s = try? c.decode(String.self) {
            raw = s
        } else if let d = try? c.decode(Double.self) {
            raw = String(d)
        } else if let i = try? c.decode(Int.self) {
            raw = String(i)
        } else {
            raw = ""
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(raw)
    }

    var double: Double? { Double(raw) }
}

struct VersionResponse: Codable {
    let version: String?
    let nzbfast: String?
}

struct QueueResponse: Codable {
    let queue: QueueBody
}

struct QueueBody: Codable {
    let paused: Bool?
    let offline: Bool?
    let slots: [QueueSlot]
    let speed: String?
    let kbpersec: Stringly?
    let sizeleft: String?
    let timeleft: String?
    let status: String?
}

struct QueueSlot: Codable, Identifiable {
    let nzoId: String
    let filename: String?
    let status: String?
    let percentage: Stringly?
    let mb: Stringly?
    let mbleft: Stringly?
    let timeleft: String?
    let activity: String?
    let activityDetail: String?
    let media: String?
    let prefetching: Bool?

    var id: String { nzoId }

    enum CodingKeys: String, CodingKey {
        case nzoId = "nzo_id"
        case filename, status, percentage, mb, mbleft, timeleft, activity
        case activityDetail = "activity_detail"
        case media, prefetching
    }

    var name: String { filename ?? nzoId }
    var pct: Double { percentage?.double ?? 0 }
    var isPaused: Bool { (status ?? "") == "Paused" }
    var totalMB: Double { mb?.double ?? 0 }
    var leftMB: Double { mbleft?.double ?? 0 }
}

struct HistoryResponse: Codable {
    let history: HistoryBody
}

struct HistoryBody: Codable {
    let slots: [HistorySlot]
    let noofslots: Int?
}

/// The §76 media chip the daemon latches during the download: what the
/// bytes said. Only the fields the Play gate reads are decoded.
struct MediaBadge: Codable {
    let res: String?
    let vcodec: String?
    let audio: String?

    /// Mirrors the daemon's `MediaFacts::any`: a probe that identified
    /// the container but read no track has nothing to gate on.
    var any: Bool { res != nil || vcodec != nil || audio != nil }
}

struct HistorySlot: Codable, Identifiable {
    let nzoId: String
    let name: String?
    let status: String?
    let failMessage: String?
    let size: String?
    let bytes: Stringly?
    let completed: Stringly?
    let storage: String?
    let media: MediaBadge?

    var id: String { nzoId }

    enum CodingKeys: String, CodingKey {
        case nzoId = "nzo_id"
        case name, status, size, bytes, completed, storage, media
        case failMessage = "fail_message"
    }

    var isCompleted: Bool { (status ?? "") == "Completed" }
    var isFailed: Bool { (status ?? "") == "Failed" }

    /// Play is offered only for rows the daemon judged to hold media:
    /// the `media` chip when it was latched, else the stored path's own
    /// extension (rows recorded before the chip existed). Everything
    /// else - ISOs, software, archive-only jobs - used to show a dead
    /// Play action (Codex sweep 5 Aug L3). Extensions mirror the
    /// daemon's MEDIA_EXTS list.
    var looksPlayable: Bool {
        guard isCompleted else { return false }
        if media?.any == true { return true }
        let exts = [".mkv", ".mp4", ".avi", ".m4v", ".ts", ".wmv"]
        for candidate in [storage, name] {
            if let p = candidate?.lowercased(), exts.contains(where: p.hasSuffix) {
                return true
            }
        }
        return false
    }
}

struct AddResponse: Codable {
    let status: Bool
    let nzoIds: [String]?
    let stream: String?
    let m3u: String?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case status, stream, m3u, error
        case nzoIds = "nzo_ids"
    }
}

struct StatusResponse: Codable {
    let status: Bool?
    let error: String?
}

struct ProbeCoverage: Codable {
    let headBytes: Stringly?
    let pct: Stringly?
    let tailOk: Bool?

    enum CodingKeys: String, CodingKey {
        case headBytes = "head_bytes"
        case pct
        case tailOk = "tail_ok"
    }
}

struct ProbeMedia: Codable {
    let container: String?
    let complete: Bool?
}

struct ProbeResponse: Codable {
    let nzoId: String?
    let file: String?
    let size: Stringly?
    let coverage: ProbeCoverage?
    let source: String?
    let pending: Bool?
    let media: ProbeMedia?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case nzoId = "nzo_id"
        case file, size, coverage, source, pending, media, error
    }

    /// Playback readiness per the mobile contract: a parsed media
    /// header is the signal; pending means keep polling.
    var ready: Bool {
        error == nil && media != nil
    }
}

// MARK: - Playback contract v1 (mode=playback, CONTRACT.md row 16)
// The one compact call this app polls. Numbers arrive as real JSON
// numbers on this call, so no Stringly decoding is needed. Keys are
// frozen; the daemon may only ADD keys. Kept in step with the Android
// parser (Parse.playback) via CONTRACT.md.

struct PlaybackCoverage: Codable {
    let headBytes: Int64?
    let pct: Double?
    let tailOk: Bool?

    enum CodingKeys: String, CodingKey {
        case pct
        case headBytes = "head_bytes"
        case tailOk = "tail_ok"
    }
}

/// Per-file readiness for the file /stream/<id> would actually serve.
/// `reason` is a closed token set - live, disk, pending, not_started,
/// not_fetched, moving, no_media, failed, unknown - so the UI branches
/// on it, never on prose. `moving` is a wait (the payload is being
/// relocated to its final folder), `no_media` is final; both carry
/// ready=false, which is what the rows below branch on.
struct PlaybackInfo: Codable {
    let ready: Bool?
    let reason: String?
    let file: String?
    let size: Int64?
    let source: String?
    let seekable: Bool?
    let coverage: PlaybackCoverage?
}

struct PlaybackJob: Codable, Identifiable {
    let nzoId: String
    let name: String?
    let status: String?
    let percentage: Double?
    let mb: Double?
    let mbleft: Double?
    let timeleft: String?
    let activity: String?
    let failMessage: String?
    /// History rows: finished size in bytes.
    let bytes: Int64?
    /// History rows: unix seconds of completion.
    let completed: Int64?
    let playback: PlaybackInfo?
    /// Tokenized play URL: carries the job's scoped token, never the
    /// API key (the grab-apikey-leak lesson).
    let stream: String?

    var id: String { nzoId }

    enum CodingKeys: String, CodingKey {
        case nzoId = "nzo_id"
        case name, status, percentage, mb, mbleft, timeleft, activity
        case failMessage = "fail_message"
        case bytes, completed, playback, stream
    }

    var displayName: String { name ?? nzoId }
    var pct: Double { percentage ?? 0 }
    var isPaused: Bool { (status ?? "") == "Paused" }
    var isFailed: Bool { (status ?? "") == "Failed" }
    /// The Play affordance: readiness rides the row, no probe needed.
    var ready: Bool { playback?.ready ?? false }
}

/// Byte-serving telemetry behind the player's health overlay. The
/// counters are process-wide and cumulative since daemon start -
/// difference two polls for movement.
struct StreamTelemetry: Codable {
    let readers: Int?
    let blockedReads: Int64?
    let zeroFilledBytes: Int64?
    let runwayMb: Int64?
    let runwayWaitMs: Int64?

    enum CodingKeys: String, CodingKey {
        case readers
        case blockedReads = "blocked_reads"
        case zeroFilledBytes = "zero_filled_bytes"
        case runwayMb = "runway_mb"
        case runwayWaitMs = "runway_wait_ms"
    }
}

struct PlaybackSnapshot: Codable {
    let contract: Int?
    let version: String?
    let nzbfast: String?
    let paused: Bool?
    let speedBps: Double?
    /// The link's learned peak (bps) and its source ("measured" |
    /// "line" | ""), a contract addition. nil or 0 = no anchor known,
    /// and the throughput chart scales to its window instead.
    let linkPeak: Double?
    let linkPeakSrc: String?
    let diskspaceGb: Double?
    let warnings: Int?
    let queueTotal: Int?
    let historyTotal: Int?
    let queue: [PlaybackJob]
    let history: [PlaybackJob]
    let stream: StreamTelemetry?
    /// The daemon's own drain latch (`Daemon::note_queue_idle`), a
    /// 2026-08-26 contract addition.
    ///
    /// NOT the same fact as an empty `queue` list, which is the reason
    /// it exists: a job that has finished downloading is out of the
    /// queue and not yet in history for the whole of its repair,
    /// extract and move. ABSENT MUST READ FALSE - "I cannot tell" and
    /// "there is nothing left to do" cannot be the same answer when a
    /// caller acts on the second by standing the engine down. Decoded
    /// here for the surfaces that ask whether the phone is really
    /// finished; the engine stand-down itself is TODO 281 IO2.
    let queueIdle: Bool?

    enum CodingKeys: String, CodingKey {
        case contract, version, nzbfast, paused, warnings, queue, history, stream
        case speedBps = "speed_bps"
        case linkPeak = "link_peak"
        case linkPeakSrc = "link_peak_src"
        case diskspaceGb = "diskspace_gb"
        case queueTotal = "queue_total"
        case historyTotal = "history_total"
        case queueIdle = "queue_idle"
    }
}

// MARK: - On-device engine setup (TODO 281 IO1)

/// The one news server a phone downloads through.
///
/// Bring-your-own-server is the posture the whole plan rests on: there
/// is no indexer, no search and no content in this app, and the user
/// supplies the provider. See
/// research/PLAN-MOBILE-DOWNLOADER-2026-08-24.md section 1.
struct NewsServer: Equatable {
    var host = ""
    var port = 563
    var tls = true
    var username = ""
    var password = ""
    var connections = 8

    /// The `mode=server_save` / `mode=server_test` body.
    ///
    /// `index: -1` appends a new row rather than editing one. Built by
    /// hand rather than through Codable because the daemon wants the
    /// server nested under a key beside the index, which is a wrapper
    /// shape and not a property of the server.
    func payload(index: Int) -> Data {
        let body: [String: Any] = [
            "index": index,
            "server": [
                "host": host,
                "port": port,
                "tls": tls,
                "username": username,
                "password": password,
                "connections": connections,
            ],
        ]
        // The dictionary is built here out of Swift scalars, so there is
        // nothing in it JSONSerialization can refuse; an empty body
        // would be refused by the daemon rather than silently accepted.
        return (try? JSONSerialization.data(withJSONObject: body)) ?? Data()
    }

    var looksComplete: Bool {
        !host.trimmingCharacters(in: .whitespaces).isEmpty && (1...65535).contains(port)
    }
}

struct ServerTestResponse: Codable {
    let status: Bool?
    let greeting: String?
    let error: String?
}
