// The one settings sheet's worth of state, and nothing else (TODO 281
// IO0, the plan's addendum A).
//
// Deliberately separate from `ServerConfig`, which answers "which engine
// am I talking to" and carries a credential. These are product choices -
// hold off on cellular, keep the screen awake - and a mistake here costs
// a preference rather than a key.
import Foundation

/// Where the queue comes from.
///
/// Named a SOURCE rather than a mode because that is what the user is
/// choosing: this phone, or a machine of theirs elsewhere. Both are
/// bring-your-own-server - the difference is only which side of the
/// house the engine runs on.
enum JobSource: String, Codable, CaseIterable {
    case device
    case remote

    var title: String {
        switch self {
        case .device: return "This device"
        case .remote: return "My server"
        }
    }
}

enum AppSettings {
    private static let d = UserDefaults.standard

    private static let sourceKey = "nzbfast.source"
    private static let cellularKey = "nzbfast.pause_on_cellular"
    private static let awakeKey = "nzbfast.keep_awake"

    static var source: JobSource {
        get { JobSource(rawValue: d.string(forKey: sourceKey) ?? "") ?? .remote }
        set { d.set(newValue.rawValue, forKey: sourceKey) }
    }

    /// Hold the queue while the phone is on cellular.
    ///
    /// Default ON, which is the opposite of the Android app's default
    /// and is not an inconsistency: this is the setting whose wrong
    /// answer costs the user money on a metered plan, and a phone is
    /// far likelier than a tablet on wifi to be on one. It undoes only
    /// its OWN pause - see `AppState.applyCellularPolicy`.
    static var pauseOnCellular: Bool {
        get { d.object(forKey: cellularKey) as? Bool ?? true }
        set { d.set(newValue, forKey: cellularKey) }
    }

    /// Keep the display awake while there is work.
    ///
    /// The honest answer to iOS's one real limitation: with the app in
    /// the background the process is suspended and the sockets stop, so
    /// a phone that is meant to be downloading has to be a phone that is
    /// awake and on this screen. Plugged in on a shelf, that makes it a
    /// small always-on downloader. Default OFF, because it is a battery
    /// decision and defaults that drain a battery are not ours to make.
    static var keepAwake: Bool {
        get { d.object(forKey: awakeKey) as? Bool ?? false }
        set { d.set(newValue, forKey: awakeKey) }
    }
}
