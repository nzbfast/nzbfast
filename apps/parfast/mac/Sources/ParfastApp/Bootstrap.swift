import SwiftUI

/// The executable target is a shim over this library so the whole app is
/// testable (see Package.swift). Everything the app is lives here.
public enum ParfastMain {
    public static func run() {
        ParfastSwiftUIApp.main()
    }
}
