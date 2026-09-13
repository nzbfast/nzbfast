// swift-tools-version: 6.0
import Foundation
import PackageDescription

// parfast desktop GUI for macOS (research/PLAN-PARFAST-GUI-2026-09-12.md).
//
// Built without Xcode project files, the `macapp/` precedent: `swift build`
// plus `make-app.sh` for the bundle. Swift 5 language mode for the same
// reason macapp gives - the app is a single-window SwiftUI front end over a
// C ABI, and Swift 6 strict-concurrency ceremony over an @MainActor UI and
// one locked core client buys nothing here.
//
// ParfastApp is a LIBRARY and `Parfast` the executable shim over it, rather
// than one executable target, because a test target that depends on an
// executable target links a second copy of `main` on macOS. The shim is ten
// lines and the whole app is testable.
// The Rust core is linked when its universal staticlib is on disk, and the
// app falls back to MockCore when it is not.
//
// Conditional rather than always-on, deliberately: `swift test` must keep
// running on a box with no Rust toolchain and no 110 MB of staticlib - the 76
// tests are over the contract, the planner and the view models, and none of
// them needs an engine. `make-app.sh` builds the lib and then this manifest
// picks it up on the next build with no edit anywhere.
//
// vendor/lib is gitignored: it holds a lipo of
// apps/parfast/target/{aarch64,x86_64}-apple-darwin/release/libparfast_ffi.a.
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let ffiLibDir = packageDir.appendingPathComponent("vendor/lib")
let hasFFI = FileManager.default.fileExists(
    atPath: ffiLibDir.appendingPathComponent("libparfast_ffi.a").path)

// PARFAST_FFI goes on EVERY target, not just the one that links the library.
// It gated `#if` blocks in three places - FfiCore's body, App.swift's
// makeCore(), and the live corpus tests - and defining it on ParfastCore alone
// meant makeCore() silently returned MockCore while the staticlib was linked,
// and the corpus tests compiled down to nothing and reported a green
// "Executed 0 tests". A conditional-compilation flag that is true in one
// target and false in its neighbours is the quietest kind of wrong.
var commonSwiftSettings: [SwiftSetting] = [.swiftLanguageMode(.v5)]
var coreDependencies: [Target.Dependency] = []
var coreLinkerSettings: [LinkerSetting] = []
if hasFFI {
    commonSwiftSettings.append(.define("PARFAST_FFI"))
    coreDependencies.append("CParfastFFI")
    coreLinkerSettings = [
        .unsafeFlags(["-L\(ffiLibDir.path)"]),
        .linkedLibrary("parfast_ffi"),
    ]
}

let package = Package(
    name: "Parfast",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "Parfast", targets: ["Parfast"]),
        .library(name: "ParfastCore", targets: ["ParfastCore"]),
    ],
    targets: [
        .systemLibrary(name: "CParfastFFI", path: "Sources/CParfastFFI"),
        .target(
            name: "ParfastCore",
            dependencies: coreDependencies,
            path: "Sources/ParfastCore",
            swiftSettings: commonSwiftSettings,
            linkerSettings: coreLinkerSettings
        ),
        .target(
            name: "ParfastApp",
            dependencies: ["ParfastCore"],
            path: "Sources/ParfastApp",
            resources: [.process("Resources")],
            swiftSettings: commonSwiftSettings
        ),
        .executableTarget(
            name: "Parfast",
            dependencies: ["ParfastApp"],
            path: "Sources/Parfast",
            swiftSettings: commonSwiftSettings
        ),
        .testTarget(
            name: "ParfastAppTests",
            dependencies: ["ParfastApp", "ParfastCore"],
            path: "Tests/ParfastAppTests",
            swiftSettings: commonSwiftSettings
        ),
    ]
)
