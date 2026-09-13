# parfast GUI for Windows

A WinUI 3 PAR2 create / verify / repair / checksum / queue app over the shared
Rust core, built to the design spec in `research/PLAN-PARFAST-GUI-2026-09-12.md`
sections 4.5 and 5.

**Private until v1 (plan decision D2).** Nothing here is on
`packaging/PUBLIC_MANIFEST`, and that is also why the Inno Setup script is
`packaging/parfast-gui.iss` INSIDE this tree rather than in the repo's
`packaging/windows/` where the plan's section 9.3 put it: `packaging` is on the
manifest wholesale, so a file left there would have shipped publicly on the next
export. The script's own header carries the full reasoning. When D2 flips, moving
it back is the publication.

## The projects, and why they are split this way

| Project | Target | What it is |
|---|---|---|
| `Parfast.Core` | `net8.0` | The FFI contract as C# types, `ICoreClient`, `MockCore` and its scenarios, `FfiCore` over P/Invoke |
| `Parfast.ViewModels` | `net8.0` | Every screen's behaviour, the block map model, the formatting, the drop routing |
| `Parfast.App` | `net8.0-windows` | The WinUI 3 window, pages and custom-drawn controls. The ONLY project that needs Windows |
| `Parfast.Gen` | `net8.0` | Generates the copy table and the design tokens from the shared JSON |
| `Parfast.Tests` | `net8.0` | xUnit over Core and ViewModels |

**The split is load-bearing, not tidiness.** Only `Parfast.App` needs a Windows
host, so everything that is not pixels builds and unit-tests on the dev Macs.
That is what let this lane make progress while the fleet's only WinUI-capable box
was busy with a bench round, and it is why a WinUI type must never appear in
`Parfast.ViewModels`.

## On the dev Mac

```sh
dotnet build build/Parfast.Portable.slnf     # the net8.0 projects
dotnet test  build/Parfast.Portable.slnf     # the whole unit suite
tools/semantic-check.sh                      # TYPE-CHECK Parfast.App's C# here
dotnet run --project Parfast.Gen             # regenerate the copy table and tokens
dotnet run --project Parfast.Gen -- --check  # refuse a tree where they are stale
python3 tools/make-icon.py                   # rebuild the .ico from its SVG masters (macOS only)
```

`build/Parfast.Portable.slnf` is a solution filter that leaves `Parfast.App` out.
`dotnet build Parfast.sln` on a Mac fails at `Parfast.App`, as it should.

**`tools/semantic-check.sh` is the one that matters most off Windows.**
`Parfast.App` cannot be BUILT here - the Windows App SDK's `XamlCompiler.exe` is
a net472 binary - but restore and reference resolution work anywhere with
`EnableWindowsTargeting`, so its C# can be type-checked against the real
reference assemblies by Roslyn. It caught **sixty-four** errors the day it was
written, every one of which had passed every other local check in silence and
would otherwise have arrived a few at a time down a ten minute CI round trip.

It cannot see the XAML compiler's own output, so `InitializeComponent` and the
`x:Name` fields are excused BY NAME, read out of the `.xaml` files - a genuinely
undefined symbol is still reported. It is not a substitute for the Windows build.
It is what makes the Windows build's first attempt worth having.

It is in `build/` rather than beside the `.sln` on purpose: CI runs a bare
`dotnet build -c Release` in this directory
(`.github/workflows/parfast-gui.yml`, the `windows` job), and that command
globs the directory for something to build. One solution file in the root and
one filter beside it is the shape that can become "specify which project or
solution file to use" on a future SDK, on a runner nobody is watching.

## On the Windows box

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\build.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tools\build.ps1 -Publish -Installer
powershell -NoProfile -ExecutionPolicy Bypass -File tools\screenshots.ps1
```

Needs the .NET 8 SDK (`winget install Microsoft.DotNet.SDK.8`). The Windows App
SDK is a NuGet package the project restores; it is not an installer. Read
the maintainer notes' "Windows-over-ssh rules" before driving a box remotely, and
take that box's `~/.parfast-rig.lock` first.

## Mock or real

`Parfast.App` asks `FfiCore.TryCreate` first and falls back to `MockCore`, saying
so in the title bar when it does. `--mock` forces the mock even when
`parfast_ffi.dll` is present, which is how the screenshot pass gets the same
pictures on any box.

The mock plays the scenarios in `Parfast.Core/Mock/MockScenarios.cs`, and it is
selected by FILE NAME: dropping `unrepairable.par2` on a mock build shows the
unrepairable screen, so the whole app is demoable from Explorer with no build flag.

## Shared strings and tokens

`apps/parfast/shared/strings/en.json` and `shared/design/tokens.json` are owned by
the macOS lane (chip B). This lane reads them and never edits them. Until they are
on origin/main, `Parfast.Gen` falls back to the bootstrap copies in
`shared-bootstrap/`, and it switches to the shared files the moment they exist,
with no edit here. Propose an addition by handoff, never by editing them.

## What is deliberately not built

- **The Windows 11 modern context menu.** The verbs appear under *Show more
  options*. The modern menu needs a sparse-package `IExplorerCommand` handler,
  which the plan names as a v1.1 item.
- **Localisation beyond English.** The string table is externalised and the .resw
  is generated, which is the work; the other locales follow by the same script.
