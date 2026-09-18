; parfast GUI Windows installer.
;
; Modelled on packaging/windows/installer.iss (nzbfast's), which is the file to
; read first: the reasoning behind the elevation policy, the per-user fallback,
; the Restart Manager and the VERSIONINFO fields is written out at length there
; and is not repeated here. What follows is only what DIFFERS, and why.
;
; Compile:  ISCC /DAppVersion=<x.y.z> /DStageDir=<dir> parfast-gui.iss
; where <dir> holds the published app: parfast-gui.exe, its runtime, the Windows
; App SDK's own DLLs (it is a SELF-CONTAINED unpackaged app, so they ship beside
; the exe rather than coming from a machine-wide runtime), LICENSE and, when the
; engine lane has landed, parfast_ffi.dll.
;
; WHY THIS IS HERE AND NOT IN packaging/windows/ BESIDE nzbfast's INSTALLER,
; which is where research/PLAN-PARFAST-GUI-2026-09-12.md section 9.3 puts it.
; Decision D2 of that same plan says the GUI is PRIVATE until v1 is polished,
; and `packaging` is on packaging/PUBLIC_MANIFEST WHOLESALE - one bare line,
; no exclusions - so a file dropped into packaging/windows/ ships verbatim to
; github.com/nzbfast/nzbfast on the next publish. The path list and D2 cannot
; both be honoured, and D2 is the decision; the plan's path list did not
; notice the manifest is a directory allowlist. `apps/` is on no manifest
; line, so the installer lives beside the app it installs and stays private
; with it, and no edit to PUBLIC_MANIFEST was needed to arrange that. When D2
; flips, this moves to packaging/windows/ and the move IS the publication.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef StageDir
  #define StageDir "stage-gui"
#endif

#define AppExe "parfast-gui.exe"

; A NUMERIC VERSION FOR THE VERSIONINFO RESOURCE, derived rather than passed.
; VersionInfoVersion is a Windows binary resource field and takes x.y.z[.w] and
; nothing else, while AppVersion is a DISPLAY string and this product's is
; "1.6.0-beta.1" (plan decision D2, tracking the CLI's NUMBER while carrying a
; stage of its own). Handing the display string to both stops the compile dead:
;
;   Error on line 43: Value of [Setup] section directive "VersionInfoVersion"
;   is invalid.  Compile aborted.
;
; which is where the first end-to-end run of the bundle script got to on 12 Sep
; 2026. Everything a person reads still says 1.6.0-beta.1; only the resource
; field is trimmed.
;
; packaging/windows/installer.iss (the nzbfast CLI's) has the same shape and has
; not hit it, because that product has never cut a pre-release. It will the day
; it does. The parfast CLI's bundler is NOT a third instance: it ships tarballs
; and a zip with no installer in them at all.
#if Pos("-", AppVersion) > 0
  #define NumericVersion Copy(AppVersion, 1, Pos("-", AppVersion) - 1)
#else
  #define NumericVersion AppVersion
#endif

[Setup]
; Its own AppId, not nzbfast's: they are separate products that can be installed
; side by side, and sharing an AppId would make each one's installer uninstall
; the other.
AppId={{5C1A4E93-2D7B-49F0-9E1C-8D6A3B44F7A2}
; "parfast (beta)" in Add or Remove Programs and on the installer's own
; pages, so a tester who installed this months ago and forgot can still
; tell what they have. The VERSION carries the stage too
; (1.6.0-beta.1), but a version string is not what anybody reads in a
; program list.
;
; alpha -> beta at 1.6.0 (17 Sep 2026). This is a DISPLAY name and the
; uninstall entry is keyed on AppId above, so an existing install upgrades
; in place and its program-list row simply re-reads - which is the whole
; reason the stage lives here rather than in the AppId. Keep it in step
; with GUI_STAGE in apps/parfast/packaging/build-parfast-gui-bundles.sh
; and with `app.stage` in apps/parfast/shared/strings/en.json, which is
; what the app's own title bar reads.
AppName=parfast (beta)
AppVersion={#AppVersion}
AppPublisher=parfast
VersionInfoVersion={#NumericVersion}
VersionInfoProductName=parfast
VersionInfoCompany=parfast
VersionInfoDescription=parfast setup
VersionInfoCopyright=GPL-3.0-or-later
DefaultDirName={autopf}\parfast
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes
CloseApplicationsFilter={#AppExe}
RestartApplications=no
; `parfast-gui-`, NOT `parfast-`. The CLI's own bundles are already
; parfast-<version>-<platform>, so the bare prefix collides with them in
; any directory that holds both - and apps/parfast/packaging's bundle
; script names its zip parfast-gui-<version>-windows-x64.zip and fetches
; this file by name, so the two must agree. They did not until 12 Sep
; 2026, when the Windows arm was first run end to end.
OutputBaseFilename=parfast-gui-{#AppVersion}-windows-x64-setup
OutputDir=out
LicenseFile={#StageDir}\LICENSE
SetupIconFile=..\Parfast.App\Assets\parfast.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName=parfast
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; WinUI 3 needs Windows 10 1809. Stated here so an older machine is refused with
; a sentence rather than by a missing-DLL dialog after the files are copied.
MinVersion=10.0.17763

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nparfast creates, verifies and repairs PAR2 recovery sets.%n%nIt is not yet code-signed, so Windows SmartScreen may have shown "Windows protected your PC", and the elevation prompt will say the publisher is unknown. Both are expected while signing is set up.%n%nSetup installs into Program Files. If you have no administrator password, choose the per-user option when prompted and it will install just for you.

[Tasks]
; The .par2 association, default ON only when nothing else owns it: MultiPar and
; QuickPar users have a handler already and taking it silently is not ours to do.
; This is the same rule and the same wording pair as nzbfast's .nzb task.
Name: "par2assoc"; Description: "Open .par2 files with parfast"; Check: not Par2Associated
Name: "par2assoc"; Description: "Open .par2 files with parfast (currently handled by another app)"; Flags: unchecked; Check: Par2Associated
; Checksum files are a smaller claim and a smaller habit, so they are OFF by
; default whatever is there.
Name: "sumassoc"; Description: "Open .sfv, .md5 and .sha256 files with parfast"; Flags: unchecked
; The right-click verbs. On Windows 11 these land under "Show more options" -
; the modern menu needs a sparse-package handler, which is a v1.1 item and is
; NOT built. Saying so here is the difference between a known limitation and a
; bug report.
Name: "shellmenu"; Description: "Add parfast to the right-click menu (under ""Show more options"" on Windows 11)"; Flags: unchecked
Name: "desktopicon"; Description: "Create a &desktop icon"; Flags: unchecked

[Files]
; The whole staged publish directory. A self-contained WinUI 3 app is about a
; hundred files, and naming them one by one would break the day the SDK adds one.
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\parfast"; Filename: "{app}\{#AppExe}"
Name: "{userdesktop}\parfast"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; HKCU throughout, exactly as nzbfast does and for the reasons its own [Registry]
; section gives. The KEYS AND VALUES BELOW MUST MATCH
; apps/parfast/windows/Parfast.App/RegistryIntegration.cs, which writes the same
; entries when the user flips Settings > Integration: if the two ever disagree,
; the installer's tick and the app's switch report different states for one thing.

; The .par2 ProgID.
Root: HKCU; Subkey: "Software\Classes\parfast.par2"; ValueType: string; ValueData: "PAR2 recovery set"; Flags: uninsdeletekey; Tasks: par2assoc
Root: HKCU; Subkey: "Software\Classes\parfast.par2\DefaultIcon"; ValueType: string; ValueData: """{app}\{#AppExe}"",0"; Tasks: par2assoc
Root: HKCU; Subkey: "Software\Classes\parfast.par2\shell\open\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: par2assoc
Root: HKCU; Subkey: "Software\Classes\.par2"; ValueType: string; ValueData: "parfast.par2"; Flags: uninsdeletevalue uninsdeletekeyifempty; Tasks: par2assoc

; Checksum files. One ProgID per extension rather than one shared: the app opens
; them all the same way, but a shared ProgID means removing one association
; removes them all.
Root: HKCU; Subkey: "Software\Classes\parfastsfv"; ValueType: string; ValueData: "Checksum file"; Flags: uninsdeletekey; Tasks: sumassoc
Root: HKCU; Subkey: "Software\Classes\parfastsfv\DefaultIcon"; ValueType: string; ValueData: """{app}\{#AppExe}"",0"; Tasks: sumassoc
Root: HKCU; Subkey: "Software\Classes\parfastsfv\shell\open\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: sumassoc
Root: HKCU; Subkey: "Software\Classes\.sfv"; ValueType: string; ValueData: "parfastsfv"; Flags: uninsdeletevalue uninsdeletekeyifempty; Tasks: sumassoc

Root: HKCU; Subkey: "Software\Classes\parfastmd5"; ValueType: string; ValueData: "MD5 checksum file"; Flags: uninsdeletekey; Tasks: sumassoc
Root: HKCU; Subkey: "Software\Classes\parfastmd5\DefaultIcon"; ValueType: string; ValueData: """{app}\{#AppExe}"",0"; Tasks: sumassoc
Root: HKCU; Subkey: "Software\Classes\parfastmd5\shell\open\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: sumassoc
Root: HKCU; Subkey: "Software\Classes\.md5"; ValueType: string; ValueData: "parfastmd5"; Flags: uninsdeletevalue uninsdeletekeyifempty; Tasks: sumassoc

Root: HKCU; Subkey: "Software\Classes\parfastsha256"; ValueType: string; ValueData: "SHA-256 checksum file"; Flags: uninsdeletekey; Tasks: sumassoc
Root: HKCU; Subkey: "Software\Classes\parfastsha256\DefaultIcon"; ValueType: string; ValueData: """{app}\{#AppExe}"",0"; Tasks: sumassoc
Root: HKCU; Subkey: "Software\Classes\parfastsha256\shell\open\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: sumassoc
Root: HKCU; Subkey: "Software\Classes\.sha256"; ValueType: string; ValueData: "parfastsha256"; Flags: uninsdeletevalue uninsdeletekeyifempty; Tasks: sumassoc

; The right-click verbs. "Verify with parfast" is on FILES only: on a folder it
; would have to guess which set inside was meant, and guessing wrong on a
; right-click is worse than not offering it. "Create PAR2 with parfast" is on
; both, because a folder is a perfectly good set of sources.
Root: HKCU; Subkey: "Software\Classes\*\shell\parfast.verify"; ValueType: string; ValueData: "Verify with parfast"; Flags: uninsdeletekey; Tasks: shellmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\parfast.verify"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#AppExe}"",0"; Tasks: shellmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\parfast.verify\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" --verify ""%1"""; Tasks: shellmenu

Root: HKCU; Subkey: "Software\Classes\*\shell\parfast.create"; ValueType: string; ValueData: "Create PAR2 with parfast"; Flags: uninsdeletekey; Tasks: shellmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\parfast.create"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#AppExe}"",0"; Tasks: shellmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\parfast.create\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" --create ""%1"""; Tasks: shellmenu

Root: HKCU; Subkey: "Software\Classes\Directory\shell\parfast.create"; ValueType: string; ValueData: "Create PAR2 with parfast"; Flags: uninsdeletekey; Tasks: shellmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\parfast.create"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#AppExe}"",0"; Tasks: shellmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\parfast.create\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" --create ""%1"""; Tasks: shellmenu

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch parfast"; Flags: postinstall nowait skipifsilent

[Code]
{ Does something OTHER than us already own .par2? Both hives are read: HKCU wins
  at resolution time, but a machine-wide handler in HKCR is still somebody else's
  claim and the tick should say so. }
function Par2Associated: Boolean;
var s: string;
begin
  Result := (RegQueryStringValue(HKEY_CURRENT_USER, 'Software\Classes\.par2', '', s)
             and (s <> '') and (s <> 'parfast.par2'))
    or (RegQueryStringValue(HKEY_CLASSES_ROOT, '.par2', '', s)
        and (s <> '') and (s <> 'parfast.par2'));
end;
