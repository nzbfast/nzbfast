using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

// Semantic check of a WinUI app's C# on a host that cannot run the XAML compiler.
//
// WHY: apps/parfast/windows/Parfast.App can only be BUILT on Windows, because the
// Windows App SDK's XamlCompiler.exe is a net472 binary. Everything before it -
// restore and reference resolution - works anywhere with EnableWindowsTargeting,
// so the references exist here even though the build cannot finish. This compiles
// the app's own C# against them and reports the errors that do not depend on
// XAML's generated code.
//
// WHAT IT CATCHES that a syntax-only parse does not, all three of which reached
// CI on 12 Sep 2026: CS0246 (a missing using), CS0535 (an interface member not
// implemented), CS8848 (`as string switch` needing parentheses).
//
// WHAT IT CANNOT SEE: anything defined by the XAML compiler's generated partials -
// InitializeComponent and the x:Name fields. Those are filtered by NAME, from the
// x:Name attributes in the .xaml files, so a genuinely undefined symbol is still
// reported and only the generated ones are excused.
// Usage: dotnet run --project Parfast.Check -- <Parfast.App dir> <refs file>
// Both are derived by tools/semantic-check.sh; run that rather than this.
if (args.Length < 2)
{
    Console.Error.WriteLine("usage: parfast-check <Parfast.App directory> <reference list file>");
    Console.Error.WriteLine("       run tools/semantic-check.sh, which derives both.");
    return 2;
}

var appDir = args[0];
var refsFile = args[1];
if (!Directory.Exists(appDir))
{
    Console.Error.WriteLine($"parfast-check: {appDir} is not there");
    return 2;
}

if (!File.Exists(refsFile))
{
    Console.Error.WriteLine(
        $"parfast-check: {refsFile} is not there. It is written by tools/semantic-check.sh from "
        + "`dotnet build -t:ResolveReferences -getItem:ReferencePath`, which needs a restore first.");
    return 2;
}

var trees = new List<SyntaxTree>();
foreach (var file in Directory.EnumerateFiles(appDir, "*.cs", SearchOption.AllDirectories).OrderBy(x => x))
{
    if (file.Contains("/obj/") || file.Contains("/bin/")) continue;
    trees.Add(CSharpSyntaxTree.ParseText(File.ReadAllText(file),
        new CSharpParseOptions(LanguageVersion.CSharp12), path: file));
}

// Parfast.Core and Parfast.ViewModels are NOT added as source. They arrive as
// project references in the resolved set, and compiling their source alongside
// the assemblies that already contain it reports every shared type as a CS0436
// conflict - three and a half thousand of them, which buries the handful that
// matter. The portable solution builds them, so the DLLs are current.

var references = File.ReadAllLines(refsFile)
    .Where(p => p.Length > 0 && File.Exists(p))
    .Select(p => (MetadataReference)MetadataReference.CreateFromFile(p))
    .ToList();

// FAILING TO FIND IS FAILING. With no references every type in the app is
// undefined, and the run would print a thousand errors or - worse, if the filter
// ever widened - none at all. A reference set this small cannot be right.
if (references.Count < 50)
{
    Console.Error.WriteLine(
        $"parfast-check: only {references.Count} reference assemblies resolved, which cannot be "
        + "right for a WinUI app. Re-run tools/semantic-check.sh so the restore happens first.");
    return 2;
}

if (trees.Count < 10)
{
    Console.Error.WriteLine($"parfast-check: only {trees.Count} source files found under {appDir}.");
    return 2;
}

// Every x:Name in the app's XAML: the XAML compiler would declare a field for each.
var generated = new HashSet<string>(StringComparer.Ordinal) { "InitializeComponent" };
foreach (var xaml in Directory.EnumerateFiles(appDir, "*.xaml", SearchOption.AllDirectories))
{
    foreach (System.Text.RegularExpressions.Match m in
             System.Text.RegularExpressions.Regex.Matches(File.ReadAllText(xaml), @"x:Name=""(\w+)"""))
    {
        generated.Add(m.Groups[1].Value);
    }
}

// ImplicitUsings=enable in Directory.Build.props, so the real compile has these
// as GLOBAL USINGS in a generated file. They go in as a synthetic tree rather
// than through CSharpCompilationOptions.Usings, which only applies to SCRIPT
// compilations - setting it there changes nothing and the check reports four
// hundred "the name Math does not exist" errors that bury the three that matter.
const string implicitUsings = """
    global using System;
    global using System.Collections.Generic;
    global using System.IO;
    global using System.Linq;
    global using System.Net.Http;
    global using System.Threading;
    global using System.Threading.Tasks;
    """;
trees.Add(CSharpSyntaxTree.ParseText(implicitUsings,
    new CSharpParseOptions(LanguageVersion.CSharp12), path: "ImplicitUsings.g.cs"));

var compilation = CSharpCompilation.Create("Parfast.App.semantic", trees, references,
    new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary,
        allowUnsafe: true, nullableContextOptions: NullableContextOptions.Enable));

// TreatWarningsAsErrors is on in Directory.Build.props, so a WARNING here is a
// build failure there. Reporting only Error missed CS0649 ("field is never
// assigned") and CS8618 ("non-nullable field must contain a non-null value"),
// both of which failed the real build while this check called the tree clean -
// which is the checker lying in the one direction that matters.
//
// NoWarn in Directory.Build.props is honoured so the two agree: CS1591 is off
// there because these are app assemblies rather than a published API surface.
// CS1701 is assembly-version unification the real build resolves through binding
// redirects it writes itself; it says "assuming ... matches" and is noise here.
string[] suppressed = ["CS1591", "CS8305", "CA1416", "MSB3277", "CS1701", "CS1702"];

var reported = 0;
foreach (var d in compilation.GetDiagnostics()
             .Where(d => d.Severity is DiagnosticSeverity.Error or DiagnosticSeverity.Warning)
             .Where(d => !suppressed.Contains(d.Id)))
{
    var text = d.GetMessage();
    // A generated member this compilation does not have.
    if (generated.Any(g => text.Contains($"'{g}'", StringComparison.Ordinal))) continue;
    // Partial halves the XAML compiler writes.
    if (d.Id is "CS0260" or "CS1061" && generated.Any(g => text.Contains(g, StringComparison.Ordinal))) continue;

    var line = d.Location.GetLineSpan();
    Console.WriteLine($"  {d.Id} {Path.GetFileName(line.Path)}({line.StartLinePosition.Line + 1}): {text}");
    reported++;
}

Console.WriteLine(reported == 0
    ? "semantic check clean (XAML-generated members excused by name)"
    : $"{reported} semantic error(s) the XAML compiler would not have explained away");
return reported == 0 ? 0 : 1;
