#!/bin/sh
# Type-check the WinUI app's C# on a host that cannot build it.
#
#   apps/parfast/windows/tools/semantic-check.sh
#
# WHY THIS EXISTS. Parfast.App can only be BUILT on Windows: the Windows App SDK's
# XamlCompiler.exe is a net472 binary and exits 126 on a Mac. But restore and
# reference resolution work anywhere with EnableWindowsTargeting, so the reference
# assemblies are here even though the build cannot finish - and the C# can be
# compiled against them by Roslyn.
#
# WHAT IT CAUGHT the day it was written (12 Sep 2026): SIXTY-FOUR real errors that
# every other local check passed over in silence, because nothing on a Mac
# compiles that project. Forty-seven were string constants the shared copy table
# had renamed; four were missing usings. Before this, each one cost a ten minute
# CI round trip and they arrived a few at a time.
#
# WHAT IT CANNOT SEE: the XAML compiler's own output. InitializeComponent and the
# x:Name fields are excused BY NAME, read out of the .xaml files, so a genuinely
# undefined symbol is still reported. It is not a substitute for the Windows
# build; it is the check that makes the Windows build's first attempt worth
# having.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
refs="${TMPDIR:-/tmp}/parfast-refs-$$.txt"
trap 'rm -f "$refs"' EXIT

echo "resolving references (restores on first run)..."
dotnet build "$here/Parfast.App/Parfast.App.csproj" \
  -p:EnableWindowsTargeting=true -t:ResolveReferences -getItem:ReferencePath 2>/dev/null \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
items=d.get('Items',{}).get('ReferencePath',[])
open('$refs','w').write('\n'.join(i['FullPath'] for i in items))
print(f'  {len(items)} reference assemblies')
"

dotnet run --project "$here/Parfast.Check" -- "$here/Parfast.App" "$refs"
