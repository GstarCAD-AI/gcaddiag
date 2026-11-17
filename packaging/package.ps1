param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'scripts/modules/Evidence.ps1')
$destination=Assert-GdiagPlainPath $Output
if (Test-Path -LiteralPath $destination) {throw 'Output already exists; choose a new zip path.'}
$parent=Split-Path -Parent $destination
if (-not (Test-Path -LiteralPath $parent)) {throw 'Output parent must already exist.'}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$files=@('SKILL.md','README.md','agents/openai.yaml','catalog/products.json','scripts/gcaddiag.ps1')
foreach ($directory in @('scripts/modules','references')) {
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root $directory) -File) {
        if ($file.Extension -in @('.ps1','.md')) { $files += $directory+'/'+$file.Name }
    }
}
$archive=[IO.Compression.ZipFile]::Open($destination,[IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($relative in $files) {
        $source=Assert-GdiagPlainPath (Join-Path $root $relative)
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {throw "Missing package resource: $relative"}
        $item=Get-Item -LiteralPath $source
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw "Package resource cannot be a reparse point: $relative"}
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$source,('gcaddiag/'+$relative),[IO.Compression.CompressionLevel]::Optimal)
    }
} finally {$archive.Dispose()}
[pscustomobject]@{path=$destination;files=$files.Count;format='portable skill folder; Codex/project copy or WorkBuddy local import candidate';hostVerification='not performed by packager; see README for actual acceptance'} | ConvertTo-Json -Compress
