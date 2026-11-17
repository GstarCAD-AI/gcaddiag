param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Evidence.ps1')
$destination=Assert-GdiagPlainPath $Output
if(Test-Path -LiteralPath $destination){throw 'Choose a new support-kit ZIP path.'}
$parent=Split-Path -Parent $destination
if(-not(Test-Path -LiteralPath $parent -PathType Container)){throw 'Output parent must already exist.'}
$staging=Assert-GdiagPlainPath (Join-Path $parent ('.gcaddiag-support-'+[guid]::NewGuid()))
New-Item -ItemType Directory -Path $staging | Out-Null
try {
    $runtime=Join-Path $staging 'runtime.zip'
    & (Join-Path $PSScriptRoot 'package.ps1') -Output $runtime | Out-Null
    Expand-Archive -LiteralPath $runtime -DestinationPath $staging
    Remove-Item -LiteralPath $runtime -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'customer-launcher.cmd') -Destination (Join-Path $staging 'collect-customer.cmd')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../references/remote-support.md') -Destination (Join-Path $staging 'START-HERE.md')
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive=[IO.Compression.ZipFile]::Open($destination,[IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach($file in Get-ChildItem -LiteralPath $staging -File -Recurse){
            $source=Assert-GdiagPlainPath $file.FullName
            $relative=$source.Substring($staging.TrimEnd('\').Length+1).Replace('\','/')
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$source,$relative,[IO.Compression.CompressionLevel]::Optimal)
        }
    }finally{$archive.Dispose()}
} finally {
    $resolved=Assert-GdiagPlainPath $staging;$boundary=[IO.Path]::GetFullPath($parent).TrimEnd('\')+'\'
    if(-not $resolved.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolved) -notmatch '^\.gcaddiag-support-[0-9a-f-]{36}$'){throw 'Refusing staging cleanup outside the verified output parent.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
[pscustomobject]@{status='prepared';path=$destination;customerPrerequisites='Windows PowerShell 5.1 and permitted script execution';modelRequired=$false;uploaded=$false;installed=$false} | ConvertTo-Json -Compress
