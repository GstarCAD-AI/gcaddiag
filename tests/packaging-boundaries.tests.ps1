$ErrorActionPreference='Stop'
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$repository=Split-Path -Parent $PSScriptRoot
$root=Join-Path $repository ('.tmp/package-boundary-'+[guid]::NewGuid())
$fixture=Join-Path $root 'fixture';$outside=Join-Path $root 'private'
New-Item -ItemType Directory -Path (Join-Path $fixture 'packaging'),(Join-Path $fixture 'scripts/modules'),(Join-Path $fixture 'agents'),(Join-Path $fixture 'catalog'),$outside -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $repository 'packaging/package.ps1') -Destination (Join-Path $fixture 'packaging/package.ps1')
Copy-Item -LiteralPath (Join-Path $repository 'scripts/modules/Evidence.ps1') -Destination (Join-Path $fixture 'scripts/modules/Evidence.ps1')
foreach($relative in @('SKILL.md','README.md','agents/openai.yaml','catalog/products.json','scripts/gcaddiag.ps1')){[IO.File]::WriteAllText((Join-Path $fixture $relative),'owned harmless package fixture')}
[IO.File]::WriteAllText((Join-Path $outside 'private.md'),'private marker must not enter package')
$junction=Join-Path $fixture 'references'
New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
try{
    $zip=Join-Path $root 'rejected-source.zip';$refused=$false
    try{& (Join-Path $fixture 'packaging/package.ps1') -Output $zip | Out-Null}catch{$refused=($_.Exception.Message -match 'Reparse')}
    Assert $refused 'Package followed a junction to external private reference data'
    if(Test-Path -LiteralPath $zip){
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive=[IO.Compression.ZipFile]::OpenRead($zip)
        try{Assert (-not @($archive.Entries | Where-Object FullName -match 'private').Count) 'Rejected private file leaked into partial package'}finally{$archive.Dispose()}
    }
    $refused=$false
    try{& (Join-Path $repository 'packaging/package.ps1') -Output (Join-Path $junction 'should-not-exist.zip') | Out-Null}catch{$refused=($_.Exception.Message -match 'Reparse')}
    Assert $refused 'Package wrote through a destination junction'
    Assert (-not(Test-Path -LiteralPath (Join-Path $outside 'should-not-exist.zip'))) 'Rejected destination was modified'
}finally{
    # Remove only the owned junction itself, with a nonrecursive native call.
    $resolved=[IO.Path]::GetFullPath($junction)
    if(-not $resolved.StartsWith([IO.Path]::GetFullPath($fixture).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected fixture junction path'}
    [IO.Directory]::Delete($resolved,$false)
}
'PASS packaging: reference and destination reparse ancestry refused; external file unchanged. Artifacts: '+$root
