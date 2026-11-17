$ErrorActionPreference='Stop'
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path (Split-Path -Parent $PSScriptRoot) ('.tmp/support-kit-'+[guid]::NewGuid())
New-Item -ItemType Directory -Path $root | Out-Null
$zip=Join-Path $root 'support.zip'
& (Join-Path $PSScriptRoot '../packaging/support-kit.ps1') -Output $zip | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=[IO.Compression.ZipFile]::OpenRead($zip)
try{
    $names=@($archive.Entries.FullName)
    Assert ('collect-customer.cmd' -in $names -and 'START-HERE.md' -in $names) 'Customer entry/instructions missing'
    Assert ('gcaddiag/scripts/gcaddiag.ps1' -in $names) 'Portable native collector missing'
    Assert (-not @($names | Where-Object {$_ -match 'TASKS\.md|GUIDELINE\.md|/tests/|/cases/|/\.tmp/|\.dll$|auth\.json'}).Count) 'Maintainer/customer/SDK/auth material leaked into support kit'
}finally{$archive.Dispose()}
$install=Join-Path $root ('extracted '+[char]0x4E2D+[char]0x6587)
Expand-Archive -LiteralPath $zip -DestinationPath $install
$case=Join-Path $root ('customer case '+[char]0x4E2D)
$launcher=Join-Path $install 'collect-customer.cmd'
$result=& $launcher $case
Assert ($LASTEXITCODE -eq 0) "Native customer launcher failed: $result"
Assert (Test-Path -LiteralPath (Join-Path $case 'report.md')) 'Customer report not created'
Assert (Test-Path -LiteralPath ($case+'-redacted.zip')) 'Reviewable redacted bundle not created'
$caseData=Get-Content -LiteralPath (Join-Path $case 'case.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Assert ($caseData.kind -eq 'local' -and $caseData.context.executorSid) 'Customer collection identity missing'
$public=Join-Path $root 'review';Expand-Archive -LiteralPath ($case+'-redacted.zip') -DestinationPath $public
$publicData=Get-Content -LiteralPath (Join-Path $public 'case.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Assert ($publicData.kind -eq 'sanitized-evidence') 'Customer sharing bundle has live authority'
Assert (@(Get-ChildItem -LiteralPath $public -File).Count -eq 2) 'Customer export includes unexpected raw artifacts'
'PASS support kit: allowlisted script-only ZIP, native Unicode/spaced customer launcher, report and sanitized bundle, no model/customer install. Artifacts: '+$root
