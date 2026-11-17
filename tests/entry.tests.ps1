$ErrorActionPreference='Stop'
function Assert($Condition,$Message) {if (-not $Condition) {throw $Message}}
$repository=Split-Path -Parent $PSScriptRoot
$root=Join-Path $repository ('.tmp/portable '+[char]0x4E2D+[char]0x6587+' '+[guid]::NewGuid())
New-Item -ItemType Directory -Path $root -Force | Out-Null
$zip=Join-Path $root 'skill.zip'
& (Join-Path $repository 'packaging/package.ps1') -Output $zip | Out-Null
Expand-Archive -LiteralPath $zip -DestinationPath $root
Assert (-not (Test-Path (Join-Path $root 'gcaddiag/TASKS.md'))) 'Task inventory leaked into runtime package'
Assert (-not (Test-Path (Join-Path $root 'gcaddiag/GUIDELINE.md'))) 'Guideline leaked into runtime package'
$entry=Join-Path $root 'gcaddiag/scripts/gcaddiag.ps1'
$case=Join-Path $root 'native case'
$originalPath=$env:PATH
try {
    $env:PATH=''
    $result=& (Join-Path $PSHOME 'powershell.exe') -NoProfile -File $entry -Action Scan -Output $case -Symptom 'Independent entry acceptance'
    Assert ($LASTEXITCODE -eq 0) "Portable scan failed: $result"
} finally { $env:PATH=$originalPath }
$parsed=$result | ConvertFrom-Json
if ($parsed.stdoutTruncated) {Assert ($parsed.targets[0].id -match '^target-') 'Compact output lost target identity'}
$saved=Get-Content -LiteralPath (Join-Path $case 'case.json') -Raw -Encoding UTF8 | ConvertFrom-Json
Assert ($saved.formatVersion -eq 1 -and $saved.kind -eq 'local') 'Case format not recorded'
Assert ($saved.context.executorSid -and $saved.context.affectedSid) 'Windows identity missing'
Assert (@(Get-Content -LiteralPath (Join-Path $case 'report.md')).Count -gt 8) 'Native report malformed'
$foreign=Join-Path $root 'foreign case';New-Item -ItemType Directory -Path $foreign | Out-Null
$saved.kind='sanitized-evidence'
$saved | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath (Join-Path $foreign 'case.json') -Encoding UTF8
$response=& (Join-Path $PSHOME 'powershell.exe') -NoProfile -File $entry -Action Record -Case $foreign -TimeoutSeconds 1
Assert ($LASTEXITCODE -eq 2) 'Public bundle authorized live capture'
'PASS entry: installed Unicode/spaced path, empty PATH, native case/report, bounded target output, public bundle refusal. Artifacts: '+$root
