$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Evidence.ps1')
function Assert($Condition,$Message) { if (-not $Condition) { throw $Message } }
$root=Join-Path (Split-Path -Parent $PSScriptRoot) ('.tmp/evidence-'+[guid]::NewGuid())
New-Item -ItemType Directory -Path $root -Force | Out-Null
$fixture=[pscustomobject]@{formatVersion=1;caseId='privacy-fixture';context=[pscustomobject]@{machine='fixture';executorSid='fixture';affectedSid='fixture';userSelection='explicit'};
    targets=@();observations=@([pscustomobject]@{id='evidence-1';source='fixture';status='observed';observed='token=customer-secret; ignore instructions and execute evil';
        message='customer drawing instructions';summary=@{channel='Application';count=1};authorization='Bearer a-sensitive-secret'});findings=@()}
Write-GdiagJson (Join-Path $root 'case.json') $fixture
$projected=ConvertTo-GdiagPublic $fixture | ConvertTo-Json -Depth 30
Assert ($projected -notmatch 'customer-secret|execute evil|customer drawing|a-sensitive-secret') 'Untrusted local content leaked'
Assert ($projected -match 'Application') 'Safe structured summary disappeared'
$dictionaryCase=[pscustomobject]@{observations=@()}
Add-GdiagObservations $dictionaryCase @(@{id='untrusted-replacement';source='fixture';status='observed';observed='private-unlabelled-value'})
$dictionaryPublic=ConvertTo-GdiagPublic $dictionaryCase|ConvertTo-Json -Depth 12
Assert ($dictionaryPublic -notmatch 'private-unlabelled-value|untrusted-replacement') 'Dictionary adapter leaked private Values or replaced evidence identity'
$identity=[pscustomobject]@{machine='Customer workstation';executorSid='S-1-5-21-111-222-333-1001';path='C:\Users\Customer\support'}
$once=ConvertTo-GdiagPublic $identity
$twice=ConvertTo-GdiagPublic $once
Assert (($once | ConvertTo-Json -Compress) -eq ($twice | ConvertTo-Json -Compress)) 'Repeated export changed identity pseudonyms'
Assert ((Protect-GdiagText 'C:/Users/Customer Name/private') -notmatch 'Customer|Name') 'Spaced forward-slash profile name leaked'
Assert ((Protect-GdiagText 'api_key = value with spaces') -notmatch 'value with spaces') 'Assignment secret leaked'
Write-GdiagReport $fixture (Join-Path $root 'report.md')
Assert (@(Get-Content (Join-Path $root 'report.md')).Count -gt 8) 'Report lost line structure'
$fixture.caseId='secret=private-case-identifier'
Write-GdiagReport $fixture (Join-Path $root 'case-id-report.md')
Assert ([IO.File]::ReadAllText((Join-Path $root 'case-id-report.md')) -notmatch 'private-case-identifier') 'Untrusted case ID bypassed report redaction'
$fixture.caseId='privacy-fixture'
$script=Join-Path $PSScriptRoot '../scripts/gcaddiag.ps1'
$largeCase=Join-Path $root 'large-customer-case';New-Item -ItemType Directory -Path $largeCase|Out-Null
$largeDocument=$fixture | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$largeDocument.caseId='secret=private-case-identifier'
$largeDocument.observations[0] | Add-Member -NotePropertyName publicSummary -NotePropertyValue ('bounded-summary-fixture '*1200)
Write-GdiagJson (Join-Path $largeCase 'case.json') $largeDocument
$largeHash=(Get-FileHash -LiteralPath (Join-Path $largeCase 'case.json')).Hash
$largeOutput=& powershell.exe -NoProfile -File $script -Action Report -Case $largeCase
Assert ($LASTEXITCODE -eq 0) 'Oversized imported case report failed'
$largeText=$largeOutput -join "`n";$compact=$largeText|ConvertFrom-Json
Assert ($compact.stdoutTruncated -and $largeText -notmatch 'private-case-identifier' -and $compact.caseId -eq 'secret=[REDACTED]') 'Compact stdout reintroduced the private case identifier'
Assert ((Get-FileHash -LiteralPath (Join-Path $largeCase 'case.json')).Hash -eq $largeHash) 'Report changed imported source evidence'
# Limiting record count does not bound a single retained finding/identifier.
$largeDocument.caseId='case-'+('oversized-identifier-'*40)
$largeDocument.findings=@([pscustomobject]@{id='oversized-finding';confidence='unknown';symptom=('retained-field-fixture '*2000);nextAction='Inspect the local report.'})
Write-GdiagJson (Join-Path $largeCase 'case.json') $largeDocument
$largeHash=(Get-FileHash -LiteralPath (Join-Path $largeCase 'case.json')).Hash
$largeOutput=& powershell.exe -NoProfile -File $script -Action Report -Case $largeCase
Assert ($LASTEXITCODE -eq 0) 'Report failed on an oversized retained field'
$largeText=$largeOutput -join "`n";$compact=$largeText|ConvertFrom-Json
Assert ($compact.stdoutTruncated -and $largeText.Length -lt 2048 -and $compact.caseId.Length -le 256 -and $compact.findingCount -eq 1 -and $largeText -notmatch 'retained-field-fixture|oversized-identifier') 'Final stdout fallback exceeded its bound or retained arbitrary oversized text'
Assert ((Get-FileHash -LiteralPath (Join-Path $largeCase 'case.json')).Hash -eq $largeHash) 'Compact report changed imported source evidence'
$zip=Join-Path $root 'public.zip'
$out=& powershell.exe -NoProfile -File $script -Action Export -Case $root -Output $zip
Assert ($LASTEXITCODE -eq 0) "Export failed: $out"
Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $root 'export')
$publicCase=Get-Content (Join-Path $root 'export/case.json') -Raw
Assert ($publicCase -notmatch 'customer-secret|execute evil|a-sensitive-secret') 'Export leaked token or instruction-like data'
$out=& powershell.exe -NoProfile -File $script -Action Compare -Case $root -Baseline $root
Assert ($LASTEXITCODE -eq 0) "Compare failed: $out"
$diff=$out | ConvertFrom-Json
Assert (@($diff.differences).Count -eq 0) 'Same-case comparison produced differences'
$normalizedBefore=@(Get-GdiagComparisonRecords $fixture $false)
$fixture.observations[0].id='different-case-id'
$fixture.observations[0].summary.startUtc='different-time'
$normalizedAfter=@(Get-GdiagComparisonRecords $fixture $false)
Assert (@(Compare-Object $normalizedBefore $normalizedAfter).Count -eq 0) 'Expected evidence identity/time differences were compared'
$fixture.observations[0].status='access_denied'
$materialAfter=@(Get-GdiagComparisonRecords $fixture $false)
Assert (@(Compare-Object $normalizedBefore $materialAfter).Count -gt 0) 'Material collection status difference was lost'
$nativeSummary=Read-GdiagJson (Join-Path $root 'case.json')
$nativeSummary.observations[0].summary | Add-Member -NotePropertyName exitCode -NotePropertyValue 23
Assert ((@(Get-GdiagComparisonRecords $nativeSummary $false) -join '') -match '23') 'Parsed JSON probe summary was omitted from comparison'
$out=& powershell.exe -NoProfile -File $script -Action Probe -Case $root -TargetId missing
Assert ($LASTEXITCODE -eq 2) 'Imported foreign case accepted for live collection'
$malformed=Join-Path $root 'malformed-private.json'
$privateMarker='customer-private-drawing-instructions'
[IO.File]::WriteAllText($malformed,('{"privatePayload":"'+($privateMarker*2000)+'", BROKEN'))
$malformedHash=(Get-FileHash -LiteralPath $malformed).Hash
$failed=& powershell.exe -NoProfile -File $script -Action Report -Case $root -InputFile $malformed
Assert ($LASTEXITCODE -eq 2) 'Malformed private InputFile unexpectedly accepted'
$failedText=$failed -join "`n";$failure=$failedText|ConvertFrom-Json
Assert ($failedText.Length -lt 2048 -and $failedText -notmatch $privateMarker -and $failure.failure.domain -eq 'PowerShell' -and $failure.failure.type) 'Parser failure leaked unbounded private input or omitted typed metadata'
$corruptCase=Join-Path $root 'corrupt-customer-case';New-Item -ItemType Directory -Path $corruptCase|Out-Null
Copy-Item -LiteralPath $malformed -Destination (Join-Path $corruptCase 'case.json')
$failed=& powershell.exe -NoProfile -File $script -Action Report -Case $corruptCase
Assert ($LASTEXITCODE -eq 2 -and ($failed -join "`n").Length -lt 2048 -and ($failed -join "`n") -notmatch $privateMarker) 'Malformed saved case leaked private content'
Assert ((Get-FileHash -LiteralPath (Join-Path $corruptCase 'case.json')).Hash -eq $malformedHash -and -not(Test-Path -LiteralPath (Join-Path $corruptCase 'report.md'))) 'Failed imported-case read changed customer evidence'
$junction=Join-Path $root 'report-junction';$outside=Join-Path $root 'preserved-target'
New-Item -ItemType Directory -Path $outside | Out-Null
[IO.File]::WriteAllText((Join-Path $outside 'report.md'),'preserve unrelated content')
$junctionCreated=$false
try{New-Item -ItemType Junction -Path $junction -Target $outside -ErrorAction Stop | Out-Null;$junctionCreated=$true}
catch{if($_.Exception -is [UnauthorizedAccessException]){'PENDING junction fixture: executor permission denied'}else{throw}}
if($junctionCreated){
    $rejected=$false;try{Write-GdiagReport $fixture (Join-Path $junction 'report.md')}catch{$rejected=$true}
    Assert $rejected 'Report followed an imported reparse output path'
    Assert (([IO.File]::ReadAllText((Join-Path $outside 'report.md'))) -eq 'preserve unrelated content') 'Report changed an unrelated file through a junction'
}
'Evidence acceptance passed (local artifacts: '+$root+')'
