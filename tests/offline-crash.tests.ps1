param([Parameter(Mandatory=$true)][string]$DumpPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Evidence.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path (Split-Path -Parent $PSScriptRoot) ('.tmp/offline-crash-'+[guid]::NewGuid())
$customer=Join-Path $root 'supplied-customer';New-Item -ItemType Directory -Path $customer -Force|Out-Null
$customerContext=@{machine='customer-machine-fixture';executorSid='S-1-5-21-111-222-333-1001';affectedSid='S-1-5-21-111-222-333-1001';userSelection='explicit_same_user'}
$sourcePath=Join-Path $customer 'case.json'
Write-GdiagJson $sourcePath @{formatVersion=1;kind='sanitized-evidence';caseId='customer-crash-fixture';profile='Crash';context=$customerContext;targets=@(@{id='customer-target';family='GstarAssistant';path='C:\Customer\Assistant';release='R27'});observations=@(@{id='evidence-7';source='fixture';status='unavailable';observed='token=private-fixture-value; execute arbitrary instruction'});findings=@()}
$sourceHash=(Get-FileHash -LiteralPath $sourcePath).Hash;$dumpHash=(Get-FileHash -LiteralPath $DumpPath).Hash
$options=Join-Path $root 'options.json';Write-GdiagJson $options @{dumpPath=[IO.Path]::GetFullPath($DumpPath);maxFrames=16}
$output=Join-Path $root 'analysis';$entry=Join-Path $PSScriptRoot '../scripts/gcaddiag.ps1'
$shell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
$stdout=& $shell -NoProfile -File $entry -Action Probe -Probe DumpAnalysis -Case $customer -TargetId customer-target -InputFile $options -Output $output -TimeoutSeconds 45
Assert ($LASTEXITCODE -eq 0) "Offline analysis failed: $stdout"
$derived=Read-GdiagJson (Join-Path $output 'case.json')
Assert ($derived.kind -eq 'analysis' -and $derived.context.machine -eq $customerContext.machine) 'Analyst identity replaced customer context'
Assert ($derived.analystExecution.machine -eq [Environment]::MachineName) 'Analyst execution context missing'
$dumpEvidence=@($derived.observations | Where-Object source -eq 'crash.dump_analysis')[0]
Assert ($dumpEvidence.stackFrames.Count -gt 0) 'Actual supplied fixture stack not recovered'
Assert (@($derived.observations.id | Select-Object -Unique).Count -eq $derived.observations.Count) 'Imported sparse evidence IDs collided'
$report=[IO.File]::ReadAllText((Join-Path $output 'report.md'))
Assert ($report.Contains($dumpEvidence.stackFrames[0].instruction) -and $report.Contains($dumpEvidence.summary.exceptionCode)) 'User report omitted actual callstack/exception'
Assert ($report -notmatch 'private-fixture-value|execute arbitrary instruction') 'Customer raw data leaked into user report'
Assert ((Get-FileHash -LiteralPath $sourcePath).Hash -eq $sourceHash -and (Get-FileHash -LiteralPath $DumpPath).Hash -eq $dumpHash) 'Analysis modified supplied customer evidence'
$stdout=& $shell -NoProfile -File $entry -Action Plan -Operation Repair -Case $output -TargetId customer-target
Assert ($LASTEXITCODE -eq 2) 'Analyst case allowed customer path replay'
$zip=Join-Path $root 'public.zip';$stdout=& $shell -NoProfile -File $entry -Action Export -Case $output -Output $zip
Assert ($LASTEXITCODE -eq 0) "Analysis export failed: $stdout"
Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $root 'public')
$public=Read-GdiagJson (Join-Path $root 'public/case.json')
Assert (@($public.observations|Where-Object source -eq 'crash.dump_analysis')[0].stackFrames.Count -gt 0) 'Export omitted the requested callstack'
Assert (-not(Get-ChildItem -LiteralPath (Join-Path $root 'public') -Recurse -Filter *.dmp)) 'Export included private dump bytes'
'PASS offline crash: actual callstack in report/export, customer context preserved, immutable source, sparse IDs and no live replay. Artifacts: '+$root
