$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Evidence.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path (Split-Path -Parent $PSScriptRoot) ('.tmp/trace-workflow-'+[guid]::NewGuid())
$case=Join-Path $root 'case';$payload=Join-Path $root 'payload';$hostRoot=Join-Path $root 'selected-cad'
New-Item -ItemType Directory -Path $case,$payload,$hostRoot -Force|Out-Null
$context=Get-GdiagContext '' $case
$assistant=@{id='assistant';family='GstarAssistant';release='R27';path=$payload;payloadRoot=$payload}
$hostTarget=@{id='host';family='GstarCAD';release='R27';path=$hostRoot}
Write-GdiagJson (Join-Path $case 'case.json') @{formatVersion=1;kind='local';caseId=$context.caseId;context=$context;profile='Crash';isCrashCase=$true;targets=@($assistant,$hostTarget);observations=@();findings=@()}
$envFile=Join-Path $payload '.env';[IO.File]::WriteAllText($envFile,"API_KEY=private-fixture-value`r`nGSTAR_LOG_LEVEL=WARN`r`n",(New-Object Text.UTF8Encoding($true)))
$before=(Get-FileHash -LiteralPath $envFile).Hash
$options=Join-Path $root 'options.json';Write-GdiagJson $options @{recipe='trace-logging';loggingContract='gstar-startup-env-v1';hostTargetId='host'}
$entry=Join-Path $PSScriptRoot '../scripts/gcaddiag.ps1';$shell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
$out=& $shell -NoProfile -File $entry -Action Plan -Operation Repair -Case $case -TargetId assistant -InputFile $options
Assert ($LASTEXITCODE -eq 0) "TRACE planning failed: $out"
$plan=Join-Path $case 'plan.json'
$out=& $shell -NoProfile -File $entry -Action Apply -Plan $plan
Assert ($LASTEXITCODE -eq 0 -and ($out|ConvertFrom-Json).status -eq 'applied') "TRACE apply failed: $out"
$out=& $shell -NoProfile -File $entry -Action Record -Case $case -TargetId assistant -Plan $plan -TimeoutSeconds 1
Assert ($LASTEXITCODE -eq 0) "TRACE capture failed: $out"
$document=Read-GdiagJson (Join-Path $case 'case.json')
Assert ($document.traceRestoration.status -eq 'undone' -and -not $document.capture.traceRestoreRequired) 'Bounded capture did not restore original startup setting'
Assert ((Get-FileHash -LiteralPath $envFile).Hash -eq $before) 'TRACE workflow lost original bytes/secret setting'
$report=[IO.File]::ReadAllText((Join-Path $case 'report.md'))
Assert ($report.Contains('original_startup_config_restored') -and $report -notmatch 'private-fixture-value') 'Restoration missing or original secret leaked in report'
'PASS TRACE workflow: main plan/apply/capture/finally-restore, exact original bytes and truthful runtime restart limit. Artifacts: '+$root
