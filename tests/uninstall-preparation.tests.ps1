$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Evidence.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Windows.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path $PSScriptRoot ('.tmp-uninstall-preparation-'+[guid]::NewGuid())
$casePath=Join-Path $root 'case';$installation=Join-Path $root ('selected '+[char]0x4e2d);$payload=Join-Path $installation 'contents';$other=Join-Path $root 'other-release'
New-Item -ItemType Directory -Path $casePath,$payload,$other -Force | Out-Null
$module=Join-Path $payload 'module.dll';[IO.File]::WriteAllText($module,'fixture payload, not executable')
$custom=Join-Path $installation 'private-customer-drawing.dwg';[IO.File]::WriteAllText($custom,'private drawing bytes')
$settings=Join-Path $payload '.env';[IO.File]::WriteAllText($settings,'API_KEY=do-not-export-fixture')
[IO.File]::WriteAllText((Join-Path $installation 'uninstall.exe'),'not a real uninstaller; must never run')
[IO.File]::WriteAllText((Join-Path $other 'custom.txt'),'other release unchanged')
Write-GdiagJson (Join-Path $payload 'payload-manifest.json') @{schema_version=2;product='GstarAssistant';layout='gstarassistant-v1';files=@{'module.dll'=(Get-GdiagFileHash $module);'.env'=(Get-GdiagFileHash $settings)}}
$context=Get-GdiagContext '' $casePath
$target=[pscustomobject]@{id='assistant-1';family='GstarAssistant';release='R27';path=$installation;payloadRoot=$payload}
$otherTarget=[pscustomobject]@{id='assistant-2';family='GstarAssistant';release='R26';path=$other}
$context.targets=@($target,$otherTarget)
$before=Get-GdiagTreeHash @(Get-GdiagTree $installation);$otherBefore=Get-GdiagTreeHash @(Get-GdiagTree $other)
$plan=New-GdiagPlan $context $target Uninstall @{}
Assert ($plan.status -eq 'guidance_only' -and $plan.preparation.status -eq 'inventory_complete') 'Native read-only preparation failed'
Assert ($plan.preparation.categories.userOrConfiguration -eq 2) 'Drawing or listed settings not marked for preservation'
Assert ($plan.preparation.categories.manifestListed -eq 1) 'Legacy nested payload manifest membership not resolved'
Assert ($plan.preparation.overlapCount -eq 0) 'Separate release wrongly overlaps'
Assert ($plan.preparation.observed.files.Count -eq 5) 'Exact private inventory incomplete'
$public=ConvertTo-GdiagPublic $plan | ConvertTo-Json -Depth 30
Assert ($public -notmatch 'private-customer-drawing|do-not-export-fixture|private drawing bytes') 'Private inventory/content leaked to agent output'
$planPath=Join-Path $casePath 'plan.json';Write-GdiagJson $planPath $plan
$failed=$false;try{Invoke-GdiagPlan $planPath Apply | Out-Null}catch{$failed=$true}
Assert $failed 'Preparation allowed executable uninstall'
$context.targets+=@([pscustomobject]@{id='nested';family='Skill';path=(Join-Path $installation 'skills')})
$nested=New-GdiagPlan $context $target Uninstall @{}
Assert ($nested.preparation.overlapCount -eq 1) 'Nested other target missed'
# Registry contract is mocked here only; the file inventory and entrypoint below are native.
function Get-GdiagRegistryRecord($Hive,$View,$Key,$Sid){
    $values=@([pscustomobject]@{name='InstallLocation';raw=$installation;type='String'})
    if($Key -match '\\Uninstall\\'){$values+=@([pscustomobject]@{name='UninstallString';raw=('"'+(Join-Path $installation 'uninstall.exe')+'"');type='String'})}
    else{$values+=@([pscustomobject]@{name='GcadProductRelease';raw='B27';type='String'},[pscustomobject]@{name='GcadLocale';raw='en-US';type='String'})}
    [pscustomobject]@{status='observed';values=$values}
}
$shared=New-GdiagPlan $context $target Uninstall @{}
Assert ($shared.preparation.sharedReleaseRoot -and $shared.preparation.startupRegistration -eq 'recorded_target_requires_current_host_validation') 'Shared R26/R27 root or B27 startup contract missed'
Assert ($shared.preparation.uninstallerRegistration -eq 'matches_exact_source_command') 'Exact uninstall command association missed'
Assert (@($shared.preparation.observed.registration | Where-Object {$_.startupKey -match '\\B27\\en-US\\'}).Count -eq 1) 'GcadProductRelease was replaced by assistant release'
$context.Remove('targets')
Write-GdiagJson (Join-Path $casePath 'case.json') @{formatVersion=1;kind='local';caseId=$context.caseId;context=$context;targets=@($target,$otherTarget);observations=@();findings=@()}
$entry=Join-Path $PSScriptRoot '../scripts/gcaddiag.ps1'
$output=& powershell.exe -NoProfile -File $entry -Action Plan -Operation Uninstall -Case $casePath -TargetId $target.id
Assert ($LASTEXITCODE -eq 0) "Main uninstall preparation failed: $output"
$saved=Read-GdiagJson (Join-Path $casePath 'case.json')
Assert (@($saved.observations | Where-Object source -eq 'maintenance.uninstall_preparation').Count -eq 1) 'Preparation missing from saved case'
$report=Get-Content -LiteralPath (Join-Path $casePath 'report.md') -Raw -Encoding UTF8
Assert ($report -match 'preservation' -and $report -notmatch 'private-customer-drawing|do-not-export-fixture') 'Preparation report missing or leaking local inventory'
Assert ((Get-GdiagTreeHash @(Get-GdiagTree $installation)) -eq $before -and (Get-GdiagTreeHash @(Get-GdiagTree $other)) -eq $otherBefore) 'Preparation modified a target'
'PASS uninstall preparation: native selected/legacy payload inventory, user-data preservation, overlap detection, exact registry contract fixtures, main report, no execution or source changes. Artifacts: '+$root
