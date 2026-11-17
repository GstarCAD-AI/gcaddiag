$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Evidence.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
function Assert($Condition,$Message) {if(-not $Condition){throw $Message}}
$root=Join-Path (Split-Path -Parent $PSScriptRoot) ('.tmp/entry-lifecycle-'+[guid]::NewGuid())
$case=Join-Path $root 'case';$source=Join-Path $root 'source';$destination=Join-Path $root 'installed'
New-Item -ItemType Directory -Path $case,$source -Force | Out-Null
$context=Get-GdiagContext '' $case
Write-GdiagJson (Join-Path $case 'case.json') @{formatVersion=1;kind='local';caseId=$context.caseId;context=$context;targets=@();observations=@();findings=@()}
[IO.File]::WriteAllText((Join-Path $source 'SKILL.md'),"---`nname: fixture`ndescription: Isolated fixture`n---`nTest resource")
$options=Join-Path $root 'options.json'
Write-GdiagJson $options @{recipe='skill-package';sourcePath=$source;destinationPath=$destination;expectedPackageHash=(Get-GdiagTreeHash @(Get-GdiagTree $source))}
$entry=Join-Path $PSScriptRoot '../scripts/gcaddiag.ps1'
$output=& powershell.exe -NoProfile -File $entry -Action Plan -Operation Setup -Case $case -InputFile $options
Assert ($LASTEXITCODE -eq 0) "Entry planning failed: $output"
Assert (-not(Test-Path $destination)) 'Entry planning mutated destination'
$plan=Join-Path $case 'plan.json'
foreach($action in @('Apply','Verify','Undo')) {
    $output=& powershell.exe -NoProfile -File $entry -Action $action -Plan $plan
    Assert ($LASTEXITCODE -eq 0) "Entry $action failed: $output"
    $parsed=$output | ConvertFrom-Json
    Assert ($parsed.status -in @('applied','verified','undone')) "Entry $action returned $($parsed.status)"
}
$document=Read-GdiagJson (Join-Path $case 'case.json')
Assert ($document.targets.Count -eq 1) 'Intended setup target not saved in case'
Assert ($document.changes.Count -eq 3) 'Lifecycle results missing from case/report'
$report=Get-Content -LiteralPath (Join-Path $case 'report.md') -Raw -Encoding UTF8
Assert ($report.Contains('verified') -and $report.Contains('undone')) 'Native report omitted verification/reversal'
'PASS entry lifecycle: intended target, plan/apply/verify/undo, same-evidence maintenance report. Artifacts: '+$root
