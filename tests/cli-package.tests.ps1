param([string]$RealPackagePath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Evidence.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Windows.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/CliPackage.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
function MustFail([scriptblock]$Body,$Message){$failed=$false;try{& $Body|Out-Null}catch{$failed=$true};Assert $failed $Message}
$root=Join-Path $PSScriptRoot ('.tmp-cli-package-'+[guid]::NewGuid())
$source=Join-Path $root 'trusted CLI source';$destination=Join-Path $root ('installed '+[char]0x4e2d);$case=Join-Path $root 'case'
New-Item -ItemType Directory -Path $source,$case -Force|Out-Null
$relativeFiles=@('bin/gcad-cli.exe','bin/gcad.cp311-win_amd64.pyd','bin/arch2d.cp311-win_amd64.pyd','bin/architect2d-headless.dll','resources/configs/products/gcad-cli.json','resources/configs/agents/main-agent-cad-v1.json','resources/data/main_agent/runtime_manifest.json','resources/data/main_agent/prompts/main-agent-core-v1.md','resources/skills/gcad-skill-manager/SKILL.md','resources/python/runtime/Python311/python311.dll','python/pygcad/__init__.py','python/pygcadwin/__init__.py','python/pygcadwin/api.py','python/pygcadwin/types.py','python/pygcadwin/_com.py','share/licenses/pygcadwin/LICENSE','bin/superseded.dll')
foreach($name in @('pythoncom.py','win32com/client/__init__.py','win32/lib/pywintypes.py','pywin32_system32/pythoncom311.dll','pywin32_system32/pywintypes311.dll')){$relativeFiles+='resources/python/runtime/Python311/Lib/site-packages/'+$name}
foreach($name in @('architecture_object_layer_rules.yaml','drawing_layer_assignment_rules.yaml','architecture_layers.xml')){$relativeFiles+='resources/architect2d/rules/core/'+$name}
foreach($relative in $relativeFiles){$path=Join-Path $source $relative;New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force|Out-Null;[IO.File]::WriteAllText($path,'fixture-'+$relative)}
# Real PE headers prove architecture parsing; no fixture executable is launched.
foreach($relative in @('bin/gcad-cli.exe','resources/python/runtime/Python311/python311.dll')){Copy-Item -LiteralPath (Get-GdiagWindowsPowerShellPath) -Destination (Join-Path $source $relative)}
Write-GdiagJson (Join-Path $source 'resources/data/main_agent/runtime_manifest.json') @{cad_backend='svg_headless';product_capabilities=@{mcp_stdio_server=$true}}
function SaveManifest($Version){
    $files=[ordered]@{};foreach($relative in $relativeFiles){if(Test-Path -LiteralPath (Join-Path $source $relative)){$files[$relative]=Get-GdiagFileHash (Join-Path $source $relative)}}
    Write-GdiagJson (Join-Path $source 'payload-manifest.json') @{schema_version=2;layout='gcad-cli-v1';product='gcad-cli';version=$Version;target_year='2027';configuration='Release';files=$files}
    Get-GdiagFileHash (Join-Path $source 'payload-manifest.json')
}
$hash=SaveManifest '0.1.0';$ctx=Get-GdiagContext '' $case
$target=[pscustomobject]@{family='gcad-cli';id='cli-1';path=$destination;state='intended'};$ctx.targets=@($target)
Write-GdiagJson (Join-Path $case 'case.json') @{formatVersion=1;kind='local';caseId=$ctx.caseId;context=$ctx;targets=@($target);observations=@();findings=@()}
$options=@{recipe='cli-package';sourcePath=$source;payloadManifestHash=$hash}
$plan=New-GdiagCliPlan $ctx $target Setup $options
Assert (-not(Test-Path -LiteralPath $destination)) 'CLI planning mutated destination'
Assert ($plan.preview.candidateVersion -eq '0.1.0' -and $plan.preview.channel -eq 'not_declared_by_payload_manifest') 'Version/channel preview invented metadata'
$applied=Invoke-GdiagCliPlan $plan Apply $case;Assert ($applied.status -eq 'applied') "CLI Setup failed: $($applied.error)"
Assert ((Invoke-GdiagCliPlan $plan Verify $case).status -eq 'verified') 'Coherent CLI Setup not verified'
$custom=Join-Path $destination 'resources/skills/custom-local/SKILL.md';New-Item -ItemType Directory -Path (Split-Path -Parent $custom) -Force|Out-Null;[IO.File]::WriteAllText($custom,'custom user skill')
Assert ((Invoke-GdiagCliPlan $plan Undo $case).status -eq 'failed') 'Undo overwrote an intervening custom skill'
$missing=Join-Path $destination 'bin/gcad.cp311-win_amd64.pyd';Remove-Item -LiteralPath $missing
$repair=New-GdiagCliPlan $ctx $target Repair $options
Assert ((ConvertTo-GdiagPublic $repair | ConvertTo-Json -Depth 30) -notmatch 'custom-local') 'Private custom inventory escaped the plan projection'
Assert ((Invoke-GdiagCliPlan $repair Apply $case).status -eq 'applied') 'Missing owned CLI payload not repaired'
Assert ((Invoke-GdiagCliPlan $repair Verify $case).status -eq 'verified' -and [IO.File]::ReadAllText($custom) -eq 'custom user skill') 'Repair lost custom resource or incomplete payload'
$config=Join-Path $destination 'resources/configs/products/gcad-cli.json';[IO.File]::WriteAllText($config,'locally edited config')
MustFail {New-GdiagCliPlan $ctx $target Update $options} 'Locally changed shipped configuration accepted for overwrite'
Copy-Item -LiteralPath (Join-Path $source 'resources/configs/products/gcad-cli.json') -Destination $config
Remove-Item -LiteralPath (Join-Path $source 'bin/superseded.dll')
[IO.File]::WriteAllText((Join-Path $source 'resources/data/main_agent/prompts/main-agent-core-v1.md'),'new coherent prompt')
$options.payloadManifestHash=SaveManifest '0.2.0'
$beforeUpdate=Get-GdiagTreeHash @(Get-GdiagCliTree $destination)
$update=New-GdiagCliPlan $ctx $target Update $options
Assert ($update.preview.comparison -eq 'newer' -and $update.preview.installedVersion -eq '0.1.0') 'Update did not compare installed and candidate release'
Assert ((Invoke-GdiagCliPlan $update Apply $case).status -eq 'applied') 'CLI update failed'
Assert (-not(Test-Path -LiteralPath (Join-Path $destination 'bin/superseded.dll')) -and (Test-Path -LiteralPath (Join-Path $update.previousPath 'bin/superseded.dll'))) 'Superseded binary mixed into new runtime or original discarded'
Assert ((Invoke-GdiagCliPlan $update Verify $case).status -eq 'verified' -and [IO.File]::ReadAllText($custom) -eq 'custom user skill') 'Update did not preserve custom file'
Assert ((Invoke-GdiagCliPlan $update Undo $case).status -eq 'undone' -and (Get-GdiagTreeHash @(Get-GdiagCliTree $destination)) -eq $beforeUpdate) 'Undo failed exact prior-tree restoration'
$stale=New-GdiagCliPlan $ctx $target Update $options
[IO.File]::WriteAllText((Join-Path $source 'unlisted-private.txt'),'not distributable')
Assert ((Invoke-GdiagCliPlan $stale Apply $case).status -eq 'failed') 'Source changed after plan but Apply continued'
Remove-Item -LiteralPath (Join-Path $source 'unlisted-private.txt')
$manifestPath=Join-Path $source 'payload-manifest.json';$originalManifest=[IO.File]::ReadAllBytes($manifestPath)
$manifest=Read-GdiagJson $manifestPath;$manifest.files|Add-Member -NotePropertyName '../escape.dll' -NotePropertyValue ('0'*64)
Write-GdiagJson $manifestPath $manifest
MustFail {Get-GdiagCliManifest $source (Get-GdiagFileHash $manifestPath)} 'Traversal accepted in trusted-looking CLI manifest'
[IO.File]::WriteAllBytes($manifestPath,$originalManifest)
# Shared entry/dispatch saves intended target, action receipts and a user report.
$entryCase=Join-Path $root 'entry case';New-Item -ItemType Directory -Path $entryCase|Out-Null
$entryContext=Get-GdiagContext '' $entryCase
Write-GdiagJson (Join-Path $entryCase 'case.json') @{formatVersion=1;kind='local';caseId=$entryContext.caseId;context=$entryContext;targets=@();observations=@();findings=@()}
$entryOptions=Join-Path $root 'entry-options.json';$entryDestination=Join-Path $root 'entry installation'
Write-GdiagJson $entryOptions @{recipe='cli-package';destinationPath=$entryDestination;sourcePath=$source;payloadManifestHash=$options.payloadManifestHash}
$entry=Join-Path $PSScriptRoot '../scripts/gcaddiag.ps1'
$output=& powershell.exe -NoProfile -File $entry -Action Plan -Operation Setup -Case $entryCase -InputFile $entryOptions
Assert ($LASTEXITCODE -eq 0) "Main CLI Plan failed: $output"
$entryPlan=Join-Path $entryCase 'plan.json'
foreach($action in @('Apply','Verify','Undo')){
    $output=& powershell.exe -NoProfile -File $entry -Action $action -Plan $entryPlan
    Assert ($LASTEXITCODE -eq 0) "Main CLI $action failed: $output"
    $receipt=$output|ConvertFrom-Json;Assert ($receipt.status -in @('applied','verified','undone')) "Main CLI $action returned $($receipt.status)"
}
$saved=Read-GdiagJson (Join-Path $entryCase 'case.json')
Assert ($saved.targets.Count -eq 1 -and $saved.targets[0].family -eq 'gcad-cli' -and $saved.targets[0].path -eq $entryDestination) 'Intended CLI target not saved with exact destination'
Assert ($saved.changes.Count -eq 3) 'CLI action receipts missing from case'
$journal=@(Get-Content -LiteralPath (Join-Path $entryCase 'actions.jsonl') -Encoding UTF8|ForEach-Object{$_|ConvertFrom-Json})
Assert ($journal.Count -eq 6) 'CLI handler duplicated or bypassed shared action journal'
$report=Get-Content -LiteralPath (Join-Path $entryCase 'report.md') -Raw -Encoding UTF8
Assert ($report -match 'verified' -and $report -match 'undone' -and -not(Test-Path -LiteralPath $entryDestination)) 'CLI shared report/undo state incorrect'
$executableTarget=[pscustomobject]@{family='gcad-cli';id='cli-1';path=(Join-Path $destination 'bin/gcad-cli.exe')}
Assert ((Get-GdiagCliRoot $executableTarget) -eq $destination) 'Inventoried CLI executable root not derived correctly'
# A real source export can be validated read-only, independently of fixture operations.
if($RealPackagePath){
    $realHash=Get-GdiagFileHash (Join-Path $RealPackagePath 'payload-manifest.json');$real=Get-GdiagCliManifest $RealPackagePath $realHash
    $realTree=Assert-GdiagCliPayload $RealPackagePath $real $realHash -Exact
    Write-GdiagJson (Join-Path $root 'real-package-validation.json') @{status='complete-inventory-verified';source=$RealPackagePath;manifestHash=$realHash;files=$realTree.Count;version=$real.version;targetYear=$real.target_year;runtimeLaunched=$false;publisherAuthenticity='local-source-export-only'}
}
'PASS CLI package: native setup, missing-file repair, coherent update, custom preservation, changed-config refusal, original-tree undo and source/manifest boundaries. Artifacts: '+$root
