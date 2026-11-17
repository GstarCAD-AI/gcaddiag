$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Windows.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Prerequisites.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path $PSScriptRoot ('.tmp-prerequisites-'+[guid]::NewGuid())
$distribution=Join-Path $root ('CLI '+[char]0x4E2D+[char]0x6587)
$bin=Join-Path $distribution 'bin';$resources=Join-Path $distribution 'resources'
New-Item -ItemType Directory -Path $bin,$resources -Force|Out-Null
Copy-Item -LiteralPath (Join-Path $PSHOME 'powershell.exe') -Destination (Join-Path $bin 'gcad-cli.exe')
Copy-Item -LiteralPath (Join-Path $PSHOME 'powershell.exe') -Destination (Join-Path $bin 'gcad-tui.exe')
foreach($relative in @('data/main_agent/runtime_manifest.json','configs/agents/main-agent-cad-v1.json','data/main_agent/prompts/main-agent-core-v1.md','skills/gcad-skill-manager/SKILL.md')){
    $path=Join-Path $resources $relative;New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force|Out-Null
    [IO.File]::WriteAllText($path,'fixture resource')
}
$environment=Join-Path $root 'dedicated environment'
New-Item -ItemType Directory -Path (Join-Path $environment 'Scripts'),(Join-Path $environment 'Lib/site-packages/pygcadwin-9.9.9.dist-info') -Force|Out-Null
Copy-Item -LiteralPath (Join-Path $PSHOME 'powershell.exe') -Destination (Join-Path $environment 'Scripts/python.exe')
[IO.File]::WriteAllText((Join-Path $environment 'pyvenv.cfg'),'home = explicit fixture')
[IO.File]::WriteAllText((Join-Path $environment 'Lib/site-packages/pygcadwin-9.9.9.dist-info/METADATA'),"Name: pygcadwin`nVersion: 9.9.9`n")
$context=@{executorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;affectedSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
$targets=@(Get-GdiagAdditionalTargets $context @{cliPaths=@($distribution);automationPaths=@($environment)})
$cli=@($targets|Where-Object {$_.family -eq 'gcad-cli' -and $_.path.StartsWith($distribution)})
Assert ($cli.Count -eq 2) 'Distinct executable distributions were conflated'
Assert (@($cli|Where-Object {$_.resources.status -eq 'metadata_present' -and $_.release -eq 'unknown' -and $_.hostVerification -eq 'pending'}).Count -eq 2) 'Metadata incorrectly became release identity or runtime readiness'
$venv=@($targets|Where-Object path -eq $environment)[0]
Assert ($venv.family -eq 'AutomationEnvironment' -and $venv.environmentMarker -eq 'present') 'Selected environment identity missing'
Assert ($venv.packageMetadata[0].declaredVersion -eq '9.9.9' -and $venv.packageMetadata[0].import -eq 'not_tested') 'Installed package metadata incorrectly establishes import/compatibility'
Remove-Item -LiteralPath (Join-Path $resources 'skills/gcad-skill-manager/SKILL.md')
$again=@(Get-GdiagAdditionalTargets $context @{cliPaths=@($distribution)})
Assert (@($again|Where-Object {$_.path.StartsWith($distribution) -and $_.resources.status -eq 'incomplete'}).Count -eq 2) 'Missing runtime contract was not attributable to selected distributions'
$native=@(Get-GdiagPrerequisiteEvidence $context $targets)
Assert (@($native|Where-Object source -eq 'prerequisite.visual-cpp-x64').Count -eq 2) 'Native registry views not collected'
$native|Select-Object source,status,summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root 'native-prerequisites.json') -Encoding UTF8
$originalRegistry=${function:Get-GdiagRegistryRecord}
try{
    function Get-GdiagRegistryRecord {
        param($Hive,$View,$Key,$UserSid)
        if($View -eq 'Registry64'){return [pscustomobject]@{hive=$Hive;view=$View;key=$Key;status='access_denied';values=@();error=@{domain='HRESULT';code=-2147024891};subkeys=@()}}
        [pscustomobject]@{hive=$Hive;view=$View;key=$Key;status='observed';values=@([pscustomobject]@{name='Installed';type='DWord';raw=1},[pscustomobject]@{name='Bld';type='DWord';raw=10000});subkeys=@()}
    }
    $fixture=@(Get-GdiagPrerequisiteEvidence $context @()|Where-Object source -eq 'prerequisite.visual-cpp-x64')
    Assert ($fixture[0].status -eq 'access_denied' -and $fixture[0].summary.nativeErrorCode -eq -2147024891) 'Denied prerequisite registry became absence'
    Assert ($fixture[1].summary.registrationAssessment -eq 'below_reviewed_generator_default' -and $fixture[1].summary.runtimeLoading -eq 'not_tested') 'Review default incorrectly became runtime health or selected-package minimum'
}finally{Set-Item -Path Function:Get-GdiagRegistryRecord -Value $originalRegistry}
'PASS prerequisites: native typed views, access-denied fixture, source-derived independent CLI resources, distinct executables, selected environment/package metadata. Artifacts: '+$root
