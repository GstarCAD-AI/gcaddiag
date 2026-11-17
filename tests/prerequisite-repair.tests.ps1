# Structural handler acceptance. Registry, Microsoft trust, UAC and host-idle checks are mocked;
# the fixture executable and post-action DLL-load child are real and touch only this test directory.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Evidence.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Windows.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/PrerequisiteRepair.ps1')
function Assert($Value,$Message){if(-not $Value){throw $Message}}
function MustFail([scriptblock]$Block,$Message){$failed=$false;try{& $Block | Out-Null}catch{$failed=$true};Assert $failed $Message}
$root=Join-Path $PSScriptRoot ('.tmp-prerequisite-repair-'+[guid]::NewGuid())
$casePath=Join-Path $root 'case';$consumer=Join-Path $root ('assistant '+[char]0x4e2d);$package=Join-Path $root 'vc_fixture.exe'
New-Item -ItemType Directory -Path $casePath,$consumer | Out-Null
$fixture=@'
using System;
using System.IO;
public static class VcFixture {
 public static int Main(string[] args) {
  if(args.Length < 4 || (args[0]!="/install" && args[0]!="/repair") || args[1]!="/norestart" || args[2]!="/log") return 91;
  if(args.Length>5 || (args.Length==5 && args[4]!="/quiet")) return 92;
  string root=AppDomain.CurrentDomain.BaseDirectory;
  File.WriteAllLines(args[3],args);
  File.WriteAllText(Path.Combine(root,"fixture-applied.txt"),args[0]);
  string code=Path.Combine(root,"fixture-exit-code.txt");
  return File.Exists(code) ? Int32.Parse(File.ReadAllText(code)) : 0;
 }
}
'@
Add-Type -TypeDefinition $fixture -OutputAssembly $package -OutputType ConsoleApplication
$dll=Join-Path $consumer 'load_fixture.dll'
$compiler=New-Object Microsoft.CSharp.CSharpCodeProvider
$parameters=New-Object CodeDom.Compiler.CompilerParameters
$parameters.GenerateExecutable=$false;$parameters.OutputAssembly=$dll;$parameters.CompilerOptions='/platform:x64'
try{$compiled=$compiler.CompileAssemblyFromSource($parameters,'public static class IsolatedVcLoadFixture { public static int Value() { return 1; } }');if($compiled.Errors.HasErrors){throw 'Could not build owned x64 DLL fixture.'}}finally{$compiler.Dispose()}
$context=Get-GdiagContext '' $casePath
$target=[pscustomobject]@{id='assistant';family='GstarAssistant';release='R27';path=$consumer;payloadRoot=$consumer}
$failure=@{id='failed-load';source='native_runtime';targetId=$target.id;status='probe_failed';observed=@{metadata=(Get-GdiagFileIdentity $dll);probe=@{nativeStages=@(@{stage='LoadLibraryEx';nativeErrorDomain='Win32';nativeErrorCode=126})}}}
$case=@{formatVersion=1;kind='local';caseId=$context.caseId;context=$context;targets=@($target);observations=@($failure)}
Write-GdiagJson (Join-Path $casePath 'case.json') $case
$publisher='CN=Microsoft Corporation, O=Microsoft Corporation, C=US';$packageHash=Get-GdiagFileHash $package
MustFail {Assert-GdiagVcPackage $package $packageHash $publisher '14.44.35211.0'} 'Unsigned fixture passed real Microsoft package trust'
MustFail {Assert-GdiagVcPackage $package ('0'*64) $publisher '14.44.35211.0'} 'Wrong package hash passed'
$script:beforeVersion='14.44.35211.0';$script:afterVersion='14.44.35211.0'
function Assert-GdiagVcPackage($Path,$Hash,$Publisher,$Version){
    if((Get-GdiagFileHash $Path) -ne $Hash -or $Publisher -ne 'CN=Microsoft Corporation, O=Microsoft Corporation, C=US' -or $Version -ne '14.44.35211.0'){throw 'Fixture trust mismatch'}
}
function Get-GdiagVcRuntimeState {
    $version=if(Test-Path -LiteralPath (Join-Path $root 'fixture-applied.txt')){$script:afterVersion}else{$script:beforeVersion}
    @{status=$(if($version){'observed'}else{'absent'});installed=[bool]$version;version=$version;observed=@{fixtureOnly=$true}}
}
function Assert-GdiagAutomationIdle {}
function Invoke-GdiagPrerequisiteInstaller($Plan,$LogPath){
    $arguments=@(('/'+$Plan.prerequisiteAction),'/norestart','/log',$LogPath)
    if($Plan.silent){$arguments+='/quiet'}
    Invoke-GdiagLifeProcess $Plan.packagePath $arguments $Plan.casePath 15
}
$options=@{recipe='vc-redist-x64';setupContract='microsoft-vc-v14-x64-v1';failureEvidenceId='failed-load';packagePath=$package;expectedPackageHash=$packageHash;expectedPublisher=$publisher;packageVersion='14.44.35211.0';prerequisiteAction='repair'}
$plan=New-GdiagPrerequisitePlan $context $target $options
Assert (-not(Test-Path -LiteralPath (Join-Path $root 'fixture-applied.txt'))) 'Planning launched the installer'
$original=Get-GdiagFileHash $dll
$result=Invoke-GdiagPrerequisitePlan $plan Apply $casePath
Assert ($result.status -eq 'applied' -and $result.runtimeVerification -eq 'observed') ('Native fixture repair failed: '+$result.error)
Assert ((Invoke-GdiagPrerequisitePlan $plan Verify $casePath).status -eq 'verified') 'Native prerequisite verification failed'
Assert ((Invoke-GdiagPrerequisitePlan $plan Undo $casePath).status -eq 'failed') 'Shared runtime incorrectly advertised Undo'
Assert ((Invoke-GdiagPrerequisitePlan $plan Apply $casePath).status -eq 'failed') 'Prior applied action replayed'
Assert ((Get-GdiagFileHash $dll) -eq $original) 'DLL verification changed consumer bytes'
# Registration current-state, package staleness and downgrade guard.
$stale=New-GdiagPrerequisitePlan $context $target $options
$script:afterVersion='14.45.0.0'
Assert ((Invoke-GdiagPrerequisitePlan $stale Apply $casePath).status -eq 'failed') 'Changed machine runtime accepted'
MustFail {New-GdiagPrerequisitePlan $context $target $options} 'Older package accepted for newer installed runtime'
$script:afterVersion='14.44.35211.0'
$tampered=New-GdiagPrerequisitePlan $context $target $options;$tampered.packageHash='0'*64
Assert ((Invoke-GdiagPrerequisitePlan $tampered Apply $casePath).status -eq 'failed') 'Tampered package accepted'
$badOptions=@{}+$options;$badOptions.failureEvidenceId='other-case'
MustFail {New-GdiagPrerequisitePlan $context $target $badOptions} 'Missing same-case failure evidence accepted'
$badOptions=@{}+$options;$badOptions.silent=$true
MustFail {New-GdiagPrerequisitePlan $context $target $badOptions} 'Silent operation accepted without agreement scope'
foreach($name in @('silent','agreementsAccepted')){
    foreach($value in @('false','true',0,1)){
        $badOptions=@{}+$options;$badOptions[$name]=$value
        MustFail {New-GdiagPrerequisitePlan $context $target $badOptions} 'Nonboolean prerequisite consent accepted during planning'
        $badPlan=New-GdiagPrerequisitePlan $context $target $options;$badPlan.$name=$value
        MustFail {Invoke-GdiagPrerequisitePlan $badPlan Apply $casePath} 'Nonboolean prerequisite consent reached the installer boundary'
    }
}
$falseOptions=@{}+$options;$falseOptions.silent=$false;$falseOptions.agreementsAccepted=$false
$interactive=New-GdiagPrerequisitePlan $context $target $falseOptions
Assert (-not $interactive.silent -and -not $interactive.agreementsAccepted) 'Explicit false consent became a silent install'
# Installer 3010 survives Verify and never becomes completed host recovery.
[IO.File]::WriteAllText((Join-Path $root 'fixture-exit-code.txt'),'3010')
$restart=New-GdiagPrerequisitePlan $context $target $options
$r=Invoke-GdiagPrerequisitePlan $restart Apply $casePath
Assert ($r.status -eq 'restart_required' -and $r.nativeExitCode -eq 3010 -and $r.runtimeVerification -eq 'pending_restart') '3010 reboot requirement lost'
Assert ((Invoke-GdiagPrerequisitePlan $restart Verify $casePath).status -eq 'restart_required') 'Verify erased original reboot requirement'
# Missing registration takes install, repair is refused; success without registration is not recovery.
Remove-Item -LiteralPath (Join-Path $root 'fixture-applied.txt')
$script:beforeVersion=$null
MustFail {New-GdiagPrerequisitePlan $context $target $options} 'Repair accepted absent runtime'
$installOptions=@{}+$options;$installOptions.prerequisiteAction='install';$installOptions.silent=$true;$installOptions.agreementsAccepted=$true
[IO.File]::WriteAllText((Join-Path $root 'fixture-exit-code.txt'),'0')
$install=New-GdiagPrerequisitePlan $context $target $installOptions
$r=Invoke-GdiagPrerequisitePlan $install Apply $casePath
Assert ($r.status -eq 'applied') ('Missing runtime fixture install failed: '+$r.error)
$script:afterVersion=$null
Assert ((Invoke-GdiagPrerequisitePlan $install Verify $casePath).status -eq 'failed') 'Missing post-install registration reported verified'
$script:afterVersion='14.44.35211.0'
$shared=New-GdiagPlan $context $target Repair $options
$planPath=Join-Path $casePath 'plan.json';Write-GdiagLifeJson $planPath $shared
Assert ((Invoke-GdiagPlan $planPath Apply).status -eq 'applied') 'Shared prerequisite Apply failed'
Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'verified') 'Shared prerequisite Verify failed'
Assert ((Invoke-GdiagPlan $planPath Undo).status -eq 'failed') 'Shared dispatcher allowed runtime Undo'
$journal=@(Get-Content -LiteralPath (Join-Path $casePath 'actions.jsonl') -Encoding UTF8 | ForEach-Object {$_ | ConvertFrom-Json})
Assert ($journal.Count -eq 6 -and @($journal | Where-Object status -eq 'started').Count -eq 3) 'Prerequisite handler duplicated or bypassed shared journaling'
[IO.File]::WriteAllText((Join-Path $root 'fixture-exit-code.txt'),'1603')
$failedInstall=New-GdiagPrerequisitePlan $context $target $options
$failedResult=Invoke-GdiagPrerequisitePlan $failedInstall Apply $casePath
Assert ($failedResult.status -eq 'failed' -and $failedResult.nativeExitCode -eq 1603) 'Failed installer native exit code was lost'
$failedState=Read-GdiagJson (Join-Path $casePath ($failedInstall.planId+'.state.json'))
Assert ($failedState.status -eq 'started' -and (Invoke-GdiagPrerequisitePlan $failedInstall Verify $casePath).status -eq 'failed') 'Failed installer became a completed action'
$public=ConvertTo-GdiagPublic $plan | ConvertTo-Json -Depth 30
Assert ($public -notmatch 'fixtureOnly|nativeStages') 'Private prerequisite details leaked'
Write-GdiagJson (Join-Path $root 'acceptance.json') @{status='passed-native-fixtures';machineInstallerExecuted=$false;trustAndRegistryMocked=$true;nativeDllProbe=$true;checks=@('same-case failure selection','exact installer arguments','source hash unchanged','install versus repair','version and current-state guards','no automatic Undo','3010 retained')}
'PASS prerequisite remedy: native owned installer and DLL probe, stale/version/trust/evidence guards and reboot outcome; actual Microsoft installer/UAC/registry acceptance remains pending. Artifacts: '+$root
