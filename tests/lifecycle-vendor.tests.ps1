# Structural handler test only: unsigned fixture + registry reads are mocked, never product acceptance.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path $PSScriptRoot ('.tmp-vendor-'+[guid]::NewGuid().ToString())
$casePath=Join-Path $root 'case';$payload=Join-Path $root 'payload';$hostRoot=Join-Path $root 'CAD host'
New-Item -ItemType Directory -Force -Path $casePath,$payload,$hostRoot|Out-Null
$code=@'
using System;
using System.IO;
public static class FixtureInstaller {
  public static int Main(string[] args) {
    string dest=null,log=null;
    foreach(string arg in args) {
      if(arg.StartsWith("/INSTALLDIR=")) dest=arg.Substring(12);
      else if(arg.StartsWith("/LOGFILE=")) log=arg.Substring(9);
      else if(arg!="/S" && arg!="/REPAIR" && arg!="/TARGET=2026" && !arg.StartsWith("/TARGETPATH=")) return 91;
    }
    if(dest==null || log==null) return 92;
    string source=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"payload");
    foreach(string file in Directory.GetFiles(source,"*",SearchOption.AllDirectories)) {
      string target=Path.Combine(dest,file.Substring(source.Length+1));
      Directory.CreateDirectory(Path.GetDirectoryName(target)); File.Copy(file,target,true);
    }
    File.Copy(System.Reflection.Assembly.GetExecutingAssembly().Location,Path.Combine(dest,"uninstall.exe"),true);
    // Model the source installer's separate generated icon, outside its payload manifest.
    File.Copy(Path.Combine(source,"modules","GstarAssistant_impl.dll"),Path.Combine(dest,"app_icon.ico"),true);
    File.WriteAllLines(log,args);
    return dest.Contains("restart") ? 3010 : 0;
  }
}
'@
$package=Join-Path $root 'setup-fixture.exe'
Add-Type -TypeDefinition $code -OutputAssembly $package -OutputType ConsoleApplication
Copy-Item -LiteralPath $package -Destination (Join-Path $hostRoot 'gcad.exe')
$catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../catalog/products.json') -Raw -Encoding UTF8|ConvertFrom-Json
$files=[ordered]@{}
foreach($relative in $catalog.assistantPayload){
    if($relative -eq 'payload-manifest.json'){continue}
    $relative=$relative.Replace('{year}','2026')
    $path=Join-Path $payload $relative;New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path)|Out-Null
    Set-Content -LiteralPath $path -Value ('fixture '+$relative) -Encoding UTF8
    $files[$relative]=Get-GdiagFileHash $path
}
$manifestPath=Join-Path $payload 'payload-manifest.json'
Write-GdiagLifeJson $manifestPath @{schema_version=2;product='GstarAssistant';layout='gstarassistant-v1';target_year='2026';version='1.0.0';files=$files}
foreach($unsafeName in @('../escaped.dll','modules\GstarAssistant.grx','NUL.txt')){
    $unsafeFiles=[ordered]@{};foreach($name in $files.Keys){$unsafeFiles[$name]=$files[$name]};$unsafeFiles[$unsafeName]=('A'*64)
    $unsafePath=Join-Path $root 'unsafe-manifest.json'
    Write-GdiagLifeJson $unsafePath @{schema_version=2;product='GstarAssistant';layout='gstarassistant-v1';target_year='2026';version='1.0.0';files=$unsafeFiles}
    $unsafeRefused=$false;try{Get-GdiagVendorManifest $unsafePath (Get-GdiagFileHash $unsafePath) 'R26'|Out-Null}catch{$unsafeRefused=$true}
    Assert $unsafeRefused ('Unsafe Windows manifest identity accepted: '+$unsafeName)
}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$ctx=@{caseId='case-vendor-fixture';casePath=$casePath;machine=[Environment]::MachineName;executorSid=$sid;affectedSid=$sid}
$hostTarget=[pscustomobject]@{id='host-1';family='GstarCAD';path=$hostRoot;release='R26';locale='CHS'}
$target=[pscustomobject]@{id='assistant-1';family='GstarAssistant';path=(Join-Path $root 'assistant install');release='R26'}
$script:fixtureDestination=$target.path
Write-GdiagLifeJson (Join-Path $casePath 'case.json') @{formatVersion=1;caseId=$ctx.caseId;context=$ctx;targets=@($hostTarget,$target)}
# Capture actual trust function before overriding it: unsigned executable must fail normally.
$trustRefused=$false
try{Assert-GdiagVendorTrust $package (Get-GdiagFileHash $package) 'CN=Fixture' '1.0.0'}catch{$trustRefused=$true}
Assert $trustRefused 'Unsigned installer was accepted'
function Assert-GdiagVendorTrust($Path,$Hash,$Publisher,$Version){if((Get-GdiagFileHash $Path) -ne $Hash){throw 'Fixture package changed'}}
function Get-GdiagVendorRegistration($Release,$Locale){
    $present=Test-Path -LiteralPath (Join-Path $script:fixtureDestination 'payload-manifest.json')
    $version=if($present){(Get-Content -LiteralPath (Join-Path $script:fixtureDestination 'payload-manifest.json') -Raw -Encoding UTF8|ConvertFrom-Json).version}else{''}
    $startupKey="Software\Gstarsoft\GstarCAD\$Release\$Locale\Applications\GstarAssistant"
    $loader=Join-Path $script:fixtureDestination 'modules/GstarAssistant.grx'
    # Fixture records follow the generator's actual writes; no registry mutation occurs.
    $entries=@(
        @{key="Software\Gstarsoft\GstarAssistant\$Release";values=@{
            InstallDir=$script:fixtureDestination;InstallLocation=$script:fixtureDestination;DisplayVersion=$version;
            TargetYear=('20'+$Release.Substring(1));Release=$Release;GrxPath=$loader;RuntimeGrxPath=$loader;
            SkillsPath=(Join-Path $script:fixtureDestination 'skills');GcadLocale=$Locale;GcadProductRelease=$Release;GcadStartupKey=$startupKey}},
        @{key="Software\Microsoft\Windows\CurrentVersion\Uninstall\GstarAssistant $Release";values=@{
            InstallLocation=$script:fixtureDestination;DisplayVersion=$version;UninstallString=('"'+(Join-Path $script:fixtureDestination 'uninstall.exe')+'"');NoModify=1;NoRepair=1}},
        @{key=$startupKey;values=@{DESCRIPTION='Gstar Assistant';LOADER=$loader;LOADCTRLS=2}}
    )
    foreach($entry in $entries){
        $values=@(if($present){foreach($name in $entry.values.Keys){[pscustomobject]@{name=$name;kind=$(if($entry.values[$name] -is [int]){'DWord'}else{'String'});value=$entry.values[$name]}}})
        $record=[pscustomobject]@{hive='HKCU';view='Registry64';key=$entry.key;exists=$present;values=$values}
        if($script:registrationFault -and $record.key -eq $script:registrationFault.key){
            if($script:registrationFault.absent){$record.exists=$false}
            elseif($script:registrationFault.view){$record.view=$script:registrationFault.view}
            else{
                $value=@($record.values|Where-Object name -eq $script:registrationFault.name)[0]
                if($script:registrationFault.kind){$value.kind=$script:registrationFault.kind}else{$value.value=$script:registrationFault.value}
            }
        }
        $record
    }
}
$options=@{recipe='vendor-package';setupContract='gstarassistant-nsis-v1';packageRelease='R26';hostTargetId=$hostTarget.id;expectedHostHash=(Get-GdiagFileHash (Join-Path $hostRoot 'gcad.exe'));packagePath=$package;expectedPackageHash=(Get-GdiagFileHash $package);expectedPublisher='CN=Fixture';payloadManifestPath=$manifestPath;payloadManifestHash=(Get-GdiagFileHash $manifestPath);silent=$true;agreementsAccepted=$true}
$plan=New-GdiagPlan $ctx $target Setup $options
Assert (-not(Test-Path -LiteralPath $target.path)) 'Vendor Plan changed target'
$planPath=Join-Path $casePath 'plan.json';Write-GdiagLifeJson $planPath $plan
foreach($name in @('silent','agreementsAccepted')){
    $badOptions=@{}+$options;$badOptions[$name]='false'
    $refused=$false;try{New-GdiagPlan $ctx $target Setup $badOptions | Out-Null}catch{$refused=$true}
    Assert $refused 'Vendor planner accepted string consent'
    $badPlan=$plan | ConvertTo-Json -Depth 24 | ConvertFrom-Json;$badPlan.$name='false'
    $badPath=Join-Path $casePath 'invalid-consent.json';Write-GdiagLifeJson $badPath $badPlan
    $refused=$false;try{Invoke-GdiagPlan $badPath Apply | Out-Null}catch{$refused=$true}
    Assert $refused 'Vendor invocation accepted string consent'
}
Assert (-not(Test-Path -LiteralPath $target.path)) 'Invalid vendor consent invoked the installer'
$result=Invoke-GdiagPlan $planPath Apply
Assert ($result.status -eq 'applied' -and $result.nativeExitCode -eq 0) "Vendor fixture setup failed: $($result.error)"
Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'verified') 'Complete manifest/registry fixture verification failed'
# A vendor install can leave payload intact while registration is partial/stale.
$installKey='Software\Gstarsoft\GstarAssistant\R26'
$uninstallKey='Software\Microsoft\Windows\CurrentVersion\Uninstall\GstarAssistant R26'
$startupKey='Software\Gstarsoft\GstarCAD\R26\CHS\Applications\GstarAssistant'
foreach($fault in @(
    @{key=$uninstallKey;absent=$true},
    @{key=$uninstallKey;name='UninstallString';value='"C:\unrelated\uninstall.exe"'},
    @{key=$installKey;name='DisplayVersion';value='0.0.0-stale'},
    @{key=$installKey;name='GcadProductRelease';value='R27'},
    @{key=$installKey;name='GcadLocale';value='en-US'},
    @{key=$installKey;name='GcadStartupKey';value='Software\unrelated'},
    @{key=$startupKey;name='LOADCTRLS';kind='String'},
    @{key=$startupKey;view='Registry32'}
)){
    $script:registrationFault=$fault
    Assert (-not (Test-GdiagVendorInstalled $plan)) 'Partial/stale registration passed complete installation verification'
}
$script:registrationFault=$null
Assert (Test-GdiagVendorInstalled $plan) 'Correct source-derived registration failed after fault removal'
Assert ((Invoke-GdiagPlan $planPath Undo).status -eq 'failed') 'Unsupported vendor rollback was accepted'
$installerLog=Get-Content -LiteralPath $result.installerLog
Assert ($installerLog -contains '/TARGET=2026') 'Typed target argument was merged/incorrect'
Assert ($installerLog -contains ('/TARGETPATH='+$hostRoot)) 'Selected spaced host path was misquoted'
Assert ($installerLog -contains ('/INSTALLDIR='+$target.path)) 'Selected spaced destination was misquoted'
Set-Content -LiteralPath (Join-Path $target.path 'custom.dwg') -Value 'preserve user file'
Remove-Item -LiteralPath (Join-Path $target.path 'modules/GstarAssistant.grx')
$plan=New-GdiagPlan $ctx $target Repair $options;Write-GdiagLifeJson $planPath $plan
$result=Invoke-GdiagPlan $planPath Apply
Assert ($result.status -eq 'applied') "Vendor fixture repair failed: $($result.error)"
Assert ((Get-Content -LiteralPath (Join-Path $target.path 'custom.dwg')) -eq 'preserve user file') 'Vendor repair lost custom drawing'
Assert ((Get-Content -LiteralPath $result.installerLog) -contains '/REPAIR') 'Repair omitted supported wrapper flag'
# Backup-time changes must stop before the installer can overwrite newer user state.
$script:savedLifeProcess=${function:Invoke-GdiagLifeProcess}
$originalConfig=Join-Path $target.path 'configs/runtime/assistant.json'
$originalConfigHash=Get-GdiagFileHash $originalConfig
foreach($faultKind in @('backup-bytes','live-file','registration')){
    $guardPlan=New-GdiagPlan $ctx $target Repair $options
    Write-GdiagLifeJson $planPath $guardPlan
    $script:backupFaultKind=$faultKind;$script:installerCalls=0
    $script:backupFaultDestination=Join-Path $casePath ($guardPlan.planId+'.originals/configs/runtime/assistant.json')
    function Invoke-GdiagLifeProcess($Executable,[string[]]$Arguments,$CasePath,[int]$TimeoutSeconds,[bool]$Interactive=$false){
        $script:installerCalls++
        & $script:savedLifeProcess $Executable $Arguments $CasePath $TimeoutSeconds $Interactive
    }
    function Copy-Item {
        [CmdletBinding()]param([string]$LiteralPath,[string]$Destination)
        Microsoft.PowerShell.Management\Copy-Item @PSBoundParameters
        if([IO.Path]::GetFullPath($Destination) -eq [IO.Path]::GetFullPath($script:backupFaultDestination)){
            if($script:backupFaultKind -eq 'backup-bytes'){[IO.File]::WriteAllText($Destination,'simulated corrupt original copy')}
            elseif($script:backupFaultKind -eq 'live-file'){[IO.File]::WriteAllText($LiteralPath,'intervening user provider setting')}
            else{$script:registrationFault=@{key='Software\Gstarsoft\GstarCAD\R26\CHS\Applications\GstarAssistant';name='LOADER';value='C:\new-user-selected-loader.grx'}}
        }
    }
    try{
        $guardResult=Invoke-GdiagPlan $planPath Apply
        Assert ($guardResult.status -eq 'failed' -and $script:installerCalls -eq 0) ('Backup-time change reached vendor execution: '+$faultKind)
        if($faultKind -eq 'live-file'){
            Assert ([IO.File]::ReadAllText($originalConfig) -eq 'intervening user provider setting') 'Backup-time user edit was overwritten'
        }else{Assert ((Get-GdiagFileHash $originalConfig) -eq $originalConfigHash) 'Failed backup check changed product configuration'}
    }finally{
        Remove-Item Function:\Copy-Item
        Set-Item Function:\Invoke-GdiagLifeProcess -Value $script:savedLifeProcess
        $script:registrationFault=$null
        Microsoft.PowerShell.Management\Copy-Item -LiteralPath (Join-Path $payload 'configs/runtime/assistant.json') -Destination $originalConfig
    }
}
$changedRelative='modules/GstarAssistant_impl.dll'
Set-Content -LiteralPath (Join-Path $payload $changedRelative) -Value 'fixture coherent next release payload' -Encoding UTF8
$files[$changedRelative]=Get-GdiagFileHash (Join-Path $payload $changedRelative)
Write-GdiagLifeJson $manifestPath @{schema_version=2;product='GstarAssistant';layout='gstarassistant-v1';target_year='2026';version='1.1.0';files=$files}
$options.payloadManifestHash=Get-GdiagFileHash $manifestPath
$previousIconHash=Get-GdiagFileHash (Join-Path $target.path 'app_icon.ico')
$plan=New-GdiagPlan $ctx $target Update $options
Assert ($plan.changes[0].generatedFiles -contains 'app_icon.ico') 'Vendor plan omitted the generated icon side effect'
# Preview arrays cannot remove files/values from the actual recovery originals.
$plan.beforeTree=@();$plan.registrationBefore=@();Write-GdiagLifeJson $planPath $plan
$result=Invoke-GdiagPlan $planPath Apply
Assert ($result.status -eq 'applied') "Vendor fixture update failed: $($result.error)"
Assert ((Get-GdiagFileHash (Join-Path $target.path 'app_icon.ico')) -ne $previousIconHash) 'Fixture did not exercise a changed generated icon'
$updatedState=Get-Content -LiteralPath (Join-Path $casePath ($plan.planId+'.state.json')) -Raw -Encoding UTF8 | ConvertFrom-Json
$iconOriginal=@($updatedState.originals | Where-Object path -eq (Join-Path $target.path 'app_icon.ico'))
Assert ($iconOriginal.Count -eq 1 -and (Get-GdiagFileHash $iconOriginal[0].backup) -eq $previousIconHash) 'Generated icon original was not preserved'
$customOriginal=@($updatedState.originals | Where-Object path -eq (Join-Path $target.path 'custom.dwg'))
Assert ($customOriginal.Count -eq 1 -and (Get-GdiagFileHash $customOriginal[0].backup) -eq (Get-GdiagFileHash $customOriginal[0].path)) 'Edited preview omitted a custom-file original'
$registryOriginals=Get-Content -LiteralPath (Join-Path $casePath ($plan.planId+'.registry-originals.json')) -Raw -Encoding UTF8 | ConvertFrom-Json
Assert (@($registryOriginals).Count -eq 3 -and @($registryOriginals[0].values).Count -gt 0) 'Edited preview omitted typed registry originals'
Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'verified') 'Coherent updated manifest verification failed'
Assert ((Get-Content -LiteralPath (Join-Path $target.path 'custom.dwg')) -eq 'preserve user file') 'Vendor update lost custom file'
$config=Join-Path $target.path 'configs/runtime/assistant.json'
Set-Content -LiteralPath $config -Value 'custom provider setting'
$editedConfigRefused=$false
try{New-GdiagPlan $ctx $target Update $options|Out-Null}catch{$editedConfigRefused=$true}
Assert $editedConfigRefused 'Vendor update would overwrite custom configuration'
Copy-Item -LiteralPath (Join-Path $payload 'configs/runtime/assistant.json') -Destination $config
# Same native fixture returns actual 3010 for another isolated intended target.
$restartTarget=[pscustomobject]@{id='assistant-restart';family='GstarAssistant';path=(Join-Path $root 'restart assistant');release='R26'}
$script:fixtureDestination=$restartTarget.path
Write-GdiagLifeJson (Join-Path $casePath 'case.json') @{formatVersion=1;caseId=$ctx.caseId;context=$ctx;targets=@($hostTarget,$target,$restartTarget)}
$plan=New-GdiagPlan $ctx $restartTarget Setup $options;Write-GdiagLifeJson $planPath $plan
$result=Invoke-GdiagPlan $planPath Apply
Assert ($result.status -eq 'restart_required' -and $result.nativeExitCode -eq 3010) "Native restart status lost: $($result.error)"
Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'restart_required') 'Verification incorrectly cleared restart requirement'
Write-Output ('Vendor handler native fixture passed; trust/registry mocked; real product acceptance pending: '+$root)
