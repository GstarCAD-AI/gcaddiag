# Typed Microsoft VC++ x64 prerequisite remedy; Lifecycle.ps1 owns the action journal.
function Get-GdiagVcRuntimeState {
    $catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../catalog/products.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $policy=$catalog.prerequisites.visualCppX64
    $record=Get-GdiagRegistryRecord LocalMachine Registry64 ($policy.registrySubkey.Replace('/','\')) $null
    $result=@{status=$record.status;installed=$false;version=$null;observed=$record}
    if($record.status -eq 'absent'){return $result}
    if($record.status -ne 'observed'){throw 'VC++ machine registry is inaccessible; prerequisite current state is unresolved.'}
    $installed=@($record.values | Where-Object name -eq $policy.installedValue)
    if($installed.Count -ne 1 -or $installed[0].type -ne 'DWord'){throw 'VC++ Installed registry value is missing or has the wrong type.'}
    if($installed[0].raw -eq 0){return $result}
    if($installed[0].raw -ne 1){throw 'VC++ Installed registry value is invalid.'}
    $parts=@()
    foreach($name in @('Major','Minor','Bld','Rbld')){
        $entry=@($record.values | Where-Object name -eq $name)
        if($entry.Count -ne 1 -or $entry[0].type -ne 'DWord' -or [long]$entry[0].raw -lt 0){throw 'VC++ numeric version registry values are incomplete or invalid.'}
        $parts+=[string]$entry[0].raw
    }
    $version=[version]($parts -join '.')
    $text=@($record.values | Where-Object name -eq 'Version')
    if($text.Count -ne 1 -or $text[0].type -ne 'String' -or [version](([string]$text[0].raw).TrimStart('v','V')) -ne $version){throw 'VC++ string and numeric version registry values disagree.'}
    $result.installed=$true;$result.version=$version.ToString();$result
}
function Assert-GdiagVcPackage($Path,$Hash,$Publisher,$Version) {
    $path=Assert-GdiagPlainPath $Path
    if([IO.Path]::GetExtension($path) -ne '.exe' -or $Hash -notmatch '^[A-Fa-f0-9]{64}$' -or (Get-GdiagFileHash $path) -ne $Hash){throw 'VC++ package file or SHA256 changed.'}
    if($Publisher -notmatch '(^|,\s*)CN=Microsoft Corporation(,|$)'){throw 'Select the trusted Microsoft publisher certificate subject.'}
    $signature=Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
    if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -ne $Publisher){throw 'VC++ package signature/publisher is not verified.'}
    $metadata=[Diagnostics.FileVersionInfo]::GetVersionInfo($path)
    if($metadata.ProductName -notmatch '^Microsoft Visual C\+\+ .*Redistributable \(x64\)' -or $metadata.ProductVersion -ne $Version -or [version]$Version -lt [version]'14.0.0.0' -or ([version]$Version).Major -ne 14){throw 'Selected package is not the expected Microsoft v14 x64 Redistributable version.'}
}
function Get-GdiagVcFailureProbe($Case,$Target,$EvidenceId) {
    $evidence=@($Case.observations | Where-Object {$_.id -eq $EvidenceId -and $_.targetId -eq $Target.id -and $_.source -eq 'native_runtime' -and $_.status -eq 'probe_failed'})
    if($evidence.Count -ne 1){throw 'Select one same-case failed native DLL probe for this assistant target.'}
    $item=$evidence[0]
    $failures=@($item.observed.probe.nativeStages | Where-Object {$_.stage -eq 'LoadLibraryEx' -and $_.nativeErrorDomain -eq 'Win32' -and $_.nativeErrorCode -in @(126,1114,14001)})
    if($failures.Count -ne 1 -or $item.observed.metadata.architecture -ne 'x64'){throw 'This recipe requires a recorded x64 DLL load/dependency failure; architecture mismatch and later Python startup failures need different diagnosis.'}
    $root=$Target.payloadRoot;if(-not $root){$root=$Target.path}
    $root=Assert-GdiagPlainPath $root
    $dll=Assert-GdiagPlainPath $item.observed.metadata.path
    if(-not $dll.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($dll) -ne '.dll' -or -not(Test-Path -LiteralPath $dll -PathType Leaf)){throw 'Failed probe DLL must still exist inside the selected assistant payload.'}
    @{path=$dll;sha256=(Get-GdiagFileHash $dll);evidenceId=$EvidenceId;nativeErrorCode=$failures[0].nativeErrorCode}
}
function Assert-GdiagVcVersionAction($Current,$Version,$Action) {
    if($Action -notin @('install','repair')){throw 'Select prerequisiteAction install or repair.'}
    if($Current.installed -and [version]$Current.version -gt [version]$Version){throw 'A newer VC++ runtime is installed; select its matching trusted repair package, never downgrade.'}
    if($Action -eq 'repair' -and (-not $Current.installed -or [version]$Current.version -ne [version]$Version)){throw 'Repair requires the exact registered runtime version; install is the supported missing/older runtime operation.'}
}
function New-GdiagPrerequisitePlan {
    param($Context,$Target,[hashtable]$Options)
    if($Target.family -ne 'GstarAssistant' -or $Target.release -notin @('R26','R27') -or $Options.recipe -ne 'vc-redist-x64' -or $Options.setupContract -ne 'microsoft-vc-v14-x64-v1'){throw 'Select the reviewed assistant target and Microsoft v14 x64 prerequisite contract.'}
    if($Context.executorSid -ne $Context.affectedSid){throw 'Keep prerequisite planning in the affected user context.'}
    foreach($name in @('silent','agreementsAccepted')){if($Options.ContainsKey($name) -and $Options[$name] -isnot [bool]){throw "$name must be a JSON boolean."}}
    $case=Read-GdiagJson (Join-Path $Context.casePath 'case.json')
    $probe=Get-GdiagVcFailureProbe $case $Target $Options.failureEvidenceId
    $package=Assert-GdiagPlainPath $Options.packagePath
    Assert-GdiagVcPackage $package $Options.expectedPackageHash $Options.expectedPublisher $Options.packageVersion
    $current=Get-GdiagVcRuntimeState
    Assert-GdiagVcVersionAction $current $Options.packageVersion $Options.prerequisiteAction
    if($Options.silent -eq $true -and $Options.agreementsAccepted -ne $true){throw 'Silent prerequisite operation requires the existing user choice and applicable agreement acceptance.'}
    [pscustomobject]@{schemaVersion=1;planId=[guid]::NewGuid().ToString();caseId=$Context.caseId;casePath=$Context.casePath;machine=$Context.machine;executorSid=$Context.executorSid;affectedSid=$Context.affectedSid;
      target=$Target;destination=(Assert-GdiagPlainPath $Target.path);operation='Repair';recipe='vc-redist-x64';setupContract='microsoft-vc-v14-x64-v1';status='planned';createdUtc=[datetime]::UtcNow.ToString('o');
      packagePath=$package;packageHash=$Options.expectedPackageHash;publisher=$Options.expectedPublisher;packageVersion=$Options.packageVersion;prerequisiteAction=$Options.prerequisiteAction;
      silent=[bool]$Options.silent;agreementsAccepted=[bool]$Options.agreementsAccepted;registrationBefore=$current;registrationBeforeHash=(Get-GdiagRegistrationHash $current);probe=$probe;
      privilege='machine-runtime; only selected vendor installer may request UAC';processRequirement='Close the selected affected CAD/assistant normally; shared runtime may be used by other applications.';
      reversible=$false;restartRequired='installer_result';timeoutSeconds=300;
      verification='Reread typed HKLM64 runtime version and rerun the same isolated DLL-load probe; CAD recovery remains separate.';
      changes=@(@{action=$Options.prerequisiteAction;component='Microsoft VC++ v14 x64 shared runtime';installedVersion=$current.version;candidateVersion=$Options.packageVersion;scope='machine';source='Explicit trusted signed local package'});
      limits=@('Shared runtime affects other applications; no runtime uninstall or automatic rollback is supported.','A dependency load failure does not prove VC++ is its cause; preserve and compare the exact native result.','Only the vendor executable receives elevation. Case identity, logs and HKCU stay with the affected user.','No automatic restart. 3010 remains restart_required; registry presence alone is not runtime recovery.','Actual Microsoft installer acceptance on a disposable machine remains pending. No redistributable is bundled.')}
}
function Invoke-GdiagPrerequisiteInstaller($Plan,$LogPath) {
    $arguments=@(('/'+$Plan.prerequisiteAction),'/norestart','/log',('"'+$LogPath+'"'))
    if($Plan.silent){$arguments+='/quiet'}
    $process=$null
    try{
        # Elevate this exact validated vendor executable only, never a shell/helper script.
        $process=Start-Process -FilePath $Plan.packagePath -Verb RunAs -ArgumentList $arguments -WindowStyle Normal -PassThru -ErrorAction Stop
        $handle=$process.Handle
        if(-not $process.WaitForExit(300000)){return @{status='timeout';exitCode=$null;terminationGap='Elevated vendor installer may still be running; inspect it before recovery or another action.'}}
        @{status='completed';exitCode=$process.ExitCode;terminationGap=$null}
    }finally{if($process){$process.Dispose()}}
}
function Invoke-GdiagPrerequisitePlan {
    param($Plan,[ValidateSet('Apply','Verify','Undo')][string]$Mode,[string]$PlanDirectory)
    $p=$Plan;$directory=Assert-GdiagPlainPath $PlanDirectory
    if($p.recipe -ne 'vc-redist-x64' -or $p.operation -ne 'Repair' -or $p.setupContract -ne 'microsoft-vc-v14-x64-v1' -or $p.target.family -ne 'GstarAssistant' -or $p.target.release -notin @('R26','R27') -or $p.timeoutSeconds -ne 300){throw 'Invalid typed prerequisite plan.'}
    if($p.silent -isnot [bool] -or $p.agreementsAccepted -isnot [bool]){throw 'Prerequisite silent/agreement choices must be JSON booleans.'}
    if($p.silent -and -not $p.agreementsAccepted){throw 'Silent agreement choice missing.'}
    if($p.prerequisiteAction -notin @('install','repair')){throw 'Unsupported prerequisite operation.'}
    $case=Read-GdiagJson (Join-Path $directory 'case.json');$saved=@($case.targets | Where-Object {$_.id -eq $p.target.id -and $_.family -eq $p.target.family -and $_.path -eq $p.target.path -and $_.release -eq $p.target.release})
    if($saved.Count -ne 1 -or $saved[0].payloadRoot -ne $p.target.payloadRoot){throw 'Selected prerequisite consumer changed.'}
    $probe=Get-GdiagVcFailureProbe $case $saved[0] $p.probe.evidenceId
    if($probe.path -ne $p.probe.path -or $probe.sha256 -ne $p.probe.sha256){throw 'Failed DLL probe target changed; recollect before repair.'}
    $statePath=Assert-GdiagPlainPath (Join-Path $directory ($p.planId+'.state.json'));$logPath=Assert-GdiagPlainPath (Join-Path $directory ($p.planId+'.vc-redist.log'))
    $state=$null;if(Test-Path -LiteralPath $statePath){$state=Read-GdiagJson $statePath}
    $result=[ordered]@{planId=$p.planId;mode=$Mode;status='started';restartRequired=$false;hostVerification='pending';runtimeVerification='not_run'}
    try{
        if($Mode -eq 'Undo'){throw 'Shared VC++ prerequisite installation is not automatically reversible; use the selected vendor recovery workflow.'}
        if($Mode -eq 'Apply'){
            if($state){throw 'Prior prerequisite action exists; inspect its state instead of replaying.'}
            Assert-GdiagVcPackage $p.packagePath $p.packageHash $p.publisher $p.packageVersion
            $current=Get-GdiagVcRuntimeState
            if((Get-GdiagRegistrationHash $current) -ne $p.registrationBeforeHash){throw 'VC++ registration changed since planning.'}
            Assert-GdiagVcVersionAction $current $p.packageVersion $p.prerequisiteAction
            Assert-GdiagAutomationIdle $p.destination @('gcad','gstarcad','GstarAssistant','embedded_python')
            $hosts=@($case.targets | Where-Object {$_.family -eq 'GstarCAD' -and $_.release -eq $p.target.release})
            foreach($hostTarget in $hosts){Assert-GdiagAutomationIdle $hostTarget.path @('gcad','gstarcad')}
            Write-GdiagLifeJson (Join-Path $directory ($p.planId+'.registry-originals.json')) $current
            $state=[pscustomobject]@{planId=$p.planId;status='started';restartRequired=$false;nativeExitCode=$null;registrationAfter=$null;probeStatus='not_run'}
            Write-GdiagLifeJson $statePath $state
            $installed=Invoke-GdiagPrerequisiteInstaller $p $logPath
            $state.nativeExitCode=$installed.exitCode;$state.restartRequired=($installed.exitCode -in @(3010,1641));Write-GdiagLifeJson $statePath $state
            $result.nativeExitCode=$installed.exitCode;$result.restartRequired=$state.restartRequired;$result.installerLog=$logPath
            if($installed.status -ne 'completed' -or $installed.exitCode -notin @(0,3010)){throw "VC++ installer $($installed.status), exit $($installed.exitCode). $($installed.terminationGap) Inspect actual machine state before retrying."}
            $state.status='applied';Write-GdiagLifeJson $statePath $state
        }elseif(-not $state -or $state.status -ne 'applied' -or $state.planId -ne $p.planId){throw 'No completed prerequisite action exists to verify.'}
        $result.nativeExitCode=$state.nativeExitCode;$result.restartRequired=[bool]$state.restartRequired
        $after=Get-GdiagVcRuntimeState;$state.registrationAfter=$after
        if(-not $after.installed -or [version]$after.version -lt [version]$p.packageVersion){throw 'Installer completion did not establish the required typed VC++ runtime registration.'}
        $result.componentVerification='typed-runtime-registration-verified'
        if($state.restartRequired){$result.status='restart_required';$result.runtimeVerification='pending_restart';$result.nextAction='Complete the required restart normally, recollect state, and rerun the failed DLL probe. This receipt keeps the original reboot requirement.'}
        else{
            $tested=Invoke-GdiagNativeDllProbe -DllPath $probe.path -TimeoutSeconds 15
            $state.probeStatus=$tested.status;$result.runtimeVerification=$tested.status
            Write-GdiagLifeJson (Join-Path $directory ($p.planId+'.vc-runtime-probe.json')) $tested
            if($tested.status -ne 'observed'){throw 'VC++ registration is present but the selected DLL-load probe still fails; root cause and host recovery remain unresolved.'}
            $result.status=if($Mode -eq 'Apply'){'applied'}else{'verified'}
            $result.nextAction='The same isolated DLL-load probe passed; verify the original selected CAD symptom separately.'
        }
        Write-GdiagLifeJson $statePath $state
    }catch{$result.status='failed';$result.error=$_.Exception.Message;if($state){Write-GdiagLifeJson $statePath $state}}
    [pscustomobject]$result
}
