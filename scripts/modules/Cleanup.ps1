# Typed cleanup of a selected completed installer file. Lifecycle.ps1 supplies primitives.
function Read-GdiagCleanupJson($Path) {
    $resolved=Assert-GdiagPlainPath $Path
    if((Get-Item -LiteralPath $resolved -ErrorAction Stop).Length -gt 16777216){throw 'Cleanup evidence exceeds 16 MiB.'}
    Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 | ConvertFrom-Json
}
function Get-GdiagCleanupReceiptHash($Receipt) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try {([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Receipt -Depth 40 -Compress))))).Replace('-','')}
    finally {$sha.Dispose()}
}
function Assert-GdiagInstallerIdle([string]$ArtifactPath) {
    $artifact=[IO.Path]::GetFullPath($ArtifactPath)
    $name=[IO.Path]::GetFileNameWithoutExtension($artifact)
    foreach($running in Get-Process -ErrorAction Stop) {
        $image=$null
        try {$image=$running.Path} catch {
            if($running.ProcessName -eq $name){throw 'Cannot inspect a same-name running installer; selected artifact use is unverified.'}
        }
        if(-not $image -and $running.ProcessName -eq $name){throw 'Cannot resolve a same-name running installer; selected artifact use is unverified.'}
        if($image -and [IO.Path]::GetFullPath($image).Equals($artifact,[StringComparison]::OrdinalIgnoreCase)){throw 'Selected installer executable is running; close only that installer before cleanup.'}
    }
}
function Assert-GdiagInstallerReceipt($Receipt,$Context,$ArtifactPath,[bool]$CheckInstaller=$true) {
    if($Receipt.recipe -ne 'vendor-package' -or $Receipt.operation -notin @('Setup','Repair','Update') -or $Receipt.status -ne 'planned' -or $Receipt.schemaVersion -ne 1){throw 'A completed typed vendor package plan is required.'}
    if($Receipt.caseId -ne $Context.caseId -or [IO.Path]::GetFullPath($Receipt.casePath) -ne [IO.Path]::GetFullPath($Context.casePath) -or $Receipt.machine -ne $Context.machine -or $Receipt.executorSid -ne $Context.executorSid -or $Receipt.affectedSid -ne $Context.affectedSid){throw 'Installer receipt must belong to this local case, machine and affected user.'}
    if($Receipt.planId -notmatch '^[0-9a-fA-F-]{36}$'){throw 'Invalid receipt plan identity.'}
    $state=Read-GdiagCleanupJson (Join-Path $Context.casePath ($Receipt.planId+'.state.json'))
    if($state.planId -ne $Receipt.planId -or $state.status -ne 'applied' -or $state.restartRequired){throw 'Installer action must be completed and have no outstanding declared restart.'}
    $journal=Join-Path $Context.casePath 'actions.jsonl'
    if((Get-Item -LiteralPath (Assert-GdiagPlainPath $journal)).Length -gt 16777216){throw 'Action journal exceeds cleanup evidence bound.'}
    $completed=@(Get-Content -LiteralPath $journal -Encoding UTF8 | ForEach-Object {if($_.Trim()){$_ | ConvertFrom-Json}} | Where-Object {$_.planId -eq $Receipt.planId -and $_.mode -eq 'Apply' -and $_.status -eq 'applied'})
    if(-not $completed.Count){throw 'No completed installer action journal receipt exists.'}
    $artifact=Assert-GdiagPlainPath $ArtifactPath
    if($artifact -ne [IO.Path]::GetFullPath($Receipt.packagePath) -or [IO.Path]::GetExtension($artifact) -ne '.exe'){throw 'Only the exact completed vendor installer file may be selected.'}
    $case=Read-GdiagCleanupJson (Join-Path $Context.casePath 'case.json')
    foreach($target in @($case.targets)) {
        if($target.family -eq 'InstallerPackage'){continue}
        if($target.path){
            $root=[IO.Path]::GetFullPath($target.path).TrimEnd('\')
            if($artifact -eq $root -or $artifact.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Installer artifact overlaps an inventoried installation, skill or environment.'}
        }
    }
    $caseRoot=[IO.Path]::GetFullPath($Context.casePath).TrimEnd('\')
    if($artifact.StartsWith($caseRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Case originals and incident recovery material are not installer-cache cleanup.'}
    if($artifact -eq [IO.Path]::GetFullPath($Receipt.payloadManifestPath)){throw 'Recovery manifest cannot be cleaned as installer.'}
    if(-not(Test-GdiagVendorInstalled $Receipt)){throw 'Installed payload/registration is not verified; retain installer recovery material.'}
    if($CheckInstaller){Assert-GdiagVendorTrust $artifact $Receipt.packageHash $Receipt.publisher $Receipt.version}
    # An exclusive read handle detects use/locks; it is closed before the single rename.
    if($CheckInstaller){$lock=[IO.File]::Open($artifact,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);$lock.Dispose()}
    Assert-GdiagInstallerIdle $artifact
}
function New-GdiagCleanupPlan {
    param($Context,$Target,[hashtable]$Options)
    if($Options.recipe -ne 'installer-artifact' -or $Target.family -ne 'InstallerPackage'){throw 'Select one InstallerPackage target and installer-artifact recipe.'}
    if($Context.executorSid -ne $Context.affectedSid){throw 'Installer cleanup requires affected-user context.'}
    $artifact=Assert-GdiagPlainPath $Target.path
    if(-not(Test-Path -LiteralPath $artifact -PathType Leaf)){throw 'Selected installer file is absent.'}
    $receipt=Read-GdiagCleanupJson $Options.completedPlanPath
    Assert-GdiagInstallerReceipt $receipt $Context $artifact
    $id=[guid]::NewGuid().ToString()
    [pscustomobject]@{schemaVersion=1;planId=$id;caseId=$Context.caseId;casePath=$Context.casePath;machine=$Context.machine;executorSid=$Context.executorSid;affectedSid=$Context.affectedSid;
        target=$Target;operation='Cleanup';recipe='installer-artifact';createdUtc=[datetime]::UtcNow.ToString('o');status='planned';privilege='affected-user';processRequirement='Selected installer not running or locked';
        destination=$artifact;beforeHash=$receipt.packageHash;quarantine=$artifact+'.gcaddiag-quarantine-'+$id;receipt=$receipt;receiptHash=(Get-GdiagCleanupReceiptHash $receipt);
        reversible=$true;restartRequired=$false;verification='Exact installer file quarantined; installed payload and registration remain verified.';
        changes=@([pscustomobject]@{path=$artifact;action='quarantine-single-installer';bytes=(Get-Item -LiteralPath $artifact).Length;ownership=('Explicitly selected signed installer used by completed vendor action '+$receipt.planId);reason='Completed selected package input; installed files do not use this external installer';activeReferences='Not within any saved installation/skill/environment target; not running; exclusive read succeeds';reversal='Restore only unchanged quarantined file to an absent original path'});
        limits=@('One exact installer file only; extraction folders, unverified download caches and custom files are excluded.','Application host recovery and prerequisite reboot state remain separate from payload verification.','No permanent deletion, registry cleanup or vendor uninstall. Duplicate skill cleanup requires actual effective host discovery and remains guidance.')}
}
function Invoke-GdiagCleanupPlan {
    param($Plan,[ValidateSet('Apply','Verify','Undo')][string]$Mode,[string]$PlanDirectory)
    $p=$Plan;$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if($p.schemaVersion -ne 1 -or $p.recipe -ne 'installer-artifact' -or $p.operation -ne 'Cleanup' -or $p.status -ne 'planned' -or $p.target.family -ne 'InstallerPackage'){throw 'Invalid typed installer cleanup plan.'}
    if($p.planId -notmatch '^[0-9a-fA-F-]{36}$' -or $p.machine -ne [Environment]::MachineName -or $p.executorSid -ne $sid -or $p.affectedSid -ne $sid){throw 'Cleanup plan machine/user identity mismatch.'}
    $directory=Assert-GdiagPlainPath $PlanDirectory
    if($directory -ne [IO.Path]::GetFullPath($p.casePath)){throw 'Cleanup plan must stay in its original local case.'}
    $case=Read-GdiagCleanupJson (Join-Path $directory 'case.json')
    if($case.formatVersion -ne 1 -or $case.kind -ne 'local' -or $case.caseId -ne $p.caseId -or $case.context.machine -ne $p.machine -or $case.context.executorSid -ne $sid -or $case.context.affectedSid -ne $sid){throw 'Cleanup requires canonical local case identity.'}
    $saved=@($case.targets|Where-Object id -eq $p.target.id)
    $path=Assert-GdiagPlainPath $p.destination
    if($saved.Count -ne 1 -or $saved[0].family -ne 'InstallerPackage' -or $saved[0].path -ne $path -or $p.target.path -ne $path){throw 'Cleanup target does not match saved case selection.'}
    $quarantine=Assert-GdiagPlainPath $p.quarantine
    if($quarantine -ne $path+'.gcaddiag-quarantine-'+$p.planId){throw 'Cleanup quarantine must be the exact same-parent owned path.'}
    if((Get-GdiagCleanupReceiptHash $p.receipt) -ne $p.receiptHash -or $p.beforeHash -ne $p.receipt.packageHash){throw 'Cleanup receipt changed.'}
    $context=@{casePath=$directory;caseId=$p.caseId;machine=$p.machine;executorSid=$sid;affectedSid=$sid}
    $statePath=Join-Path $directory ($p.planId+'.state.json');$journal=Join-Path $directory 'actions.jsonl'
    $state=$null;if(Test-Path -LiteralPath $statePath){$state=Read-GdiagCleanupJson $statePath}
    $result=[ordered]@{planId=$p.planId;mode=$Mode;status='started';timeUtc=[datetime]::UtcNow.ToString('o');restartRequired=$false;hostVerification='pending';changes=@()}
    try {
        if($Mode -eq 'Apply') {
            if($state){throw 'Prior action exists; inspect state before replanning.'}
            Assert-GdiagInstallerReceipt $p.receipt $context $path
            if((Get-GdiagFileHash $path) -ne $p.beforeHash -or (Test-Path -LiteralPath $quarantine)){throw 'Installer cleanup precondition changed.'}
            $state=[pscustomobject]@{planId=$p.planId;status='started';originalPath=$path;quarantine=$quarantine;hash=$p.beforeHash}
            Write-GdiagLifeJson $statePath $state
            Move-Item -LiteralPath $path -Destination $quarantine -ErrorAction Stop
            $state.status='applied';Write-GdiagLifeJson $statePath $state;$result.status='applied'
        } elseif($Mode -eq 'Verify') {
            if(-not $state -or $state.status -ne 'applied' -or (Test-Path -LiteralPath $path) -or (Get-GdiagFileHash $quarantine) -ne $p.beforeHash){throw 'Selected artifact quarantine is not verified.'}
            Assert-GdiagInstallerIdle $quarantine
            Assert-GdiagInstallerReceipt $p.receipt $context $path $false
            $result.status='verified';$result.componentVerification='installer-quarantined-installed-payload-and-registration-verified'
        } else {
            if(-not $state -or $state.status -ne 'applied' -or $state.planId -ne $p.planId -or $state.originalPath -ne $path -or $state.quarantine -ne $quarantine -or $state.hash -ne $p.beforeHash){throw 'Cleanup action state is not a completed matching action.'}
            if((Test-Path -LiteralPath $path) -or (Get-GdiagFileHash $quarantine) -ne $p.beforeHash){throw 'Undo preserves intervening edits/new original files.'}
            Assert-GdiagInstallerIdle $quarantine
            Move-Item -LiteralPath $quarantine -Destination $path -ErrorAction Stop
            $state.status='undone';Write-GdiagLifeJson $statePath $state;$result.status='undone'
        }
    } catch {$result.status='failed';$result.error=$_.Exception.Message}
    [pscustomobject]$result
}
