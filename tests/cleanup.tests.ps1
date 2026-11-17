# Signature/payload boundary is mocked for isolated fixture receipts, not vendor acceptance.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Cleanup.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
function MustFail([scriptblock]$Block,$Message){$failed=$false;try{& $Block|Out-Null}catch{$failed=$true};Assert $failed $Message}
$root=Join-Path $PSScriptRoot ('.tmp-cleanup-'+[guid]::NewGuid())
$casePath=Join-Path $root 'case';$download=Join-Path $root 'selected downloads';$installation=Join-Path $root 'installed';$other=Join-Path $root 'other release'
New-Item -ItemType Directory -Path $casePath,$download,$installation,$other -Force|Out-Null
$ownedImage=Join-Path $root ('owned-installer-'+[guid]::NewGuid().ToString('N')+'.exe')
Add-Type -TypeDefinition 'public static class OwnedInstallerIdleFixture { public static void Main() { System.Threading.Thread.Sleep(30000); } }' -OutputType ConsoleApplication -OutputAssembly $ownedImage
$owned=Start-Process -FilePath $ownedImage -WindowStyle Hidden -PassThru
$null=$owned.Handle
try {
    MustFail {Assert-GdiagInstallerIdle $ownedImage} 'Exact running installer executable was treated as idle'
    Assert-GdiagInstallerIdle (Join-Path $other ([IO.Path]::GetFileName($ownedImage)))
    Assert (-not $owned.HasExited) 'Idle inspection terminated an owned process'
} finally {if(-not $owned.HasExited){$owned.Kill();[void]$owned.WaitForExit(1000)};$owned.Dispose()}
# A relevant inaccessible image is a collection gap, not evidence that the selected file is idle.
$script:inaccessibleImage=[pscustomobject]@{ProcessName='inaccessible-installer'}
$script:inaccessibleImage|Add-Member -MemberType ScriptProperty -Name Path -Value {throw [UnauthorizedAccessException]::new('fixture access denied')}
function Get-Process {param($ErrorAction) $script:inaccessibleImage}
try {MustFail {Assert-GdiagInstallerIdle (Join-Path $download 'inaccessible-installer.exe')} 'Inaccessible same-name installer was treated as idle'}
finally {Remove-Item Function:\Get-Process}
$installer=Join-Path $download 'selected vendor package.exe';Set-Content -LiteralPath $installer -Value 'isolated executable fixture' -Encoding UTF8
$drawing=Join-Path $download 'customer.dwg';Set-Content -LiteralPath $drawing -Value 'preserve customer drawing' -Encoding UTF8
$otherFile=Join-Path $other 'plugin.grx';Set-Content -LiteralPath $otherFile -Value 'other installation' -Encoding UTF8
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$context=@{casePath=$casePath;caseId='cleanup-fixture';machine=[Environment]::MachineName;executorSid=$sid;affectedSid=$sid}
$target=[pscustomobject]@{id='package-1';family='InstallerPackage';path=$installer}
Write-GdiagLifeJson (Join-Path $casePath 'case.json') @{formatVersion=1;kind='local';caseId=$context.caseId;context=$context;targets=@($target,@{id='assistant-1';family='GstarAssistant';path=$installation},@{id='cad26';family='GstarCAD';path=$other})}
$vendorId=[guid]::NewGuid().ToString()
$receipt=[pscustomobject]@{schemaVersion=1;planId=$vendorId;caseId=$context.caseId;casePath=$casePath;machine=$context.machine;executorSid=$sid;affectedSid=$sid;recipe='vendor-package';operation='Setup';status='planned';packagePath=$installer;packageHash=(Get-GdiagFileHash $installer);publisher='fixture publisher';version='1';destination=$installation;payloadManifestPath=(Join-Path $root 'manifest.json')}
$receiptPath=Join-Path $casePath 'completed-plan.json';Write-GdiagLifeJson $receiptPath $receipt
Write-GdiagLifeJson (Join-Path $casePath ($vendorId+'.state.json')) @{planId=$vendorId;status='applied';restartRequired=$false}
@{planId=$vendorId;mode='Apply';status='applied'}|ConvertTo-Json -Compress|Set-Content -LiteralPath (Join-Path $casePath 'actions.jsonl') -Encoding UTF8
$originalTrust=(Get-Command Assert-GdiagVendorTrust).ScriptBlock
MustFail {Assert-GdiagVendorTrust $installer $receipt.packageHash $receipt.publisher $receipt.version} 'Unsigned fixture accepted by real signature boundary'
function Assert-GdiagVendorTrust($Path,$Hash,$Publisher,$Version){if((Get-GdiagFileHash $Path) -ne $Hash){throw 'Fixture package changed'}}
function Test-GdiagVendorInstalled($Plan){(Test-Path -LiteralPath $Plan.destination -PathType Container)}
function NewFixturePlan {New-GdiagCleanupPlan $context $target @{recipe='installer-artifact';completedPlanPath=$receiptPath}}
$plan=NewFixturePlan
Write-GdiagLifeJson (Join-Path $casePath 'cleanup-plan.json') $plan
$plan=Read-GdiagCleanupJson (Join-Path $casePath 'cleanup-plan.json')
Assert (Test-Path -LiteralPath $installer) 'Planning moved installer'
Assert ($plan.changes[0].bytes -gt 0 -and $plan.changes[0].ownership) 'Cleanup preview omitted size/ownership'
Assert ((Invoke-GdiagCleanupPlan $plan Apply $casePath).status -eq 'applied') 'Installer quarantine failed'
Assert (-not(Test-Path -LiteralPath $installer) -and (Test-Path -LiteralPath $plan.quarantine)) 'Wrong quarantine state'
Assert ((Invoke-GdiagCleanupPlan $plan Verify $casePath).status -eq 'verified') 'Quarantine verification failed'
Set-Content -LiteralPath $installer -Value 'intervening user file' -Encoding UTF8
Assert ((Invoke-GdiagCleanupPlan $plan Undo $casePath).status -eq 'failed') 'Undo overwrote intervening original'
Remove-Item -LiteralPath $installer
Set-Content -LiteralPath $plan.quarantine -Value 'intervening quarantine edit' -Encoding UTF8
Assert ((Invoke-GdiagCleanupPlan $plan Undo $casePath).status -eq 'failed') 'Undo restored changed quarantined file'
Set-Content -LiteralPath $plan.quarantine -Value 'isolated executable fixture' -Encoding UTF8
Assert ((Invoke-GdiagCleanupPlan $plan Undo $casePath).status -eq 'undone') 'Supported unchanged undo failed'
Assert ((Get-Content -LiteralPath $drawing -Raw).Contains('preserve customer')) 'Custom drawing changed'
Assert ((Get-Content -LiteralPath $otherFile -Raw).Contains('other installation')) 'Other installation changed'
$sharedPlan=New-GdiagPlan -Context $context -Target $target -Operation Cleanup -Options @{recipe='installer-artifact';completedPlanPath=$receiptPath}
$sharedPath=Join-Path $casePath 'shared-cleanup-plan.json';Write-GdiagLifeJson $sharedPath $sharedPlan
foreach($mode in @('Apply','Verify','Undo')) {
    $sharedResult=Invoke-GdiagPlan -PlanPath $sharedPath -Mode $mode
    Assert ($sharedResult.status -in @('applied','verified','undone')) "Shared cleanup dispatch failed: $mode $($sharedResult.error)"
}
$sharedReceipts=@(Get-Content -LiteralPath (Join-Path $casePath 'actions.jsonl') | ForEach-Object {$_ | ConvertFrom-Json} | Where-Object planId -eq $sharedPlan.planId)
Assert ($sharedReceipts.Count -eq 6) 'Shared executor did not retain sole ownership of started/completed cleanup journaling'
$stale=NewFixturePlan;Set-Content -LiteralPath $installer -Value 'changed package' -Encoding UTF8
Assert ((Invoke-GdiagCleanupPlan $stale Apply $casePath).status -eq 'failed') 'Stale installer source accepted'
Set-Content -LiteralPath $installer -Value 'isolated executable fixture' -Encoding UTF8
$tampered=NewFixturePlan;$tampered.quarantine=Join-Path $root 'escape.exe'
MustFail {Invoke-GdiagCleanupPlan $tampered Apply $casePath} 'Noncanonical quarantine accepted'
$receipt.packagePath=$drawing;Write-GdiagLifeJson $receiptPath $receipt
MustFail {NewFixturePlan} 'Drawing accepted as installer cleanup'
$receipt.packagePath=$installer;Write-GdiagLifeJson $receiptPath $receipt
Write-GdiagLifeJson (Join-Path $casePath ($vendorId+'.state.json')) @{planId=$vendorId;status='applied';restartRequired=$true}
MustFail {NewFixturePlan} 'Outstanding declared reboot ignored'
Write-GdiagLifeJson (Join-Path $casePath ($vendorId+'.state.json')) @{planId=$vendorId;status='applied';restartRequired=$false}
$unproved=$receipt|ConvertTo-Json -Depth 20|ConvertFrom-Json;$unproved.planId=[guid]::NewGuid().ToString();Write-GdiagLifeJson $receiptPath $unproved
MustFail {NewFixturePlan} 'Missing completed action accepted'
Write-GdiagLifeJson $receiptPath $receipt
$junction=Join-Path $root 'download link'
try {
    New-Item -ItemType Junction -Path $junction -Target $download -ErrorAction Stop|Out-Null
    $linked=[pscustomobject]@{id='package-1';family='InstallerPackage';path=(Join-Path $junction 'selected vendor package.exe')}
    MustFail {New-GdiagCleanupPlan $context $linked @{recipe='installer-artifact';completedPlanPath=$receiptPath}} 'Junction cleanup boundary accepted'
}catch{if($_.Exception.Message -match 'Junction cleanup boundary'){throw};'PENDING junction creation denied; plain path/refusal cases completed'}
'PASS cleanup: exact completed installer receipt, native quarantine/verify/undo, edit/stale/reboot/reparse refusal, custom drawing and other release preservation. Fixture trust/payload boundary mocked; actual vendor acceptance pending. Artifacts: '+$root
