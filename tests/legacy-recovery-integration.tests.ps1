$ErrorActionPreference='Stop'
# Reuse native owned vendor executable fixture; publisher and registration remain mocked.
. (Join-Path $PSScriptRoot 'lifecycle-vendor.tests.ps1')
$script:fixtureDestination=$target.path
$savedManifest=Join-Path $target.path 'payload-manifest.json'
Remove-Item -LiteralPath $savedManifest
$missing=Join-Path $target.path 'modules/GstarAssistant.grx';Remove-Item -LiteralPath $missing
$refused=$false;try{New-GdiagPlan $ctx $target Repair $options | Out-Null}catch{$refused=$true}
Assert $refused 'Unknown installed metadata allowed ordinary repair without selected recovery'
$recoveryOptions=@{}+$options;$recoveryOptions.recoverMissingManifest=$true
$generated=New-GdiagPlan $ctx $target Repair $recoveryOptions
Assert ($generated.status -eq 'guidance_only' -and $generated.preparation.generatedCollisionCount -eq 2) 'Generated existing icon/uninstaller collisions did not produce preservation plan'
# Only remove this test's owned generated icon/uninstaller to exercise the eligible branch.
Remove-Item -LiteralPath (Join-Path $target.path 'uninstall.exe')
Remove-Item -LiteralPath (Join-Path $target.path 'app_icon.ico')
$eligible=New-GdiagPlan $ctx $target Repair $recoveryOptions
Assert ($eligible.status -eq 'planned' -and $eligible.legacyRecovery.canOverlay) 'Missing-manifest no-collision repair not planned'
$recoveryPlan=Join-Path $casePath 'recovery-plan.json';Write-GdiagLifeJson $recoveryPlan $eligible
$customHash=Get-GdiagFileHash (Join-Path $target.path 'custom.dwg')
$result=Invoke-GdiagPlan $recoveryPlan Apply
Assert ($result.status -eq 'applied') "Native owned recovery fixture failed: $($result.error)"
Assert ((Invoke-GdiagPlan $recoveryPlan Verify).status -eq 'verified') 'Recovery payload/registration not verified'
Assert ((Get-GdiagFileHash (Join-Path $target.path 'custom.dwg')) -eq $customHash) 'Recovery changed custom data'
Assert ((Test-Path -LiteralPath $savedManifest) -and (Test-Path -LiteralPath $missing)) 'Missing metadata/module not restored'
# Differing customer bytes must produce a concrete private collision inventory.
Remove-Item -LiteralPath $savedManifest
$config=Join-Path $target.path 'configs/runtime/assistant.json';[IO.File]::WriteAllText($config,'customer-edited configuration')
$blocked=New-GdiagPlan $ctx $target Repair $recoveryOptions
Assert ($blocked.status -eq 'guidance_only' -and $blocked.preparation.collisionCount -eq 1) 'Unknown configuration edit was not preserved'
$blockedPath=Join-Path $casePath 'migration-needed.json';Write-GdiagLifeJson $blockedPath $blocked
$refused=$false;try{Invoke-GdiagPlan $blockedPath Apply | Out-Null}catch{$refused=$true}
Assert $refused 'Preservation plan could execute vendor installer'
$refused=$false;try{New-GdiagPlan $ctx $target Update $recoveryOptions | Out-Null}catch{$refused=$true}
Assert $refused 'Unknown installed metadata silently allowed Update'
Write-GdiagLifeJson (Join-Path $root 'legacy-integration-acceptance.json') @{status='passed';nativeFixture='missing-manifest repair and verification';trustAndRegistration='mocked';vendorProductAcceptance='pending';preservedCustomHash=$customHash}
'PASS integrated legacy recovery: explicit scope, native owned missing-file/manifest restore, full verification, custom files preserved, differing files preparation-only. Artifacts: '+$root
