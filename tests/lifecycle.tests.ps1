$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
function Assert($Condition,$Message) { if(-not $Condition){throw $Message} }
function MustFail([scriptblock]$Block,$Message) { $failed=$false;try{& $Block | Out-Null}catch{$failed=$true};Assert $failed $Message }
$root=Join-Path $PSScriptRoot ('.tmp-lifecycle-'+[guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $root | Out-Null
$casePath=Join-Path $root 'current case';New-Item -ItemType Directory -Path $casePath | Out-Null
$source=Join-Path $root 'trusted source';New-Item -ItemType Directory -Path $source | Out-Null
Set-Content -LiteralPath (Join-Path $source 'SKILL.md') -Value "---`nname: sample`ndescription: test fixture`n---`nfixture" -Encoding UTF8
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$ctx=@{caseId='case-native-lifecycle';casePath=$casePath;machine=[Environment]::MachineName;executorSid=$sid;affectedSid=$sid}
$destination=Join-Path $root ('installed skill '+[char]0x4E2D+[char]0x6587)
$target=[pscustomobject]@{id='skill-1';path=$destination;family='Skill'}
Write-GdiagLifeJson (Join-Path $casePath 'case.json') @{formatVersion=1;caseId=$ctx.caseId;context=$ctx;targets=@($target)}
$options=@{recipe='skill-package';sourcePath=$source;expectedPackageHash=(Get-GdiagTreeHash @(Get-GdiagTree $source))}
$plan=New-GdiagPlan -Context $ctx -Target $target -Operation Setup -Options $options
Assert (-not (Test-Path -LiteralPath $destination)) 'Planning mutated target'
$planPath=Join-Path $casePath 'plan.json';Write-GdiagLifeJson $planPath $plan
$invalidIdentity=New-GdiagPlan -Context $ctx -Target $target -Operation Setup -Options $options
$invalidIdentity.planId='../escaped-artifact'
Write-GdiagLifeJson (Join-Path $casePath 'invalid-plan.json') $invalidIdentity
MustFail {Invoke-GdiagPlan (Join-Path $casePath 'invalid-plan.json') Apply} 'Plan identity escaped case-local artifact paths'
Assert (-not(Test-Path -LiteralPath (Join-Path $root 'escaped-artifact.state.json'))) 'Invalid plan wrote outside its case'
$result=Invoke-GdiagPlan $planPath Apply;Assert ($result.status -eq 'applied') "Setup failed: $($result.error)"
Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'verified') 'Setup verification failed'
Set-Content -LiteralPath (Join-Path $destination 'SKILL.md') -Value 'user edit' -Encoding UTF8
Assert ((Invoke-GdiagPlan $planPath Undo).status -eq 'failed') 'Undo overwrote user edit'
Copy-Item -LiteralPath (Join-Path $source 'SKILL.md') -Destination (Join-Path $destination 'SKILL.md')
Assert ((Invoke-GdiagPlan $planPath Undo).status -eq 'undone') 'Supported undo failed'
Set-Content -LiteralPath (Join-Path $source '.env') -Value 'TOKEN=not-a-real-secret'
$secretOptions=@{}+$options;$secretOptions.expectedPackageHash=Get-GdiagTreeHash @(Get-GdiagTree $source)
MustFail {New-GdiagPlan $ctx $target Setup $secretOptions} 'Credential file accepted in package'
Remove-Item -LiteralPath (Join-Path $source '.env')
$tampered=New-GdiagPlan $ctx $target Setup $options
$tampered.destination=Join-Path $root 'other target'
Write-GdiagLifeJson $planPath $tampered
MustFail {Invoke-GdiagPlan $planPath Apply} 'Tampered destination accepted'
Assert (-not (Test-Path -LiteralPath $tampered.destination)) 'Tampered target mutated'
# Re-plan setup after undo; empty directories are harmless.
$plan=New-GdiagPlan $ctx $target Setup $options;Write-GdiagLifeJson $planPath $plan
Set-Content -LiteralPath (Join-Path $source 'SKILL.md') -Value 'changed source' -Encoding UTF8
Assert ((Invoke-GdiagPlan $planPath Apply).status -eq 'failed') 'Stale source accepted'
$options.expectedPackageHash=Get-GdiagTreeHash @(Get-GdiagTree $source)
$plan=New-GdiagPlan $ctx $target Setup $options;Write-GdiagLifeJson $planPath $plan
Assert ((Invoke-GdiagPlan $planPath Apply).status -eq 'applied') 'Second setup failed'
# Repair a missing recorded resource, update a coherent package, retain a custom file.
Remove-Item -LiteralPath (Join-Path $destination 'SKILL.md')
$plan=New-GdiagPlan $ctx $target Repair $options;Write-GdiagLifeJson $planPath $plan
Assert ((Invoke-GdiagPlan $planPath Apply).status -eq 'applied') 'Repair failed'
Set-Content -LiteralPath (Join-Path $destination 'custom.txt') -Value 'keep me'
Set-Content -LiteralPath (Join-Path $source 'SKILL.md') -Value 'new package' -Encoding UTF8
$options.expectedPackageHash=Get-GdiagTreeHash @(Get-GdiagTree $source)
$plan=New-GdiagPlan $ctx $target Update $options;Write-GdiagLifeJson $planPath $plan
Assert ((Invoke-GdiagPlan $planPath Apply).status -eq 'applied') 'Update failed'
Assert ((Get-Content -LiteralPath (Join-Path $destination 'custom.txt')) -eq 'keep me') 'Custom file lost'
Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'verified') 'Update verification failed'
$wrong=@{}+$ctx;$wrong.affectedSid='S-1-0-0';MustFail {New-GdiagPlan $wrong $target Repair $options} 'Wrong affected user accepted'
$plan=New-GdiagPlan $ctx $target Update $options;Write-GdiagLifeJson $planPath $plan
Set-Content -LiteralPath (Join-Path $destination 'custom.txt') -Value 'intervening edit'
Assert ((Invoke-GdiagPlan $planPath Apply).status -eq 'failed') 'Stale target accepted'
$old=Join-Path $root 'old case';New-Item -ItemType Directory -Path $old | Out-Null
Write-GdiagLifeJson (Join-Path $old 'case.json') @{formatVersion=1;caseId='selected-old-case';context=$ctx}
$oldTarget=[pscustomobject]@{id='old-case';path=$old;family='Case'}
Write-GdiagLifeJson (Join-Path $casePath 'case.json') @{formatVersion=1;caseId=$ctx.caseId;context=$ctx;targets=@($target,$oldTarget)}
Set-Content -LiteralPath (Join-Path $old 'custom.dwg') -Value 'protected'
MustFail {New-GdiagPlan $ctx $oldTarget Cleanup @{recipe='old-case'}} 'Cleanup accepted drawing'
Remove-Item -LiteralPath (Join-Path $old 'custom.dwg')
$plan=New-GdiagPlan $ctx $oldTarget Cleanup @{recipe='old-case'};Write-GdiagLifeJson $planPath $plan
# An edited plan cannot redirect the case recipe to an installed component.
$bad=$plan | ConvertTo-Json -Depth 24 | ConvertFrom-Json
$bad.target=$target;$bad.destination=$target.path;$bad.beforeTreeHash=Get-GdiagTreeHash @(Get-GdiagTree $target.path)
$bad.quarantine=$target.path+'.gcaddiag-quarantine-'+$bad.planId
$badPath=Join-Path $casePath 'invalid-cleanup.json';Write-GdiagLifeJson $badPath $bad
MustFail {Invoke-GdiagPlan $badPath Apply} 'Case cleanup accepted a Skill target'
Assert (Test-Path -LiteralPath (Join-Path $target.path 'SKILL.md')) 'Invalid case cleanup moved an installation'
$bad=$plan | ConvertTo-Json -Depth 24 | ConvertFrom-Json
$bad.quarantine=Join-Path $root 'unrelated sibling';Write-GdiagLifeJson $badPath $bad
foreach($mode in @('Apply','Verify','Undo')){MustFail {Invoke-GdiagPlan $badPath $mode} 'Case cleanup accepted a noncanonical recovery path'}
# Even a rewritten current-state hash cannot make customer files disposable.
Set-Content -LiteralPath (Join-Path $old 'customer.dwg') -Value 'preserve this drawing'
$bad=$plan | ConvertTo-Json -Depth 24 | ConvertFrom-Json
$bad.beforeTreeHash=Get-GdiagTreeHash @(Get-GdiagTree $old);Write-GdiagLifeJson $badPath $bad
Assert ((Invoke-GdiagPlan $badPath Apply).status -eq 'failed') 'Case cleanup trusted an edited hash instead of checking ownership'
Assert (Test-Path -LiteralPath (Join-Path $old 'customer.dwg')) 'Invalid case cleanup moved customer files'
Remove-Item -LiteralPath (Join-Path $old 'customer.dwg')
Assert ((Invoke-GdiagPlan $planPath Apply).status -eq 'applied') 'Case quarantine failed'
Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'verified') 'Case quarantine verify failed'
Assert ((Invoke-GdiagPlan $planPath Undo).status -eq 'undone') 'Case quarantine undo failed'
$junction=Join-Path $root 'junction'
New-Item -ItemType Junction -Path $junction -Target $source | Out-Null
MustFail {Get-GdiagTree $junction} 'Reparse target accepted'
# Keep bounded test evidence for parent review; no recursive deletion.
Write-Output ('Lifecycle acceptance passed: '+$root)
