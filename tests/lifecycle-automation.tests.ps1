param([string]$BasePython=(Get-Command python -ErrorAction Stop).Source)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$busyRefused=$false
try { Assert-GdiagAutomationIdle (Split-Path -Parent (Get-Process -Id $PID).Path) } catch { $busyRefused=$true }
Assert $busyRefused 'Mutation boundary ignored an executable running inside selected tree'
$root=Join-Path $PSScriptRoot ('.tmp-automation-'+[guid]::NewGuid().ToString())
$casePath=Join-Path $root 'case';New-Item -ItemType Directory -Path $casePath -Force | Out-Null
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$ctx=@{caseId='case-native-automation';casePath=$casePath;machine=[Environment]::MachineName;executorSid=$sid;affectedSid=$sid}
$destination=Join-Path $root ('automation '+[char]0x4E2D+[char]0x6587)
$target=[pscustomobject]@{id='automation-1';path=$destination;family='AutomationEnvironment'}
Write-GdiagLifeJson (Join-Path $casePath 'case.json') @{formatVersion=1;caseId=$ctx.caseId;context=$ctx;targets=@($target)}
$options=@{recipe='automation-venv';pythonPath=$BasePython;expectedPythonHash=(Get-GdiagFileHash $BasePython);standalonePython=$true;wheels=@();dependencies=@();timeoutSeconds=120}
$plan=New-GdiagPlan $ctx $target Setup $options
$planPath=Join-Path $casePath 'plan.json';Write-GdiagLifeJson $planPath $plan
Assert (-not(Test-Path -LiteralPath $destination)) 'Automation planning created a venv'
$result=Invoke-GdiagPlan $planPath Apply
Assert ($result.status -eq 'applied') "Venv setup failed: $($result.error)"
Assert ($result.readiness -eq 'stdlib-only') 'Stdlib mistaken for automation readiness'
Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'verified') 'Venv verify failed'
# Repair recreates only owned dedicated environment; previous environment kept whole.
$plan=New-GdiagPlan $ctx $target Repair $options;Write-GdiagLifeJson $planPath $plan
$result=Invoke-GdiagPlan $planPath Apply
Assert ($result.status -eq 'applied') "Venv repair failed: $($result.error)"
Assert (Test-Path -LiteralPath $plan.previousPath) 'Original environment not preserved'
Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'verified') 'Venv repair verify failed'
Assert ((Invoke-GdiagPlan $planPath Undo).status -eq 'undone') 'Venv repair undo failed'
$bundled=Join-Path (Split-Path -Parent $BasePython) 'Lib/ensurepip/_bundled'
$pipWheel=Get-ChildItem -LiteralPath $bundled -Filter 'pip-*.whl' | Select-Object -First 1
if($pipWheel){
    $pipVersion=($pipWheel.BaseName -split '-')[1]
    $options.wheels=@(@{path=$pipWheel.FullName;sha256=(Get-GdiagFileHash $pipWheel.FullName)})
    $options.dependencies=@('pip=='+$pipVersion)
    $plan=New-GdiagPlan $ctx $target Update $options;Write-GdiagLifeJson $planPath $plan
    $result=Invoke-GdiagPlan $planPath Apply
    Assert ($result.status -eq 'applied') "Offline wheel update failed: $($result.error)"
    Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'verified') 'Offline wheel version verification failed'
    Assert ((Invoke-GdiagPlan $planPath Undo).status -eq 'undone') 'Offline wheel update undo failed'
}
$probe=Invoke-GdiagLifeProcess $BasePython @('-I','-c','import time; time.sleep(10)') $casePath 1
Assert ($probe.status -eq 'timeout') 'Owned child timeout was not bounded'
Assert ((Get-GdiagFileHash $BasePython) -eq $options.expectedPythonHash) 'Base interpreter changed'
Write-Output ('Automation stdlib/offline pip wheel native acceptance passed; pygcadwin/COM pending: '+$root)
