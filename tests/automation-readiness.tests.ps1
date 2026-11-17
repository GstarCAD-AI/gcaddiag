param(
    [Parameter(Mandatory=$true)][string]$BasePython,
    [string]$WheelDirectory=(Join-Path $PSScriptRoot '.tmp-automation-readiness-download'),
    [string]$ExistingEnvironment
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Evidence.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Windows.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Prerequisites.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
# Published PyPI artifacts, not the unversioned/local checkout. No download in test.
$trusted=@(
    @{name='pygcadwin-0.1.0-py3-none-any.whl';sha256='7caf09f2566c3cf49b7fbffcac4e85c560a08ff884b129ecfbe8ef13966e7d0d';source='https://pypi.org/pypi/pygcadwin/0.1.0/json'},
    @{name='pywin32-311-cp311-cp311-win_amd64.whl';sha256='3ce80b34b22b17ccbd937a6e78e7225d80c52f5ab9940fe0506a1a16f3dab503';source='https://pypi.org/pypi/pywin32/311/json'}
)
$wheels=@(foreach($item in $trusted){
    $path=[IO.Path]::GetFullPath((Join-Path $WheelDirectory $item.name))
    Assert ((Get-GdiagFileHash $path) -eq $item.sha256) ('Supplied wheel is absent or differs from published PyPI SHA256: '+$item.name)
    @{path=$path;sha256=$item.sha256}
})
$root=Join-Path $PSScriptRoot ('.tmp-automation-readiness-'+[guid]::NewGuid())
$case=Join-Path $root 'case';New-Item -ItemType Directory -Path $case -Force|Out-Null
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$context=@{caseId='actual-automation-readiness';casePath=$case;machine=[Environment]::MachineName;executorSid=$sid;affectedSid=$sid}
$target=[pscustomobject]@{id='automation-selected';family='AutomationEnvironment';path=(Join-Path $root ('dedicated '+[char]0x4E2D+[char]0x6587));pythonPath=$null}
if($ExistingEnvironment){
    $target.path=[IO.Path]::GetFullPath($ExistingEnvironment)
    $owned=Get-Content -LiteralPath (Join-Path $target.path 'gcaddiag-environment.json') -Raw -Encoding UTF8|ConvertFrom-Json
    Assert ($owned.owner -eq 'gcaddiag') 'Reused test environment is not a gcaddiag-owned fixture'
}
$target.pythonPath=Join-Path $target.path 'Scripts/python.exe'
Write-GdiagJson (Join-Path $case 'case.json') @{formatVersion=1;kind='local';caseId=$context.caseId;context=$context;targets=@($target)}
$before=Get-GdiagFileHash $BasePython
$options=@{recipe='automation-venv';pythonPath=$BasePython;expectedPythonHash=$before;standalonePython=$true;wheels=$wheels;dependencies=@('pygcadwin==0.1.0','pywin32==311');timeoutSeconds=120}
if(-not $ExistingEnvironment){
    $plan=New-GdiagPlan $context $target Setup $options
    $planPath=Join-Path $case 'plan.json';Write-GdiagJson $planPath $plan
    $applied=Invoke-GdiagPlan $planPath Apply
    Assert ($applied.status -eq 'applied') ('Dedicated offline package setup failed: '+$applied.error)
    Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'verified') 'Exact offline package verification failed'
}
$evidence=Invoke-GdiagAutomationReadiness -Context $context -Target $target -Options @{wheelPaths=@($wheels.path)} -TimeoutSeconds 30
Write-GdiagJson (Join-Path $root 'readiness.json') $evidence
Assert ($evidence.status -eq 'observed') 'Readiness subprocess failed'
Assert ($evidence.summary.automationReadiness -eq 'imports_verified_host_pending') ('Package/pywin32 import readiness not verified; inspect local evidence: '+$root)
Assert ($evidence.summary.dedicatedEnvironment -and $evidence.summary.pipInSelectedPrefix) 'Pip/import escaped selected environment'
Assert ($evidence.summary.pipRouteAssessment -eq 'selected_interpreter_default') 'Pip configuration redirects isolated installs'
Assert ($evidence.observed.readiness.interpreter -eq $target.pythonPath) 'Interpreter identity mismatch'
Assert (@($evidence.observed.readiness.wheels|Where-Object {$_.pythonCompatible -and $_.wheelTagsCompatible}).Count -eq 2) 'Trusted wheel compatibility not established'
$pipConfig=Join-Path $target.path 'pip.ini'
$originalConfig=if(Test-Path -LiteralPath $pipConfig){[IO.File]::ReadAllBytes($pipConfig)}else{$null}
try{
    [IO.File]::WriteAllText($pipConfig,"[install]`ntarget = "+(Join-Path $root 'unexpected target')+"`n")
    $redirect=Invoke-GdiagAutomationReadiness -Context $context -Target $target -TimeoutSeconds 30
    Assert ($redirect.summary.pipRouteAssessment -eq 'redirect_configured') 'Site pip target redirect was mistaken for selected environment install target'
    Assert ($redirect.observed.readiness.isolatedPipRedirectKeys -contains 'install.target') 'Redirect key provenance missing'
}finally{
    if($null -ne $originalConfig){[IO.File]::WriteAllBytes($pipConfig,$originalConfig)}else{Remove-Item -LiteralPath $pipConfig}
}
# A separate metadata-only wheel with a future Python/platform must not be accepted.
Add-Type -AssemblyName System.IO.Compression
$incompatible=Join-Path $root 'incompatible.whl'
$file=[IO.File]::Open($incompatible,[IO.FileMode]::CreateNew)
$archive=New-Object IO.Compression.ZipArchive($file,[IO.Compression.ZipArchiveMode]::Create)
try{
    foreach($entry in @(@{name='fixture-1.dist-info/WHEEL';text="Wheel-Version: 1.0`nTag: cp999-cp999-win_arm64`n"},@{name='fixture-1.dist-info/METADATA';text="Name: fixture`nVersion: 1`nRequires-Python: >=99`n"})){
        $writer=New-Object IO.StreamWriter($archive.CreateEntry($entry.name).Open());$writer.Write($entry.text);$writer.Dispose()
    }
}finally{$archive.Dispose();$file.Dispose()}
$rejected=Invoke-GdiagAutomationReadiness -Context $context -Target $target -Options @{wheelPaths=@($incompatible)} -TimeoutSeconds 30
Assert (-not $rejected.observed.readiness.wheels[0].pythonCompatible -and -not $rejected.observed.readiness.wheels[0].wheelTagsCompatible) 'Incompatible wheel mistaken for usable package'
Assert ((Get-GdiagFileHash $BasePython) -eq $before) 'Base interpreter changed'
Assert ($evidence.observed.readiness.hostAttachment -eq 'not_tested') 'Imports falsely imply CAD host health'
$processes=@(Get-Process -ErrorAction Stop|Where-Object ProcessName -in @('gcad','GstarCAD')|Select-Object Id,SessionId,Path)
Write-GdiagJson (Join-Path $root 'acceptance.json') @{status='imports-and-pip-target-verified';interpreter=$target.pythonPath;packages=@('pygcadwin==0.1.0','pywin32==311');sources=$trusted;reusedPriorSetupFixture=([bool]$ExistingEnvironment);hostVerification='pending';runningCadCandidates=$processes;noHostCreatedOrClosed=$true;baseInterpreterUnchanged=$true}
'PASS native automation: exact offline PyPI wheels, selected interpreter/pip target, actual pygcadwin/pythoncom imports, incompatible wheel rejection, base unchanged; CAD host pending. Artifacts: '+$root
