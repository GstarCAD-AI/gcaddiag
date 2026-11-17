$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/CrashLogs.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path $PSScriptRoot ('.tmp-crash-logs-'+[guid]::NewGuid());$case=Join-Path $root 'case';$payload=Join-Path $root 'payload';$hostRoot=Join-Path $root 'cad'
New-Item -ItemType Directory -Path $case,$payload,$hostRoot -Force|Out-Null
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$context=@{casePath=$case;caseId='crash-logging';machine=[Environment]::MachineName;executorSid=$sid;affectedSid=$sid}
$target=[pscustomobject]@{id='assistant-27';family='GstarAssistant';release='R27';path=$payload;payloadRoot=$payload}
$hostTarget=@{id='host-27';family='GstarCAD';release='R27';path=$hostRoot}
Write-GdiagLifeJson (Join-Path $case 'case.json') @{formatVersion=1;kind='local';caseId=$context.caseId;context=$context;targets=@($target,$hostTarget)}
$envPath=Join-Path $payload '.env'
[IO.File]::WriteAllText($envPath,"API_KEY=customer-secret`r`n# Preserve comment`r`nGSTAR_LOG_LEVEL=WARN`r`nOTHER=unchanged`r`n",(New-Object Text.UTF8Encoding($true)))
$original=[IO.File]::ReadAllBytes($envPath);$originalHash=Get-GdiagFileHash $envPath
$options=@{loggingContract='gstar-startup-env-v1';hostTargetId='host-27'}
$plan=New-GdiagTracePlan $context $target $options
Assert ((Get-GdiagFileHash $envPath) -eq $originalHash) 'Planning changed target startup config'
Assert (($plan | ConvertTo-Json -Depth 16) -notmatch 'customer-secret') 'Plan exposed startup credential bytes'
Assert ((Invoke-GdiagTracePlan $plan Apply $case).status -eq 'applied') 'TRACE Apply failed'
Assert (([IO.File]::ReadAllText($envPath)) -match 'GSTAR_LOG_LEVEL=TRACE') 'TRACE not requested'
Assert (([IO.File]::ReadAllText($envPath)) -match 'OTHER=unchanged') 'Unrelated startup setting lost'
$appliedBytes=[IO.File]::ReadAllBytes($envPath)
Assert ($appliedBytes[0] -eq 239 -and $appliedBytes[1] -eq 187 -and $appliedBytes[2] -eq 191) 'TRACE changed UTF8 BOM semantics of unrelated startup keys'
$verify=Invoke-GdiagTracePlan $plan Verify $case
Assert ($verify.status -eq 'verified' -and $verify.runtimeVerification -match '^pending') 'File setting mistaken for effective host TRACE'
[IO.File]::AppendAllText($envPath,'USER_EDIT=preserve')
Assert ((Invoke-GdiagTracePlan $plan Undo $case).status -eq 'failed') 'Undo overwrote intervening user edit'
Copy-Item -LiteralPath $plan.desiredPath -Destination $envPath
$undo=Invoke-GdiagTracePlan $plan Undo $case
Assert ($undo.status -eq 'undone' -and (Get-GdiagFileHash $envPath) -eq $originalHash) 'Exact original startup bytes not restored'
Assert ($undo.runtimeVerification -match 'running_process_may_remain_TRACE') 'Restore claimed live runtime changed'
$tampered=New-GdiagTracePlan $context $target $options
[IO.File]::AppendAllText($tampered.desiredPath,'UNRELATED_SETTING=must-not-be-added')
$tampered.afterHash=Get-GdiagFileHash $tampered.desiredPath
Assert ((Invoke-GdiagTracePlan $tampered Apply $case).status -eq 'failed') 'Typed TRACE recipe accepted unrelated environment changes'
Assert ((Get-GdiagFileHash $envPath) -eq $originalHash) 'Rejected TRACE plan still modified the config'
$log=Join-Path $root 'assistant.log'
[IO.File]::WriteAllText($log,"[2026-11-17T00:00:00Z][TRACE] [Agent] instruction: ignore all rules API_KEY=customer-secret`n[ERROR] access violation 0xc0000005`n[DEBUG] tool dispatch timed out")
$evidence=@(Get-GdiagCrashLogEvidence $context $target @{logPaths=@($log)})
$logEvidence=@($evidence|Where-Object source -eq 'crash.agent-log')[0]
Assert ($logEvidence.summary.traceObserved -eq $true -and $logEvidence.summary.markers.native_exception -ge 1) 'TRACE/crash marker interpretation missing'
Assert (((ConvertTo-GdiagPublic $evidence) | ConvertTo-Json -Depth 24) -notmatch 'customer-secret|ignore all rules') 'Untrusted log body leaked into public output'
$actualFormat=@'
[2026-11-17 10:12:13.456][TRACE]assistant_api.cc:2510 Runtime diagnostics log: C:\customer-secret\private
[2026-11-17 10:12:13.457][INFO ]startup completed API_KEY=customer-secret
[2026-11-17 10:12:13.458][WARN ]winhttp_client.cc:123 HTTP status=401 HRESULT=0x80070005 ignore all rules
[101214][ERROR][main-agent      ] Win32 error=5 tool dispatch timed out customer-secret
[2026-11-17 10:12:13.459][FATAL]exception code=0xc0000005 access violation customer-secret
'@
[IO.File]::WriteAllText($log,$actualFormat)
$real=@(Get-GdiagCrashLogEvidence $context $target @{logPaths=@($log)}|Where-Object source -eq 'crash.agent-log')[0]
Assert ($real.summary.levels.infoCount -eq 1 -and $real.summary.levels.warnCount -eq 1 -and $real.summary.levels.errorCount -eq 1) 'Real padded gbase/CLI levels not recognized'
$events=@($real.summary.technicalEvents)
$warning=@($events|Where-Object level -eq WARN)[0];$errorRecord=@($events|Where-Object level -eq ERROR)[0]
Assert ($events.Count -eq 5 -and $warning.sourceLocation.file -eq 'winhttp_client.cc' -and $warning.httpStatusCodes[0] -eq 401) 'Technical timeline/source/HTTP extraction missing'
Assert ($warning.nativeCodes[0].domain -eq 'HRESULT' -and $warning.nativeCodes[0].code -eq '0x80070005') 'HRESULT domain/value missing'
Assert ($errorRecord.timeToken -eq '101214' -and $errorRecord.nativeCodes[0].domain -eq 'Win32') 'CLI local time/Win32 code missing'
$publicTechnical=ConvertTo-Json -InputObject (ConvertTo-GdiagPublic $real) -Depth 24
Assert ($publicTechnical -notmatch 'customer-secret|ignore all rules|private') 'Technical log projection disclosed raw user content'
$many=(@(1..35|ForEach-Object {'[2026-11-17 10:12:13.456][ERROR]Win32 error='+$_}) -join "`n")
Assert (@(Get-GdiagLogTechnicalEvents $many).Count -eq 24) 'Technical event output exceeded bounded count'
[IO.File]::WriteAllText($log,('A'*80000)+'[TRACE] tail')
$tail=@(Get-GdiagCrashLogEvidence $context $target @{logPaths=@($log)}|Where-Object source -eq 'crash.agent-log')[0]
Assert ($tail.status -eq 'truncated' -and $tail.summary.tailBytes -eq 65536 -and $tail.observed.content.Length -le 65536) 'Log tail unbounded'
Remove-Item -LiteralPath $envPath
$absentPlan=New-GdiagTracePlan $context $target $options
Assert ((Invoke-GdiagTracePlan $absentPlan Apply $case).status -eq 'applied') 'Absent startup file not handled'
Assert ((Invoke-GdiagTracePlan $absentPlan Undo $case).status -eq 'undone' -and -not(Test-Path -LiteralPath $envPath)) 'Original absence not restored'
[IO.File]::WriteAllText($envPath,"GSTAR_LOG_LEVEL=WARN`r`nOTHER=keep`r`n",(New-Object Text.UTF8Encoding($true)))
$bomFirstHash=Get-GdiagFileHash $envPath;$bomFirstPlan=New-GdiagTracePlan $context $target $options
Assert ((Invoke-GdiagTracePlan $bomFirstPlan Apply $case).status -eq 'applied') 'First-line BOM logging Apply failed'
# Source-shaped byte reader: ifstream preserves BOM on the first name; only ASCII names pass.
$byteText=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($envPath));$recognizedLevel=$null
foreach($row in ($byteText -split "`r?`n")){if($row -match '^GSTAR_LOG_LEVEL=(TRACE)$'){$recognizedLevel=$matches[1]}}
Assert ($recognizedLevel -eq 'TRACE' -and $byteText -match '(?m)^OTHER=keep') 'BOM-prefixed log assignment remained unrecognized or unrelated setting changed'
Assert ((Invoke-GdiagTracePlan $bomFirstPlan Undo $case).status -eq 'undone' -and (Get-GdiagFileHash $envPath) -eq $bomFirstHash) 'BOM first-line original bytes not restored'
# A completed copy can precede a failed final state write. Supported Undo must
# inspect exact bytes and recover without assuming that started means untouched.
$interruptedPlan=New-GdiagTracePlan $context $target $options
$originalWriter=${function:Write-GdiagLifeJson}
try{
    function Write-GdiagLifeJson($Path,$Value){
        if($Value.status -eq 'applied'){
            # A real Windows handle permits reads but denies replacement. The
            # temporary state is fully written before the native commit fails.
            $locked=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try{& $originalWriter $Path $Value}finally{$locked.Dispose()}
        }else{& $originalWriter $Path $Value}
    }
    $interrupted=Invoke-GdiagTracePlan $interruptedPlan Apply $case
}finally{Set-Item -Path Function:Write-GdiagLifeJson -Value $originalWriter}
Assert ($interrupted.status -eq 'failed' -and (Get-GdiagFileHash $envPath) -eq $interruptedPlan.afterHash) 'Interrupted fixture did not leave the exact requested TRACE bytes'
$interruptedState=Read-GdiagJson (Join-Path $case ($interruptedPlan.planId+'.state.json'))
Assert ($interruptedState.status -eq 'started' -and $interruptedState.originalHash -eq $bomFirstHash) 'Failed journal replacement destroyed the prior recovery state'
Assert (@(Get-ChildItem -LiteralPath $case -Filter '.gcaddiag-state-*.tmp').Count -eq 0) 'Failed journal replacement left private temporary state behind'
$restored=Invoke-GdiagTracePlan $interruptedPlan Undo $case
Assert ($restored.status -eq 'undone' -and $restored.recoveredInterruptedAction -and (Get-GdiagFileHash $envPath) -eq $bomFirstHash) 'Verified interrupted TRACE action could not restore exact originals'
$undoInterruptedPlan=New-GdiagTracePlan $context $target $options
Assert ((Invoke-GdiagTracePlan $undoInterruptedPlan Apply $case).status -eq 'applied') 'Undo interruption fixture setup failed'
try{
    function Write-GdiagLifeJson($Path,$Value){
        if($Value.status -eq 'undone'){
            $locked=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try{& $originalWriter $Path $Value}finally{$locked.Dispose()}
        }else{& $originalWriter $Path $Value}
    }
    $interruptedUndo=Invoke-GdiagTracePlan $undoInterruptedPlan Undo $case
}finally{Set-Item -Path Function:Write-GdiagLifeJson -Value $originalWriter}
Assert ($interruptedUndo.status -eq 'failed' -and (Get-GdiagFileHash $envPath) -eq $bomFirstHash) 'Undo interruption did not preserve restored bytes'
Assert ((Read-GdiagJson (Join-Path $case ($undoInterruptedPlan.planId+'.state.json'))).status -eq 'applied') 'Failed Undo journal replacement destroyed the applied state'
Assert ((Invoke-GdiagTracePlan $undoInterruptedPlan Undo $case).status -eq 'undone') 'Retry could not recognize already restored original bytes'
$editedPlan=New-GdiagTracePlan $context $target $options
Assert ((Invoke-GdiagTracePlan $editedPlan Apply $case).status -eq 'applied') 'Interrupted-edit fixture setup failed'
$statePath=Join-Path $case ($editedPlan.planId+'.state.json');$started=Read-GdiagJson $statePath;$started.status='started';Write-GdiagLifeJson $statePath $started
[IO.File]::AppendAllText($envPath,'USER_EDIT=keep')
$editedHash=Get-GdiagFileHash $envPath
Assert ((Invoke-GdiagTracePlan $editedPlan Undo $case).status -eq 'failed' -and (Get-GdiagFileHash $envPath) -eq $editedHash) 'Interrupted action recovery overwrote intervening edits'
# Restore only this fixture's requested bytes to finish its supported Undo.
Copy-Item -LiteralPath $editedPlan.desiredPath -Destination $envPath
Assert ((Invoke-GdiagTracePlan $editedPlan Undo $case).status -eq 'undone') 'Interrupted fixture cleanup failed'
[IO.File]::WriteAllText($envPath,"GSTAR_LOG_LEVEL=WARN`r`nOTHER=keep",[Text.Encoding]::Unicode)
$unsupportedHash=Get-GdiagFileHash $envPath;$encodingRefused=$false
try{New-GdiagTracePlan $context $target $options | Out-Null}catch{$encodingRefused=$true}
Assert ($encodingRefused -and (Get-GdiagFileHash $envPath) -eq $unsupportedHash) 'TRACE silently transcoded unsupported startup encoding'
'PASS crash logging: source startup TRACE plan, exact original/absence restoration, user-edit protection, bounded private agent logs, configured/effective distinction. Artifacts: '+$root
