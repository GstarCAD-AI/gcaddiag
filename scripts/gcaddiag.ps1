[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Scan','Probe','Record','Plan','Apply','Verify','Undo','Export','Compare','Report')][string]$Action,
    [string]$Case, [string]$Output, [string]$TargetId, [string]$FindingId,
    [ValidateSet('Setup','Repair','Cleanup','Update','Uninstall')][string]$Operation,
    [string]$Plan, [string]$InputFile, [string]$Baseline, [string]$AffectedSid,
    [string]$Probe='Runtime', [string]$Endpoint,
    [ValidateSet('All','Windows','GstarCAD','GstarAssistant','gcad-cli','Automation','ExternalAgent','Crash')][string]$Profile='All',
    [string]$Symptom, [datetime]$StartTime=[datetime]::Now.AddHours(-2),
    [ValidateRange(1,300)][int]$TimeoutSeconds=15
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
. (Join-Path $PSScriptRoot 'modules/Evidence.ps1')
try {
    if ($TargetId -and -not $Case) {throw '-TargetId always requires -Case; IDs are not portable between scans.'}
    foreach ($module in @('Windows','Lifecycle','Integration','Prerequisites','Components','Cleanup','CrashLogs','CrashDumps','CrashEvidence','CliPackage','PrerequisiteRepair','CodexMcpRepair')) { . (Join-Path $PSScriptRoot "modules/$module.ps1") }
    $options=@{}
    if ($InputFile) {
        $inputObject=Read-GdiagJson $InputFile
        foreach ($p in $inputObject.PSObject.Properties) { $options[$p.Name]=$p.Value }
    }
    if($Action -eq 'Probe' -and $Probe -eq 'DumpAnalysis'){
        if(-not $Output -or -not $options.dumpPath){throw 'Offline DumpAnalysis requires an explicit analyst-local dumpPath in InputFile and a new -Output directory.'}
        $casePath=Assert-GdiagPlainPath $Output
        if(Test-Path -LiteralPath $casePath){throw 'Use a new analysis output directory; supplied customer evidence is not overwritten.'}
        $analysisContext=Get-GdiagContext '' $casePath
        if($Case){$document=Read-GdiagJson (Join-Path $Case 'case.json');if($document.formatVersion -ne 1){throw 'Unsupported source case format.'}}
        else{$document=[pscustomobject]@{formatVersion=1;caseId=$analysisContext.caseId;collectorVersion=$script:GdiagVersion;kind='analysis';profile='Crash';symptom=$(if($Symptom){$Symptom}else{'Supplied minidump crash analysis'});context=@{machine=$null;executorSid=$null;affectedSid=$null;userSelection='customer_context_not_collected'};targets=@();observations=@();findings=@();completeness='partial'}}
        $target=$null
        if($TargetId){$matches=@($document.targets|Where-Object id -eq $TargetId);if($matches.Count -ne 1){throw 'Selected customer target is not unique in the supplied case.'};$target=$matches[0]}
        $document | Add-Member -NotePropertyName kind -NotePropertyValue analysis -Force
        $document | Add-Member -NotePropertyName analystExecution -NotePropertyValue $analysisContext -Force
        $document | Add-Member -NotePropertyName isCrashCase -NotePropertyValue $true -Force
        New-Item -ItemType Directory -Path $casePath | Out-Null
        $analysisContext.caseId=$document.caseId
        $dumpTimeout=if($PSBoundParameters.ContainsKey('TimeoutSeconds')){$TimeoutSeconds}else{45}
        Add-GdiagObservations $document (Invoke-GdiagDumpAnalysis -Context $analysisContext -Target $target -Options $options -TimeoutSeconds $dumpTimeout)
        $dumpEvidence=@($document.observations|Where-Object source -eq 'crash.dump_analysis'|Select-Object -Last 1)[0]
        $dumpFinding=[pscustomobject]@{id=('finding-dump-'+[guid]::NewGuid().ToString('N').Substring(0,10));targetId=$dumpEvidence.targetId;evidenceIds=@($dumpEvidence.id);
            confidence=$(if($dumpEvidence.summary.exceptionCode){'confirmed'}else{'unknown'});
            symptom=$(if($dumpEvidence.summary.exceptionCode){'Minidump records exception '+$dumpEvidence.summary.exceptionCode}else{'Minidump exception context remains unresolved.'});
            impact=('{0} recovered frames; stack status: {1}. This records execution context, not a proven root cause.' -f @($dumpEvidence.stackFrames).Count,$dumpEvidence.summary.stackStatus);
            nextAction='Confirm the dump belongs to the selected incident, compare matching module versions and local symbols, then correlate the exception stack with TRACE/log/event evidence.';cause='unresolved'}
        $document.findings=@($document.findings)+@($dumpFinding)
        Write-GdiagJson (Join-Path $casePath 'case.json') $document
        Write-GdiagReport $document (Join-Path $casePath 'report.md')
        $result=$document
    } elseif ($Action -in @('Apply','Verify','Undo')) {
        if (-not $Plan) { throw '-Plan is required.' }
        $result=Invoke-GdiagPlan -PlanPath $Plan -Mode $Action
        if ($result.status -eq 'failed') {
            $result | Add-Member -NotePropertyName nextAction -NotePropertyValue 'Inspect the local action journal and actual state. Partial changes may remain; confirm owned probe processes stopped before recovery. Automatic undo is restricted to completed supported actions.' -Force
        }
        $executedPlan=Read-GdiagJson $Plan
        $casePath=$executedPlan.casePath
        $document=Read-GdiagJson (Join-Path $casePath 'case.json')
        $maintenance=[pscustomobject]@{timeUtc=[datetime]::UtcNow.ToString('o');planId=$executedPlan.planId;operation=$executedPlan.operation;
            mode=$Action;targetId=$executedPlan.target.id;status=$result.status;nativeExitCode=$result.nativeExitCode;restartRequired=$result.restartRequired;hostVerification=$result.hostVerification;
            componentVerification=$result.componentVerification;runtimeVerification=$result.runtimeVerification;prerequisiteRebootStatus=$result.prerequisiteRebootStatus;readiness=$result.readiness;nextAction=$result.nextAction}
        if (-not $document.PSObject.Properties['changes']) {$document | Add-Member -NotePropertyName changes -NotePropertyValue @()}
        $document.changes=@($document.changes)+@($maintenance)
        Write-GdiagJson (Join-Path $casePath 'case.json') $document
        Write-GdiagReport $document (Join-Path $casePath 'report.md')
    } elseif ($Action -eq 'Scan') {
        if (-not $Output) { throw '-Output is required for a new case.' }
        $casePath=Assert-GdiagPlainPath $Output
        if (Test-Path -LiteralPath $casePath) { throw 'New case output must not already exist.' }
        $context=Get-GdiagContext $AffectedSid $casePath
        $context.startUtc=$StartTime.ToUniversalTime().ToString('o')
        New-Item -ItemType Directory -Path $casePath | Out-Null
        $document=[pscustomobject]@{ formatVersion=1; kind='local'; collectorVersion=$script:GdiagVersion; caseId=$context.caseId; context=$context;
            profile=$Profile; symptom=$Symptom; targets=@(); observations=@(); findings=@(); completeness='partial' }
        $document.targets=@(Get-GdiagInventory -Context $context)
        $additionalTargets=@(Get-GdiagAdditionalTargets -Context $context -Options $options)
        $cliPaths=@($additionalTargets | Where-Object family -eq 'gcad-cli' | ForEach-Object {$_.path})
        $document.targets=@($document.targets | Where-Object {$_.family -ne 'gcad-cli' -or $_.path -notin $cliPaths}) + $additionalTargets
        if ($Profile -in @('GstarCAD','GstarAssistant','gcad-cli')) {$document.targets=@($document.targets | Where-Object family -eq $Profile)}
        elseif ($Profile -in @('Windows','ExternalAgent')) {$document.targets=@()}
        foreach ($selection in @(@{key='selectedSkillPath';family='Skill'},@{key='selectedCasePath';family='Case'},@{key='selectedAutomationPath';family='AutomationEnvironment'})) {
            if ($options[$selection.key]) {
                $selectedPath=Assert-GdiagPlainPath $options[$selection.key]
                $marker=switch ($selection.family) {'Skill' {'SKILL.md'} 'Case' {'case.json'} 'AutomationEnvironment' {'pyvenv.cfg'}}
                if (-not (Test-Path -LiteralPath (Join-Path $selectedPath $marker) -PathType Leaf)) { throw "Selected $($selection.family) lacks $marker" }
                $document.targets+= [pscustomobject]@{family=$selection.family;path=$selectedPath;selection='explicit user input';treeHash=(Get-GdiagTreeHash @(Get-GdiagTree $selectedPath))}
            }
        }
        if ($options.selectedInstallerPath) {
            $installerPath=Assert-GdiagPlainPath $options.selectedInstallerPath
            if ([IO.Path]::GetExtension($installerPath) -ne '.exe' -or -not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {throw 'Select an existing installer executable file.'}
            $document.targets+=[pscustomobject]@{family='InstallerPackage';path=$installerPath;selection='explicit user input';file=(Get-GdiagFileIdentity $installerPath)}
        }
        if($options.selectedAgentConfigPath){
            $configPath=Assert-GdiagPlainPath $options.selectedAgentConfigPath
            if((Split-Path -Leaf $configPath) -ne 'config.toml' -or -not(Test-Path -LiteralPath $configPath -PathType Leaf)){throw 'Select an existing native Codex config.toml file.'}
            $document.targets+=[pscustomobject]@{family='AgentConfig';path=$configPath;selection='explicit user input';configHash=(Get-GdiagFileHash $configPath)}
        }
        $i=0; foreach ($target in $document.targets) { $i++; $target | Add-Member -NotePropertyName id -NotePropertyValue "target-$i" -Force }
        $context.targets=$document.targets
        Add-GdiagObservations $document (Get-GdiagWindowsEvidence -Context $context)
        Add-GdiagObservations $document (Get-GdiagPrerequisiteEvidence -Context $context -Targets $document.targets)
        if($Profile -eq 'Crash' -or $Symptom -match '(?i)crash|hang|access.violation|fatal|\u5d29\u6e83|\u95ea\u9000|\u65e0\u54cd\u5e94' -or $options.dumpPaths){
            $document | Add-Member -NotePropertyName isCrashCase -NotePropertyValue $true -Force
            foreach($crashTarget in @($document.targets|Where-Object family -eq 'GstarAssistant')){Add-GdiagObservations $document (Get-GdiagCrashLogEvidence -Context $context -Target $crashTarget -Options $options)}
            Add-GdiagObservations $document (Get-GdiagCrashEvidence -Context $context -Target $null -Options $options)
        }
        $context.Remove('targets')
        $context.Remove('additionalInventoryGaps')
        Add-GdiagObservations $document (Get-GdiagAgentEvidence -Context $context -Options $options)
        if ($Endpoint) { Add-GdiagObservations $document (Invoke-GdiagConnectivity -Context $context -Endpoint $Endpoint -TimeoutSeconds $TimeoutSeconds -DirectStages:([bool]$options.directNetworkStages)) }
        $document.findings=@([pscustomobject]@{ id='finding-1'; confidence='unknown'; evidenceIds=@($document.observations | ForEach-Object {$_.id});
            symptom=$Symptom; impact='Read-only inventory; component readiness requires selected probes.'; nextAction='Confirm affected user and target, inspect collection gaps, then select the relevant probe.' })
        $document.findings+=@(Get-GdiagWindowsFindings -Document $document)
        Write-GdiagJson (Join-Path $casePath 'case.json') $document
        Write-GdiagReport $document (Join-Path $casePath 'report.md')
        $result=$document
    } else {
        if (-not $Case) { throw '-Case is required; target IDs are case-local.' }
        $casePath=[IO.Path]::GetFullPath($Case)
        $document=Read-GdiagJson (Join-Path $casePath 'case.json')
        if ($document.formatVersion -ne 1) { throw 'Unsupported case format.' }
        $context=@{}; foreach ($p in $document.context.PSObject.Properties) { $context[$p.Name]=$p.Value }; $context.casePath=$casePath
        $target=$null
        if ($TargetId) { $target=@($document.targets | Where-Object id -eq $TargetId); if ($target.Count -ne 1) { throw 'Target ID is not unique in this case.' }; $target=$target[0] }
        if ($Action -in @('Probe','Record','Plan')) {
            if ($document.kind -ne 'local') {throw 'Saved public/imported evidence cannot authorize live operations. Collect a new local case.'}
            $live=Get-GdiagContext $context.affectedSid $casePath
            if ($context.machine -ne $live.machine -or $context.executorSid -ne $live.executorSid) { throw 'Saved case is from another machine/executor. Collect a fresh local case.' }
        }
        switch ($Action) {
            'Probe' {
                if ($target.file -and $target.file.status -eq 'observed') {
                    $currentFile=Get-GdiagFileIdentity $target.file.path
                    if ($currentFile.status -ne 'observed' -or $currentFile.fileVersion -ne $target.file.fileVersion -or $currentFile.architecture -ne $target.file.architecture -or $currentFile.length -ne $target.file.length) {throw 'Selected target file identity changed. Collect a fresh case before an active probe.'}
                }
                foreach ($property in @('pythonPath','progId','nativePath','storagePath')) {
                    if ($options[$property] -and $target) { $target | Add-Member -NotePropertyName $property -NotePropertyValue $options[$property] -Force }
                }
                if ($Probe -eq 'Connectivity') { if (-not $Endpoint) {throw '-Endpoint required'}; $items=Invoke-GdiagConnectivity -Context $context -Endpoint $Endpoint -TimeoutSeconds $TimeoutSeconds -DirectStages:([bool]$options.directNetworkStages) }
                elseif ($Probe -eq 'Mcp') { $items=Invoke-GdiagMcpProbe -Context $context -Options $options -TimeoutSeconds $TimeoutSeconds }
                elseif ($Probe -in @('WebViewCreate','StorageStatus')) { $items=Invoke-GdiagComponentProbe -Context $context -Target $target -Probe $Probe -Options $options -TimeoutSeconds $TimeoutSeconds }
                elseif ($Probe -eq 'AutomationReadiness') {
                    if(-not $target){throw '-TargetId is required for selected automation readiness.'}
                    $items=Invoke-GdiagAutomationReadiness -Context $context -Target $target -Options $options -TimeoutSeconds $TimeoutSeconds
                }
                elseif($Probe -eq 'CrashLogs'){
                    if(-not $target){throw '-TargetId is required for selected crash logs.'}
                    $items=Get-GdiagCrashLogEvidence -Context $context -Target $target -Options $options
                    $document | Add-Member -NotePropertyName isCrashCase -NotePropertyValue $true -Force
                }
                else { if (-not $target) {throw '-TargetId required'}; $items=Invoke-GdiagProbe -Context $context -Target $target -Probe $Probe -TimeoutSeconds $TimeoutSeconds }
                Add-GdiagObservations $document $items; $result=$document
            }
            'Record' {
                $traceCapturePlan=$null
                if($Plan){
                    $traceCapturePlan=Read-GdiagJson $Plan
                    if($traceCapturePlan.recipe -ne 'trace-logging' -or $traceCapturePlan.caseId -ne $document.caseId -or $TimeoutSeconds -gt $traceCapturePlan.captureSeconds){throw 'Record -Plan requires an applied TRACE plan from the same case and a capture interval within its bound.'}
                    $checkedTrace=Invoke-GdiagPlan -PlanPath $Plan -Mode Verify
                    if($checkedTrace.status -ne 'verified'){throw 'TRACE configuration is not in its applied state; inspect current state before capture.'}
                    $traceTargets=@($document.targets|Where-Object id -eq $traceCapturePlan.target.id)
                    if($traceTargets.Count -ne 1 -or ($target -and $target.id -ne $traceTargets[0].id)){throw 'TRACE capture target does not match the selected local case target.'}
                    $target=$traceTargets[0]
                }
                $capture=[pscustomobject]@{state='preparing';processId=$PID;processStartUtc=$null;startedUtc=[datetime]::UtcNow.ToString('o');timeoutSeconds=$TimeoutSeconds}
                if($traceCapturePlan){$capture|Add-Member -NotePropertyName tracePlanId -NotePropertyValue $traceCapturePlan.planId;$capture|Add-Member -NotePropertyName traceRestoreRequired -NotePropertyValue $true}
                $document | Add-Member -NotePropertyName capture -NotePropertyValue $capture -Force
                try {
                    $capture.processStartUtc=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')
                    $context.targets=@($(if($target){$target}else{$document.targets}))
                    if($traceCapturePlan){$context.targets=@($context.targets)+@($traceCapturePlan.hostTarget)}
                    $baselineItems=@(Get-GdiagWindowsEvidence -Context $context)
                    if($document.isCrashCase -or $traceCapturePlan){
                        if($target){$baselineItems+=@(Get-GdiagCrashLogEvidence -Context $context -Target $target -Options $options)}
                        $baselineItems+=@(Get-GdiagCrashEvidence -Context $context -Target $target -Options $options)
                    }
                    foreach ($item in $baselineItems) {$item | Add-Member -NotePropertyName phase -NotePropertyValue baseline -Force}
                    Add-GdiagObservations $document $baselineItems
                    $capture.state='recording'
                    Write-GdiagJson (Join-Path $casePath 'case.json') $document
                    Write-GdiagReport $document (Join-Path $casePath 'report.md')
                    $context.startUtc=[datetime]::UtcNow.ToString('o')
                    [Console]::Error.WriteLine("Reproduce now. Capture ends in $TimeoutSeconds seconds. Ctrl+C cancels capture; associated TRACE restoration runs when possible.")
                    Start-Sleep -Seconds $TimeoutSeconds
                    $context.endUtc=[datetime]::UtcNow.ToString('o')
                    $reproductionItems=@(Get-GdiagWindowsEvidence -Context $context)
                    if($document.isCrashCase -or $traceCapturePlan){
                        if($target){$reproductionItems+=@(Get-GdiagCrashLogEvidence -Context $context -Target $target -Options $options)}
                        $reproductionItems+=@(Get-GdiagCrashEvidence -Context $context -Target $target -Options $options)
                    }
                    foreach ($item in $reproductionItems) {$item | Add-Member -NotePropertyName phase -NotePropertyValue reproduction -Force}
                    Add-GdiagObservations $document $reproductionItems
                    $document.findings=@($document.findings | Where-Object id -eq 'finding-1') + @(Get-GdiagWindowsFindings -Document $document)
                    $capture.state='completed'
                } finally {
                    if ($capture.state -in @('preparing','recording')) {$capture.state='cancelled_or_failed'}
                    if($traceCapturePlan){
                        try{$restored=Invoke-GdiagPlan -PlanPath $Plan -Mode Undo}
                        catch{$restored=[pscustomobject]@{status='failed';runtimeVerification='unknown';nextAction='Inspect the local TRACE plan, original backup and current startup file; preserve intervening user edits.'}}
                        $document | Add-Member -NotePropertyName traceRestoration -NotePropertyValue $restored -Force
                        $capture.traceRestoreRequired=($restored.status -ne 'undone')
                        if(-not $document.PSObject.Properties['changes']){$document|Add-Member -NotePropertyName changes -NotePropertyValue @()}
                        $document.changes=@($document.changes)+@([pscustomobject]@{timeUtc=[datetime]::UtcNow.ToString('o');planId=$traceCapturePlan.planId;operation='Repair';mode='Undo';targetId=$traceCapturePlan.target.id;status=$restored.status;restartRequired=$restored.restartRequired;componentVerification=$restored.componentVerification;runtimeVerification=$restored.runtimeVerification;nextAction=$restored.nextAction})
                    }
                    Write-GdiagJson (Join-Path $casePath 'case.json') $document
                    Write-GdiagReport $document (Join-Path $casePath 'report.md')
                }
                $result=$document
            }
            'Plan' {
                if (-not $Operation) {throw '-Operation required'}
                if (-not $target -and $Operation -ne 'Setup') {throw '-TargetId required'}
                $context.targets=$document.targets
                $result=New-GdiagPlan -Context $context -Target $target -Operation $Operation -Options $options
                if ($Operation -eq 'Setup' -and $result.target -and -not $target) {
                    $document.targets+=@($result.target)
                    Write-GdiagJson (Join-Path $casePath 'case.json') $document
                }
                $planPath=Join-Path $casePath 'plan.json'; Write-GdiagJson $planPath $result
                if($result.preparation){
                    $preparation=$result.preparation
                    $summary=[ordered]@{}
                    $members=if($preparation -is [System.Collections.IDictionary]){@($preparation.Keys)}else{@($preparation.PSObject.Properties.Name)}
                    foreach($key in $members){if($key -notin @('observed','installationPath')){$summary[$key]=$preparation.$key}}
                    $source=if($Operation -eq 'Uninstall'){'maintenance.uninstall_preparation'}else{'maintenance.recovery_preparation'}
                    Add-GdiagObservations $document ([pscustomobject]@{source=$source;status='guidance_only';targetId=$target.id;summary=$summary;observed=$preparation.observed})
                    $context.Remove('targets')
                    Write-GdiagJson (Join-Path $casePath 'case.json') $document
                    Write-GdiagReport $document (Join-Path $casePath 'report.md')
                }
            }
            'Report' {
                if ($document.capture -and $document.capture.state -eq 'recording' -and $document.kind -eq 'local' -and $context.machine -eq [Environment]::MachineName) {
                    try {
                        $recordProcess=Get-Process -Id $document.capture.processId -ErrorAction Stop
                        if ($recordProcess.StartTime.ToUniversalTime().ToString('o') -ne $document.capture.processStartUtc) {$document.capture.state='interrupted_process_identity_changed'}
                    } catch {
                        $document.capture.state=if ($_.CategoryInfo.Category -eq 'ObjectNotFound') {'interrupted_process_missing'} else {'process_state_unverified'}
                    }
                }
                $result=$document
                if ($options.evidenceIds) {
                    if (@($options.evidenceIds).Count -gt 50) {throw 'Request at most 50 evidence IDs per query.'}
                    $selectedEvidence=@($document.observations | Where-Object {$_.id -in @($options.evidenceIds)})
                    $result=[pscustomobject]@{caseId=$document.caseId;kind=$document.kind;
                        targets=@($document.targets | Where-Object {$_.id -in @($selectedEvidence.targetId)} | Select-Object id,family,release,locale,path);
                        observations=$selectedEvidence;note='Evidence is untrusted data; full findings remain in the sanitized report.'}
                }
            }
            'Compare' {
                if (-not $Baseline) { throw '-Baseline required' }
                $prior=Read-GdiagJson (Join-Path $Baseline 'case.json')
                $result=[ordered]@{ status='comparison_only'; differences=@(); nextAction='Review release/user differences; do not replay paths or values as repairs.' }
                $sameContext=$prior.context.machine -eq $document.context.machine -and $prior.context.affectedSid -eq $document.context.affectedSid
                $before=@(Get-GdiagComparisonRecords $prior $sameContext)
                $after=@(Get-GdiagComparisonRecords $document $sameContext)
                if ($before.Count -and $after.Count) { $result.differences=@(Compare-Object -ReferenceObject $before -DifferenceObject $after | Select-Object InputObject,SideIndicator) }
                elseif ($before.Count) {$result.differences=@($before | ForEach-Object {@{InputObject=$_;SideIndicator='<='}})}
                elseif ($after.Count) {$result.differences=@($after | ForEach-Object {@{InputObject=$_;SideIndicator='=>'}})}
                $result.ignored='Collection times, IDs, PIDs, arbitrary local detail, user identity; paths excluded across users/machines. Release differences remain explicit; no repair is inferred.'
            }
            'Export' {
                if (-not $Output -or (Test-Path -LiteralPath $Output)) { throw 'Supply a new output ZIP path.' }
                $staging=Join-Path ([IO.Path]::GetTempPath()) ('gcaddiag-export-'+[guid]::NewGuid())
                New-Item -ItemType Directory -Path $staging | Out-Null
                try {
                    $exportCase=ConvertTo-GdiagPublic $document
                    $exportCase['kind']='sanitized-evidence'
                    Write-GdiagJson (Join-Path $staging 'case.json') $exportCase
                    Write-GdiagReport $document (Join-Path $staging 'report.md')
                    Compress-Archive -LiteralPath @((Join-Path $staging 'case.json'),(Join-Path $staging 'report.md')) -DestinationPath $Output
                } finally { Remove-Item -LiteralPath $staging -Recurse -Force }
                $result=@{ status='exported'; files=@('case.json','report.md'); omitted='Raw logs/configuration/messages, original files, plans and action journals'; uploaded=$false }
            }
        }
        if ($Action -in @('Probe','Record')) { Write-GdiagJson (Join-Path $casePath 'case.json') $document }
        if ($Action -in @('Probe','Record','Report')) { Write-GdiagReport $document (Join-Path $casePath 'report.md') }
    }
    $publicResult=ConvertTo-GdiagPublic $result
    $serialized=ConvertTo-Json -InputObject $publicResult -Depth 40 -Compress
    if ($serialized.Length -gt 24000) {
        $publicResult=[ordered]@{status='completed';caseId=(ConvertTo-GdiagPublic $document.caseId);casePath=(Protect-GdiagText $casePath);stdoutTruncated=$true;
            capture=$publicResult.capture;
            targetCount=@($document.targets).Count;observationCount=@($document.observations).Count;
            targets=@($publicResult.targets | Select-Object -First 12 | ForEach-Object {[pscustomobject]$_} | Select-Object id,family,release,locale,path,expectationStatus);
            findings=@($publicResult.findings | Select-Object -First 12 | ForEach-Object {[pscustomobject]$_} | Select-Object id,targetId,confidence,symptom,impact,nextAction);
            nextAction='Read report.md for full sanitized evidence; local case.json contains sensitive details.'}
        $serialized=ConvertTo-Json -InputObject $publicResult -Depth 30 -Compress
        if($serialized.Length -gt 24000){
            # A selected field can itself be oversized in imported evidence.
            # Keep the final fallback independent of arbitrary document strings/objects.
            $compactCaseId=ConvertTo-GdiagPublic $document.caseId
            if($compactCaseId -isnot [string] -or $compactCaseId.Length -gt 256){$compactCaseId='[CASE IDENTIFIER OMITTED]'}
            $publicResult=[ordered]@{status='completed';caseId=$compactCaseId;stdoutTruncated=$true;
                targetCount=@($document.targets).Count;observationCount=@($document.observations).Count;findingCount=@($document.findings).Count;
                nextAction='Read report.md in the selected case directory for sanitized evidence. Local case.json contains sensitive details.'}
            $serialized=ConvertTo-Json -InputObject $publicResult -Depth 5 -Compress
        }
    }
    $serialized
    exit 0
} catch {
    # Parser/native exception messages can contain the complete private input.
    # Emit only fixed guidance and typed failure metadata, including on early input failures.
    [ordered]@{ status='command_failed'; error='Command failed; private exception text withheld.';
        failure=@{domain='PowerShell';type=$_.Exception.GetType().FullName;category=$_.CategoryInfo.Category.ToString();hresult=$_.Exception.HResult};
        nextAction='Inspect the selected input and local action journal, if present, for policy/access or state issues. No global policy changes are made.' } | ConvertTo-Json -Compress
    exit 2
}
