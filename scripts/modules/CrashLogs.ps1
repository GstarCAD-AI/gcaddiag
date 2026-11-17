# Source contract: gbase/log_config.cc; GstarAssistant assistant_app.cpp loadStartupEnvironmentFile.
function Get-GdiagLogSettings($Path) {
    $settings=@{level='not_set';file='not_set';console='not_set';duplicateLevelAssignments=0}
    if(Test-Path -LiteralPath $Path){
        if((Get-Item -LiteralPath $Path).Length -gt 1048576){throw 'Startup environment file exceeds 1 MiB inspection bound.'}
        foreach($line in [IO.File]::ReadAllLines($Path)){
            if($line -match '^\s*GSTAR_LOG_LEVEL\s*=\s*(.*?)\s*$'){
                $settings.duplicateLevelAssignments++
                if($settings.level -eq 'not_set'){$v=$matches[1].Trim('"',"'").ToLowerInvariant();$settings.level=if($v -in @('trace','debug','info','warn','warning','error','fatal','off','none','silent')){$v}else{'invalid'}}
            }elseif($line -match '^\s*GSTAR_LOG_FILE\s*=\s*(.*?)\s*$'){$settings.file='configured; value retained locally only'}
            elseif($line -match '^\s*GSTAR_LOG_CONSOLE\s*=\s*(.*?)\s*$'){$settings.console='configured'}
        }
    }
    $settings
}
function Get-GdiagTraceText([string]$Text,[bool]$PreserveUtf8Bom=$false) {
    if([regex]::Matches($Text,'(?m)^\s*GSTAR_LOG_LEVEL\s*=').Count -gt 1){throw 'Duplicate startup log-level assignments require reconciliation.'}
    $updated=if($Text -match '(?m)^\s*GSTAR_LOG_LEVEL\s*='){[regex]::Replace($Text,'(?m)^\s*GSTAR_LOG_LEVEL\s*=[^\r\n]*','GSTAR_LOG_LEVEL=TRACE')}else{$Text+$(if($Text -and -not $Text.EndsWith("`n")){"`r`n"}else{''})+"GSTAR_LOG_LEVEL=TRACE`r`n"}
    # C++ ifstream keeps BOM bytes in the first name, which isValidEnvironmentName rejects.
    # Move only the logging assignment off that first line; never activate unrelated first keys.
    if($PreserveUtf8Bom -and $updated -match '^[ \t]*GSTAR_LOG_LEVEL\s*='){$updated="# gcaddiag TRACE logging; original UTF8 BOM preserved`r`n"+$updated}
    $updated
}
function Get-GdiagTraceEncoding($Path) {
    $bom=$false
    if(Test-Path -LiteralPath $Path){
        $bytes=[IO.File]::ReadAllBytes($Path)
        if($bytes.Length -ge 2 -and (($bytes[0] -eq 255 -and $bytes[1] -eq 254) -or ($bytes[0] -eq 254 -and $bytes[1] -eq 255))){throw 'Startup environment is UTF16; preserve it and reconcile supported product encoding before TRACE.'}
        $bom=$bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191
        $strict=New-Object Text.UTF8Encoding($false,$true);[void]$strict.GetString($bytes)
    }
    New-Object Text.UTF8Encoding($bom,$true)
}
function Get-GdiagLogTechnicalEvents([string]$Text) {
    # gbase logger.cc: [YYYY-MM-DD HH:MM:SS.mmm][INFO ]basename:line body.
    # gcad-cli app_runtime.cc: [HHMMSS][INFO ][agent context] body.
    $records=New-Object Collections.Generic.List[object]
    foreach($line in ($Text -split "`r?`n")){
        $header=[regex]::Match($line,'^\[(?<time>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})?|\d{6})\]\[(?<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s*\](?<body>.*)$')
        if(-not $header.Success){$header=[regex]::Match($line,'^\[(?<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s*\](?<body>.*)$')}
        if(-not $header.Success){continue}
        $body=$header.Groups['body'].Value;$tags=New-Object Collections.Generic.List[string]
        foreach($signature in @(@('access_violation','(?i)access.violation|0xc0000005'),@('stack_overflow','(?i)stack.overflow|0xc00000fd'),@('fail_fast','(?i)fail.fast|0xc0000409|terminate called'),@('python_exception','(?i)Traceback \(most recent call last\)|Python.*exception'),@('timeout','(?i)timed? ?out|deadline exceeded'),@('tool_dispatch','(?i)WrappedMcpExecute|tool.*dispatch'),@('runtime_startup','(?i)initializ|startup|Runtime diagnostics log:'),@('provider_http_failure','(?i)HTTP\s*(?:status\s*)?[:=]?\s*[45]\d{2}'))){if($body -match $signature[1]){$tags.Add($signature[0])}}
        $codes=New-Object Collections.Generic.List[object]
        foreach($match in [regex]::Matches($body,'(?i)\b(?<domain>HRESULT|Win32(?:[_ -]error)?|exception(?:[_ -]code)?)\s*[:=]?\s*(?<code>0x[0-9a-f]{8}|\d{1,10})\b')){
            $number=if($match.Groups['code'].Value -match '^0x'){[Convert]::ToInt64($match.Groups['code'].Value.Substring(2),16)}else{[long]$match.Groups['code'].Value}
            if($number -le [uint32]::MaxValue){$domain=if($match.Groups['domain'].Value -match '(?i)^Win32'){'Win32'}elseif($match.Groups['domain'].Value -match '(?i)^HRESULT'){'HRESULT'}else{'exception'};$codes.Add([pscustomobject]@{domain=$domain;code=('0x{0:X8}' -f $number)})}
            if($codes.Count -ge 4){break}
        }
        $http=@([regex]::Matches($body,'(?i)\bHTTP(?:/[12](?:\.\d)?)?\s*(?:status\s*)?[:=]?\s*(?<code>[1-5]\d{2})\b')|Select-Object -First 2|ForEach-Object{[int]$_.Groups['code'].Value})
        $level=$header.Groups['level'].Value
        if(-not $tags.Count -and -not $codes.Count -and -not $http.Count -and $level -notin @('ERROR','FATAL')){continue}
        $location=$null;$loc=[regex]::Match($body,'^\s*(?<file>assistant_api\.cc|winhttp_client\.cc|webview_impl\.cc|plugin_loader\.cpp|assistant_app\.cpp|app_runtime\.cc|logger\.cc):(?<line>\d{1,8})\b')
        if($loc.Success){$location=@{file=$loc.Groups['file'].Value;line=[int]$loc.Groups['line'].Value}}
        if($records.Count -eq 24){$records.RemoveAt(0)}
        $records.Add([pscustomobject]@{level=$level;timeToken=$header.Groups['time'].Value;timeBasis='host_local_or_unspecified; CLI HHMMSS has no date';signatureTags=$tags.ToArray();nativeCodes=$codes.ToArray();httpStatusCodes=$http;sourceLocation=$location;correlation='unverified_record_text_only';messageBodyIncluded=$false})
    }
    $records.ToArray()
}
function Get-GdiagCrashLogEvidence {
    param($Context,$Target,[hashtable]$Options=@{})
    $root=$Target.payloadRoot;if(-not $root){$root=$Target.path}
    if($Target.family -eq 'GstarAssistant' -and $root){
        try{
            $file=Assert-GdiagPlainPath (Join-Path $root '.env');$settings=Get-GdiagLogSettings $file
            $executor=[Environment]::GetEnvironmentVariable('GSTAR_LOG_LEVEL','Process')
            $safeExecutor=if(-not $executor){'not_set'}elseif($executor.ToLowerInvariant() -in @('trace','debug','info','warn','warning','error','fatal','off','none','silent')){$executor.ToLowerInvariant()}else{'invalid'}
            [pscustomobject]@{source='crash.log-level';targetId=$Target.id;status='observed';summary=@{fileLevel=$settings.level;duplicateLevelAssignments=$settings.duplicateLevelAssignments;executorLevel=$safeExecutor;effectiveHostLevel='unverified';processEnvironmentPrecedence='existing process variable wins over .env';restart='required for startup-file change';compileFloor='reviewed source defaults TRACE; installed build flags unknown';cliTraceSwitch='unsupported; CLI and agent JSON parsers do not accept TRACE'};observed=@{path=$file;source='gbase/src/base/log_config.cc; gbase/include/base/logger.h; GstarAssistant assistant_app.cpp loadStartupEnvironmentFile'}}
        }catch{[pscustomobject]@{source='crash.log-level';targetId=$Target.id;status='collection_error';summary=@{nativeErrorCode=$_.Exception.HResult;nextAction='Inspect selected startup configuration access locally.'}}}
    }
    $paths=@($Options.logPaths | Where-Object {$_})
    if(-not $paths.Count -and $Target.release -match '^R(26|27)$' -and $Context.profilePath){$paths=@(Join-Path $Context.profilePath ('AppData/Local/GstarAssistant/20'+$matches[1]+'/logs/assistant.log'))}
    if($paths.Count -gt 16){throw 'Select at most 16 log files per crash investigation.'}
    foreach($path in $paths){
        $stream=$null;$reader=$null
        try{
            $path=Assert-GdiagPlainPath $path
            if(-not(Test-Path -LiteralPath $path -PathType Leaf)){[pscustomobject]@{source='crash.agent-log';targetId=$Target.id;status='absent';summary=@{effectiveRoot='unverified';nextAction='Resolve actual host state root and log sink; absence does not prove no failure.'};observed=@{path=$path}};continue}
            $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
            $tail=[Math]::Min(65536,$stream.Length);[void]$stream.Seek(-$tail,[IO.SeekOrigin]::End)
            $buffer=New-Object byte[] ([int]$tail);$read=0
            while($read -lt $buffer.Length){$n=$stream.Read($buffer,$read,$buffer.Length-$read);if(-not $n){break};$read+=$n}
            $text=[Text.Encoding]::UTF8.GetString($buffer,0,$read)
            $counts=[ordered]@{};foreach($level in @('TRACE','DEBUG','INFO','WARN','ERROR','FATAL')){$counts[$level.ToLowerInvariant()+'Count']=[regex]::Matches($text,'(?m)^(?:\[[0-9TZ:+ .-]+\])?\['+$level+'\s*\]').Count}
            $markers=[ordered]@{};foreach($pattern in @(@('native_exception','(?i)access.violation|0xc0000005|stack.overflow|terminate called'),@('python_exception','(?i)Traceback \(most recent call last\)|Python.*exception'),@('timeout','(?i)timed? ?out|deadline exceeded'),@('tool_dispatch','(?i)WrappedMcpExecute|tool.*dispatch'),@('startup','(?i)initializ|startup|Runtime diagnostics log:'))){$markers[$pattern[0]]=[regex]::Matches($text,$pattern[1]).Count}
            [pscustomobject]@{source='crash.agent-log';targetId=$Target.id;status=$(if($stream.Length -gt $tail){'truncated'}else{'observed'});summary=@{tailBytes=$tail;levels=$counts;markers=$markers;technicalEvents=@(Get-GdiagLogTechnicalEvents $text);traceObserved=($counts.traceCount -gt 0);cause='unresolved';incidentCorrelation='timestamps/process identity must be matched to the selected incident; TRACE counts do not establish incident association';contentInPublicOutput=$false};observed=@{path=$path;content=$text}}
        }catch{
            $exception=$_.Exception;while($exception.InnerException){$exception=$exception.InnerException}
            [pscustomobject]@{source='crash.agent-log';targetId=$Target.id;status=$(if(($exception.HResult -band 65535) -eq 5){'access_denied'}else{'collection_error'});summary=@{nativeErrorCode=$exception.HResult;cause='unresolved'}}
        }finally{if($reader){$reader.Dispose()}elseif($stream){$stream.Dispose()}}
    }
}
function New-GdiagTracePlan {
    param($Context,$Target,[hashtable]$Options)
    if($Target.family -ne 'GstarAssistant' -or $Target.release -notin @('R26','R27') -or $Options.loggingContract -ne 'gstar-startup-env-v1'){throw 'Select a reviewed GstarAssistant target and loggingContract=gstar-startup-env-v1.'}
    if($Context.executorSid -ne $Context.affectedSid){throw 'TRACE startup changes require affected-user execution.'}
    $case=Read-GdiagJson (Join-Path $Context.casePath 'case.json');$hosts=@($case.targets|Where-Object {$_.id -eq $Options.hostTargetId -and $_.family -eq 'GstarCAD' -and $_.release -eq $Target.release})
    if($hosts.Count -ne 1){throw 'Select exactly one same-case/same-release GstarCAD host.'}
    $root=$Target.payloadRoot;if(-not $root){$root=$Target.path};$path=Assert-GdiagPlainPath (Join-Path $root '.env')
    $settings=Get-GdiagLogSettings $path
    if($settings.duplicateLevelAssignments -gt 1){throw 'Duplicate startup log-level assignments require focused reconciliation first.'}
    $before=Get-GdiagFileHash $path;$text=if($before){[IO.File]::ReadAllText($path)}else{''}
    $encoding=Get-GdiagTraceEncoding $path
    $after=Get-GdiagTraceText $text ($encoding.GetPreamble().Length -gt 0)
    # Exact bytes stay local; the plan exposes only hashes and intended setting.
    $id=[guid]::NewGuid().ToString();$desired=Join-Path $Context.casePath ($id+'.trace-config');[IO.File]::WriteAllText((Assert-GdiagPlainPath $desired),$after,$encoding)
    [pscustomobject]@{schemaVersion=1;planId=$id;caseId=$Context.caseId;casePath=$Context.casePath;machine=$Context.machine;executorSid=$Context.executorSid;affectedSid=$Context.affectedSid;target=$Target;operation='Repair';recipe='trace-logging';status='planned';destination=$Target.path;configPath=$path;beforeHash=$before;afterHash=(Get-GdiagFileHash $desired);desiredPath=$desired;hostTarget=$hosts[0];previousLevel=$settings.level;requestedLevel='TRACE';reversible=$true;privilege='affected-user';restartRequired=$true;captureSeconds=120;verification='TRACE requested in startup file; effective host level and compile floor require restart and actual TRACE evidence.';changes=@(@{path=$path;setting='GSTAR_LOG_LEVEL';value='TRACE'});limits=@('Close only the selected host normally before Apply; do not terminate customer drawings.','Existing process environment wins over startup file. Installed compile flags may remove TRACE sites.','TRACE/DEBUG can enable LLM request/response logging and contain prompts, code or credentials; keep raw evidence local and bound reproduction.','Undo restores exact original startup bytes/absence only if the file is unchanged; a running host can remain at TRACE until normal restart.');restoreAfterCapture=$true}
}
function Invoke-GdiagTracePlan {
    param($Plan,[ValidateSet('Apply','Verify','Undo')][string]$Mode,[string]$PlanDirectory)
    $p=$Plan;$path=Assert-GdiagPlainPath $p.configPath
    $case=Read-GdiagJson (Join-Path $PlanDirectory 'case.json');$saved=@($case.targets|Where-Object {$_.id -eq $p.target.id -and $_.family -eq 'GstarAssistant' -and $_.path -eq $p.target.path -and $_.release -eq $p.target.release})
    if($saved.Count -ne 1 -or $saved[0].payloadRoot -ne $p.target.payloadRoot){throw 'TRACE payload identity differs from the saved case.'}
    $root=$saved[0].payloadRoot;if(-not $root){$root=$saved[0].path}
    if($p.recipe -ne 'trace-logging' -or $p.operation -ne 'Repair' -or $p.target.family -ne 'GstarAssistant' -or $p.target.release -notin @('R26','R27') -or $path -ne [IO.Path]::GetFullPath((Join-Path $root '.env')) -or $p.requestedLevel -ne 'TRACE'){throw 'Invalid typed TRACE startup plan.'}
    $selectedHosts=@($case.targets|Where-Object {$_.id -eq $p.hostTarget.id -and $_.path -eq $p.hostTarget.path -and $_.family -eq 'GstarCAD' -and $_.release -eq $p.target.release})
    if($selectedHosts.Count -ne 1){throw 'TRACE host identity no longer matches the selected case.'}
    $desired=Assert-GdiagPlainPath $p.desiredPath
    if($desired -ne (Join-Path $PlanDirectory ($p.planId+'.trace-config'))){throw 'TRACE config staging must remain case-local.'}
    $statePath=Join-Path $PlanDirectory ($p.planId+'.state.json');$backup=Assert-GdiagPlainPath (Join-Path $PlanDirectory ($p.planId+'.trace-original'))
    $state=$null;if(Test-Path -LiteralPath $statePath){$state=Read-GdiagJson $statePath}
    $r=[ordered]@{status='started';mode=$Mode;planId=$p.planId;restartRequired=$true;runtimeVerification='pending_restart_and_TRACE_evidence';hostVerification='pending';requestedLevel='TRACE'}
    try{
        if($Mode -eq 'Apply'){
            if($state){throw 'Prior TRACE action exists; inspect or Undo before replanning.'}
            Assert-GdiagAutomationIdle $p.hostTarget.path @('gcad','gstarcad')
            if((Get-GdiagFileHash $path) -ne $p.beforeHash -or (Get-GdiagFileHash $desired) -ne $p.afterHash){throw 'TRACE plan configuration precondition changed.'}
            [void](Get-GdiagLogSettings $path)
            $currentText=if($p.beforeHash){[IO.File]::ReadAllText($path)}else{''}
            $encoding=Get-GdiagTraceEncoding $path;$expected=Get-GdiagTraceText $currentText ($encoding.GetPreamble().Length -gt 0);$hasher=[Security.Cryptography.SHA256]::Create()
            $expectedBytes=[byte[]]($encoding.GetPreamble()+$encoding.GetBytes($expected))
            try{$expectedHash=([BitConverter]::ToString($hasher.ComputeHash($expectedBytes))).Replace('-','')}finally{$hasher.Dispose()}
            if($expectedHash -ne $p.afterHash){throw 'TRACE plan contains changes beyond the single supported logging setting.'}
            if(Test-Path -LiteralPath $backup){throw 'TRACE original recovery path already exists.'}
            $state=[pscustomobject]@{planId=$p.planId;status='started';originalHash=$p.beforeHash;backup=$backup;afterHash=$p.afterHash};Write-GdiagLifeJson $statePath $state
            if($p.beforeHash){Copy-Item -LiteralPath $path -Destination $backup -ErrorAction Stop}
            Copy-Item -LiteralPath $desired -Destination $path -ErrorAction Stop
            $state.status='applied';Write-GdiagLifeJson $statePath $state;$r.status='applied';$r.componentVerification='startup_config_TRACE_requested'
        }elseif($Mode -eq 'Verify'){
            if(-not $state -or $state.status -ne 'applied' -or (Get-GdiagFileHash $path) -ne $p.afterHash){throw 'TRACE startup configuration is not in the applied state.'}
            $r.status='verified';$r.componentVerification='startup_config_only';$r.nextAction='Restart selected host normally, reproduce briefly, inspect actual TRACE records, then restore via Undo.'
        }else{
            if(-not $state -or $state.status -notin @('applied','started') -or $state.planId -ne $p.planId -or $state.backup -ne $backup -or $state.originalHash -ne $p.beforeHash -or $state.afterHash -ne $p.afterHash){throw 'Undo requires the matching original TRACE action state.'}
            $currentHash=Get-GdiagFileHash $path
            $originalPresent=if($state.originalHash){$currentHash -eq $state.originalHash}else{-not(Test-Path -LiteralPath $path)}
            if(-not $originalPresent -and $currentHash -ne $state.afterHash){throw 'Undo preserves intervening or partially written TRACE bytes; inspect the private original and current file locally before manual recovery.'}
            if(-not $originalPresent){
                if($state.originalHash){if((Get-GdiagFileHash $backup) -ne $state.originalHash){throw 'TRACE original backup changed.'};Copy-Item -LiteralPath $backup -Destination $path -ErrorAction Stop}else{Remove-Item -LiteralPath $path -ErrorAction Stop}
            }
            if((Get-GdiagFileHash $path) -ne $state.originalHash -or (-not $state.originalHash -and (Test-Path -LiteralPath $path))){throw 'Original TRACE configuration restoration could not be verified.'}
            $r.recoveredInterruptedAction=($state.status -eq 'started')
            $state.status='undone';Write-GdiagLifeJson $statePath $state;$r.status='undone';$r.componentVerification='original_startup_config_restored';$r.runtimeVerification='running_process_may_remain_TRACE_until_normal_restart'
        }
    }catch{$r.status='failed';$r.error=$_.Exception.Message}
    [pscustomobject]$r
}
