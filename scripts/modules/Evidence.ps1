$script:GdiagVersion = '0.1.0'
function Assert-GdiagPlainPath($Path) {
    $full=[IO.Path]::GetFullPath($Path);$cursor=$full
    while($cursor){
        if(Test-Path -LiteralPath $cursor){if((Get-Item -LiteralPath $cursor -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse-point mutation boundary refused.'}}
        $parent=Split-Path -Parent $cursor;if($parent -eq $cursor){break};$cursor=$parent
    }
    $full
}
function Write-GdiagJson($Path, $Value) {
    $json = ConvertTo-Json -InputObject $Value -Depth 40
    [IO.File]::WriteAllText((Assert-GdiagPlainPath $Path), $json, (New-Object Text.UTF8Encoding($false)))
}
function Read-GdiagJson($Path) {
    if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 33554432) {throw 'JSON evidence exceeds the 32 MiB input bound; select a smaller case/query.'}
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}
function Get-GdiagPseudonym([string]$Text,[string]$Prefix) {
    $hash=[Security.Cryptography.SHA256]::Create()
    try {$digest=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text.ToLowerInvariant())))).Replace('-','').Substring(0,12);return "$Prefix-$digest"}
    finally {$hash.Dispose()}
}
function Get-GdiagIntegrity {
    try {
        if (-not ('GdiagTokenIntegrity' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class GdiagTokenIntegrity {
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr buffer, int size, out int needed);
  [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
  [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  public static int Read(IntPtr process) {
    IntPtr token;
    if (!OpenProcessToken(process, 8, out token)) throw new System.ComponentModel.Win32Exception();
    IntPtr buffer=IntPtr.Zero;
    try {
      int needed; GetTokenInformation(token,25,IntPtr.Zero,0,out needed);
      if (needed<=0) throw new System.ComponentModel.Win32Exception();
      buffer=Marshal.AllocHGlobal(needed);
      if (!GetTokenInformation(token,25,buffer,needed,out needed)) throw new System.ComponentModel.Win32Exception();
      IntPtr sid=Marshal.ReadIntPtr(buffer);
      byte count=Marshal.ReadByte(GetSidSubAuthorityCount(sid));
      return Marshal.ReadInt32(GetSidSubAuthority(sid,(uint)(count-1)));
    } finally { if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer); CloseHandle(token); }
  }
}
'@ -ErrorAction Stop | Out-Null
        }
        $level=[GdiagTokenIntegrity]::Read((Get-Process -Id $PID).Handle)
        @{status='observed';rid=$level;label=$(if($level -lt 4096){'untrusted'}elseif($level -lt 8192){'low'}elseif($level -lt 12288){'medium'}elseif($level -lt 16384){'high'}else{'system_or_protected'})}
    } catch { @{status='unavailable';hresult=$_.Exception.HResult;nextAction='Token integrity inspection blocked; administrator membership alone does not establish elevation.'} }
}
function Protect-GdiagText([string]$Text) {
    # Redact whole assignments (including space-bearing secrets), headers and URL credentials.
    $Text = [regex]::Replace($Text, '(?im)(authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)(["\s]*[:=]["\s]*)([^\r\n,}]+)', '$1$2[REDACTED]')
    $Text = [regex]::Replace($Text, '(?i)\b(Bearer|Basic)\s+[A-Za-z0-9+/=_\.\-]+', '$1 [REDACTED]')
    $Text = [regex]::Replace($Text, '(?i)\bsk-[A-Za-z0-9_-]{8,}', '[REDACTED]')
    $Text = [regex]::Replace($Text, '(https?://)[^/\s:@]+:[^/\s@]+@', '$1[REDACTED]@')
    $Text = [regex]::Replace($Text, '(?i)([?&](?:token|key|sig|code)=)[^&\s"\\]+', '$1[REDACTED]')
    $Text = [regex]::Replace($Text, '[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '[EMAIL]')
    $Text = [regex]::Replace($Text, '(?i)([A-Z]:[/\\](?:Users|Documents and Settings)[/\\])([^/\\"\r\n]+)', {param($m) if($m.Groups[2].Value -match '^\[user-[0-9A-F]{12}\]$'){$m.Value}else{$m.Groups[1].Value+'['+(Get-GdiagPseudonym $m.Groups[2].Value 'user')+']'}})
    $Text = [regex]::Replace($Text, 'S-1-5-21-(?:\d+-){2}\d+-\d+', {param($m) Get-GdiagPseudonym $m.Value 'sid'})
    return $Text
}
function ConvertTo-GdiagPublic($Value) {
    # Use a conservative structured projection: free-form logs/errors/configuration never leave local evidence.
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return Protect-GdiagText $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $r = [ordered]@{}
        foreach ($key in $Value.Keys) {
            if ($key -match '(?i)^(raw|message|xml|stdout|stderr|content|arguments|environment|observed|data|error|details)$') { $r[$key] = '[LOCAL DETAIL OMITTED]' }
            elseif ($key -match '(?i)(password|secret|token|cookie|authorization)') { $r[$key] = '[REDACTED]' }
            elseif ($key -eq 'machine' -and $Value[$key]) {$r[$key]=if($Value[$key] -match '^machine-[0-9A-F]{12}$'){$Value[$key]}else{Get-GdiagPseudonym ([string]$Value[$key]) 'machine'}}
            else { $r[$key] = ConvertTo-GdiagPublic $Value[$key] }
        }
        return $r
    }
    if ($Value -is [System.Collections.IEnumerable]) { return ,@($Value | ForEach-Object { ConvertTo-GdiagPublic $_ }) }
    if ($Value -is [pscustomobject]) {
        $r = [ordered]@{}; foreach ($p in $Value.PSObject.Properties) { $r[$p.Name] = $p.Value }
        return ConvertTo-GdiagPublic $r
    }
    return $Value
}
function Get-GdiagContext([string]$AffectedSid, [string]$CasePath) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $identity.User.Value
    $explicitAffectedUser=[bool]$AffectedSid
    if (-not $AffectedSid) { $AffectedSid = $sid }
    $AffectedSid=(New-Object Security.Principal.SecurityIdentifier($AffectedSid)).Value
    $profilePath = $env:USERPROFILE
    $profileStatus='executor_profile';$profileError=$null
    if ($AffectedSid -ne $sid) {
        $profilePath = $null
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$AffectedSid")
            if ($key) { try { $profilePath = $key.GetValue('ProfileImagePath');$profileStatus='registered_profile_candidate' } finally { $key.Dispose() } }
            else {$profileStatus='unavailable'}
        } catch {$profileStatus='access_unavailable';$profileError=$_.Exception.HResult}
    }
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $process = Get-Process -Id $PID
    return @{ machine=[Environment]::MachineName; executorSid=$sid; affectedSid=$AffectedSid; profilePath=$profilePath;
        casePath=$CasePath; caseId=[guid]::NewGuid().ToString(); startUtc=[DateTime]::UtcNow.AddHours(-2).ToString('o'); endUtc=[DateTime]::UtcNow.ToString('o');
        powershell=$PSVersionTable.PSVersion.ToString();profileStatus=$profileStatus;profileError=$profileError; processArchitecture=$(if ([Environment]::Is64BitProcess) {'x64'} else {'x86'});
        osArchitecture=$(if ([Environment]::Is64BitOperatingSystem) {'x64'} else {'x86'}); osVersion=[Environment]::OSVersion.Version.ToString();
        timeZoneId=[TimeZoneInfo]::Local.Id;utcOffsetMinutes=[TimeZoneInfo]::Local.GetUtcOffset([datetime]::Now).TotalMinutes;localDateAtCollection=[datetime]::Now.ToString('yyyy-MM-dd');
        elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); integrity=(Get-GdiagIntegrity); sessionId=$process.SessionId;
        userSelection=$(if(-not $explicitAffectedUser){'executor_default_confirm_affected_user'}elseif($sid -eq $AffectedSid){'explicit_same_user'}else{'explicit_other_user'});
        executionPolicy=@(Get-ExecutionPolicy -List | Select-Object @{Name='scope';Expression={$_.Scope.ToString()}},@{Name='policy';Expression={$_.ExecutionPolicy.ToString()}}) }
}
function Add-GdiagObservations($Document, $Items) {
    $ids=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach($existing in @($Document.observations)){if($existing.id){[void]$ids.Add([string]$existing.id)}}
    $nextId=1
    foreach ($item in @($Items)) {
        if ($null -eq $item) { continue }
        while($ids.Contains('evidence-'+$nextId)){$nextId++}
        $id='evidence-'+$nextId;[void]$ids.Add($id)
        $record = [ordered]@{ id=$id; timeUtc=[DateTime]::UtcNow.ToString('o') }
        if ($item -is [System.Collections.IDictionary]) { foreach ($k in $item.Keys) {if($k -ne 'id'){$record[$k]=$item[$k]}} }
        else {foreach ($p in $item.PSObject.Properties) {if($p.Name -ne 'id'){$record[$p.Name] = $p.Value}}}
        $Document.observations = @($Document.observations) + [pscustomobject]$record
    }
}
function Get-GdiagComparisonRecords($Document,[bool]$IncludePaths) {
    foreach ($target in @($Document.targets)) {
        $record=[ordered]@{kind='target';family=$target.family;release=$target.release;locale=$target.locale;
            view=$target.registry.view;hive=$target.registry.hive;architecture=$target.file.architecture;fileVersion=$target.file.fileVersion;
            fileStatus=$target.file.status;registered=$target.registered;expectationStatus=$target.expectationStatus;
            missingPayload=@($target.payload.missing | Where-Object {$_})}
        if ($IncludePaths) { $record.path=$target.path }
        ConvertTo-GdiagPublic $record | ConvertTo-Json -Depth 15 -Compress
    }
    foreach ($observation in @($Document.observations)) {
        $summary=$observation.summary; if (-not $summary) {$summary=$observation.publicSummary}
        $record=[ordered]@{kind='observation';source=$observation.source;status=$observation.status}
        $associatedTarget=@($Document.targets | Where-Object {$observation.targetId -and $_.id -eq $observation.targetId})
        if ($associatedTarget.Count -eq 1) {$record.target=[ordered]@{family=$associatedTarget[0].family;release=$associatedTarget[0].release;locale=$associatedTarget[0].locale;hive=$associatedTarget[0].registry.hive;view=$associatedTarget[0].registry.view}}
        foreach($key in @('stage','exitCode','nativeErrorDomain','nativeErrorCode','hresult','httpStatus','authentication','probeStatus','initialize','discovery')) {
            if($summary -and $null -ne $summary.$key) {$record[$key]=$summary.$key}
        }
        ConvertTo-GdiagPublic $record | ConvertTo-Json -Depth 15 -Compress
    }
}
function Write-GdiagReport($Document, $Path) {
    $public = ConvertTo-GdiagPublic $Document
    $findings=@($public.findings | Where-Object {$_})
    $priorityFindings=@($findings | Sort-Object @{Expression={switch($_.confidence){'confirmed'{0}'hypothesis'{1}default{2}}}})
    $gaps=@($public.observations | Where-Object {$_.status -in @('access_denied','unavailable','unknown','collection_error','disabled','timeout','truncated','host_verification_pending','host_selection_unresolved','partial_stack','no_exception_context','invalid_dump','probe_failed','busy','io_error','schema_mismatch')})
    $confirmed=@($findings | Where-Object confidence -eq 'confirmed')
    $changes=@($public.changes | Where-Object {$_})
    $dumpAnalyses=@($public.observations | Where-Object source -eq 'crash.dump_analysis')
    $crashRelated=($public.isCrashCase -or $public.profile -eq 'Crash' -or $dumpAnalyses.Count -gt 0 -or $public.symptom -match '(?i)crash|hang|0xc0000005|access.?violation|\u5d29\u6e83|\u95ea\u9000|\u65e0\u54cd\u5e94')
    $outcome=if($confirmed.Count){'Findings need follow-up.'}elseif($gaps.Count){'Diagnostics collected with unresolved checks.'}else{'Diagnostics collected; component and host readiness require the relevant verification.'}
    $symptom=if($public.symptom){[Net.WebUtility]::HtmlEncode([string]$public.symptom)}elseif($crashRelated){'Crash investigation; customer symptom details were not supplied.'}else{'Environment/readiness check'}
    $lines=@('# GCAD diagnostic report','',('Generated UTC: '+[datetime]::UtcNow.ToString('o')),('Case: '+[Net.WebUtility]::HtmlEncode([string]$public.caseId)),
        '', '## Summary','', $outcome,('Requested check: '+$symptom),
        ('Scope: {0}; {1} installation/component candidates; {2} evidence records.' -f $public.profile,@($public.targets).Count,@($public.observations).Count),
        ('Maintenance: '+$(if($changes.Count){'Activity recorded; see changes and verification below.'}else{'No maintenance action recorded.'})),
        'Collection success is separate from environment health and original symptom recovery.')
    if($dumpAnalyses.Count){
        $latestDump=@($dumpAnalyses|Select-Object -Last 1)[0]
        $lines+=('Crash evidence: exception {0}; thread {1}; {2} recovered frames; analysis {3}; incident association {4}; root cause unresolved.' -f $latestDump.summary.exceptionCode,$latestDump.summary.exceptionThreadId,@($latestDump.stackFrames).Count,$latestDump.status,$latestDump.summary.association)
    }elseif($crashRelated){$lines+='Crash callstack: unavailable until a relevant dump with exception context is analyzed. See the callstack section and missing evidence below.'}
    if($public.context.startUtc -and $public.context.endUtc){$lines+=('Selected evidence window UTC: {0} to {1}.' -f $public.context.startUtc,$public.context.endUtc)}
    if($public.context.userSelection -eq 'executor_default_confirm_affected_user'){$lines+=@('', 'Affected user is unconfirmed. The collector recorded its executor account; confirm the customer account before using per-user findings for repair.')}
    if($public.capture.traceRestoreRequired){$lines+=@('', 'TRACE restoration needs review on the customer machine. Inspect the original plan and current startup setting; an interrupted capture or intervening edit must not silently leave verbose logging enabled. A running host may require a normal restart after restoration.')}
    $lines+=@('', '## Main findings','')
    if(-not $findings.Count){$lines+='No findings have been established from this evidence yet.'}
    foreach($finding in @($priorityFindings | Select-Object -First 5)) {
        $targetLabel=if($finding.targetId){$finding.targetId}else{'target not yet attributed'}
        $lines+=('- {0}: {1} ({2}; {3})' -f $finding.confidence,([Net.WebUtility]::HtmlEncode([string]$finding.symptom)),$targetLabel,$finding.id)
    }
    $lines+=@('', '## Recommended next steps','')
    if($public.context.userSelection -eq 'executor_default_confirm_affected_user'){$lines+='- Confirm the affected Windows user and intended release/installation.'}
    $nextActions=@($priorityFindings | ForEach-Object {$_.nextAction} | Where-Object {$_} | Select-Object -Unique -First 5)
    foreach($next in $nextActions){$lines+=('- '+[Net.WebUtility]::HtmlEncode([string]$next))}
    if(-not $nextActions.Count){$lines+='- Select the relevant installation/component and collect the missing evidence before choosing a repair.'}
    if($crashRelated){
        $lines+=@('', '## Crash log analysis','')
        $levelChecks=@($public.observations|Where-Object source -eq 'crash.log-level')
        foreach($check in $levelChecks){$lines+=('- {0}: startup log level {1}; effective host level {2}; evidence {3}.' -f $check.targetId,$check.summary.fileLevel,$check.summary.effectiveHostLevel,$check.id)}
        $logChecks=@($public.observations|Where-Object source -eq 'crash.agent-log')
        foreach($check in $logChecks){
            $lines+=('- {0}: {1}; TRACE {2}, ERROR {3}, FATAL {4}; evidence {5}. Timestamp/process correlation remains required.' -f $check.targetId,$check.status,$check.summary.levels.traceCount,$check.summary.levels.errorCount,$check.summary.levels.fatalCount,$check.id)
            foreach($technical in @($check.summary.technicalEvents | Select-Object -First 8)){
                if($technical){$line=$technical|ConvertTo-Json -Depth 8 -Compress;$lines+=('  Technical event: '+[Net.WebUtility]::HtmlEncode($line))}
            }
        }
        if(-not $levelChecks.Count -and -not $logChecks.Count){$lines+='No selected product log-level or agent-log evidence has been collected in this case.'}
        $lines+=@('', '## Crash callstack','')
        if(-not $dumpAnalyses.Count){$lines+='No minidump has been analyzed. A reliable callstack is unavailable; collect an existing relevant dump through the agreed support channel and run offline DumpAnalysis. Event fault-module names and log text are not substitutes for stack frames.'}
        foreach($analysis in $dumpAnalyses){
            $lines+=('Dump: {0}; evidence: {1}; analysis status: {2}.' -f $analysis.dumpMetadata.fileName,$analysis.id,$analysis.status)
            $lines+=('Exception: {0}; exception thread: {1}; architecture: {2}; symbols: {3}.' -f $analysis.summary.exceptionCode,$analysis.summary.exceptionThreadId,$analysis.summary.architecture,$analysis.summary.symbols)
            if($analysis.summary.dumpTimestampUtc){$lines+=('Dump header timestamp UTC: '+$analysis.summary.dumpTimestampUtc)}
            $frames=@($analysis.stackFrames | Where-Object {$_})
            if($frames.Count){
                $lines+=@('', '| Frame | Module | Callsite/symbol | Instruction | Displacement | Symbol status |','| --- | --- | --- | --- | --- | --- |')
                foreach($frame in $frames){
                    $cells=@($frame.index,$frame.module,$frame.symbol,$frame.instruction,$frame.displacement,$frame.symbolStatus)|ForEach-Object {([Net.WebUtility]::HtmlEncode([string]$_)).Replace('|','&#124;').Replace("`n",' ')}
                    $lines+=('| '+($cells -join ' | ')+' |')
                }
                $lines+=@('', 'These are recovered exception-context frames. Missing private/managed symbols and module-only offsets remain explicit; a frame alone does not establish root cause.')
            }else{$lines+=('Callstack not recovered: {0}. {1}' -f $analysis.summary.stackStatus,$analysis.summary.nextAction)}
            $lines+=''
        }
    }
    $lines+=@('', '## Checks still unresolved','')
    if(-not $gaps.Count){$lines+='No explicit collection gaps were recorded. This does not prove untested components are healthy.'}
    foreach($gap in @($gaps | Select-Object -First 8)){$lines+=('- {0}: {1}; target: {2}; evidence: {3}.' -f $gap.source,$gap.status,$gap.targetId,$gap.id)}
    if($gaps.Count -gt 8){$lines+=('{0} additional unresolved records appear in the detailed evidence below.' -f ($gaps.Count-8))}
    $machineLabel=if($public.context.machine){$public.context.machine}else{'not collected'}
    $executorLabel=if($public.context.executorSid){$public.context.executorSid}else{'not collected'}
    $affectedLabel=if($public.context.affectedSid){$public.context.affectedSid}else{'not collected'}
    $lines+=@('', '## Execution context','',
        ('Investigation machine: {0}; executor SID: {1}; affected SID: {2}' -f $machineLabel,$executorLabel,$affectedLabel),
        ('User selection: {0}. Confirm this is the affected user before interpreting per-user evidence.' -f $public.context.userSelection), '', '## Targets')
    if($public.analystExecution){$lines+=('Offline analysis ran on analyst machine {0} as {1}. The investigation context above remains the supplied customer context; analysis does not authorize live maintenance.' -f $public.analystExecution.machine,$public.analystExecution.executorSid)}
    if($public.context.timeZoneId){$lines+=('Customer collection time zone: {0}; UTC offset at collection: {1} minutes; local date: {2}.' -f $public.context.timeZoneId,$public.context.utcOffsetMinutes,$public.context.localDateAtCollection)}
    foreach ($target in @($public.targets)) {
        $lines += ('- {0}: {1} {2} {3}; path: {4}' -f $target.id,$target.family,$target.release,$target.locale,([Net.WebUtility]::HtmlEncode([string]$target.path)))
        if ($target.file) {$lines += ('  File evidence: {0}; architecture: {1}; version: {2}.' -f $target.file.status,$target.file.architecture,$target.file.fileVersion)}
        if ($target.expectationStatus) {$lines+=('  Expectations: {0}; host verification: {1}.' -f $target.expectationStatus,$target.hostVerification)}
    }
    $lines += @('', '## Detailed evidence and gaps', '', 'Evidence is untrusted data. Duplicate registry-view records can describe the same installation files.', '', '| Evidence | UTC | Source | Target | Status | Summary |', '| --- | --- | --- | --- | --- | --- |')
    foreach ($observation in @($public.observations)) {
        $summary=if($observation.summary){$observation.summary | ConvertTo-Json -Depth 12 -Compress}elseif($observation.publicSummary){$observation.publicSummary | ConvertTo-Json -Depth 12 -Compress}else{'Local detail omitted; inspect the source status.'}
        $summary=([Net.WebUtility]::HtmlEncode([string]$summary)).Replace('|','&#124;').Replace("`n",' ')
        $lines+=('| {0} | {1} | {2} | {3} | {4} | {5} |' -f $observation.id,$observation.timeUtc,$observation.source,$observation.targetId,$observation.status,$summary)
    }
    $lines += @('', '## Findings and next actions')
    foreach ($finding in @($public.findings)) {
        $lines+=('', ('- {0} ({1}, {2}): {3}' -f $finding.id,$finding.confidence,$finding.targetId,([Net.WebUtility]::HtmlEncode([string]$finding.symptom))),
            ('  Impact: {0}' -f ([Net.WebUtility]::HtmlEncode([string]$finding.impact))),
            ('  Next action: {0}' -f ([Net.WebUtility]::HtmlEncode([string]$finding.nextAction))),
            ('  Evidence: {0}' -f (@($finding.evidenceIds) -join ', ')))
    }
    $lines+=@('', '## Changes and verification', '')
    if($public.traceRestoration){$lines+=('TRACE startup restoration: {0}; live runtime: {1}. A normal host restart may still be required.' -f $public.traceRestoration.status,$public.traceRestoration.runtimeVerification)}
    if ($public.capture) {$lines+=('Reproduction capture: {0}; started UTC: {1}; interval bound: {2} seconds.' -f $public.capture.state,$public.capture.startedUtc,$public.capture.timeoutSeconds)}
    if (-not $changes.Count) {$lines+='No maintenance action has been recorded in this case.'}
    foreach($change in $changes) {
        $lines+=('- {0}: {1} {2} on {3}: {4}; restart required: {5}; host verification: {6}; plan: {7}.' -f $change.timeUtc,$change.operation,$change.mode,$change.targetId,$change.status,$change.restartRequired,$change.hostVerification,$change.planId)
        if($null -ne $change.nativeExitCode){$lines+=('  Native installer exit: '+$change.nativeExitCode)}
        foreach($field in @('componentVerification','runtimeVerification','prerequisiteRebootStatus','readiness')) {if($change.$field){$lines+=('  {0}: {1}' -f $field,$change.$field)}}
        if ($change.nextAction) {$lines+=('  Next action: '+$change.nextAction)}
    }
    $lines += @('', 'Raw messages and configuration stay in local case.json. Review locally before sharing additional details. No target mutation is authorized by reading a case.')
    [IO.File]::WriteAllLines((Assert-GdiagPlainPath $Path), $lines, (New-Object Text.UTF8Encoding($false)))
}
