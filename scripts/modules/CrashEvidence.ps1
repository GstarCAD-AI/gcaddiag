# Read-only bounded crash evidence. Dump bytes and free-form WER data stay local.
# LocalDumps contract: https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps
function New-GdiagCrashObservation($Source,$Status,$Summary,$Observed,$TargetId) {
    [pscustomobject]@{source=$Source;status=$Status;summary=$Summary;observed=$Observed;targetId=$TargetId;timeUtc=[datetime]::UtcNow.ToString('o')}
}
function Get-GdiagCrashEventKind($Event) {
    $name='';foreach($field in @($Event.fields)){if($field.name -eq 'EventName'){$name=[string]$field.value}}
    if($Event.provider -eq 'Application Error' -and $Event.eventId -eq 1000){return 'application_crash_record'}
    if($Event.provider -eq 'Application Hang' -and $Event.eventId -eq 1002){return 'application_hang_record'}
    if($Event.provider -eq 'Windows Error Reporting' -and $Event.eventId -eq 1001){
        if($name -match '^AppHang'){return 'wer_hang_record'}
        if($name -match '^(APPCRASH|BEX|CLR20r3|MoAppCrash)'){return 'wer_crash_record'}
        return 'wer_report_unclassified'
    }
    'unclassified_event'
}
function Read-GdiagWerReport($Path,$Target) {
    $file=Get-Item -LiteralPath (Assert-GdiagPlainPath $Path) -ErrorAction Stop
    if($file.Length -gt 131072){return [pscustomobject]@{path=$file.FullName;status='truncated';association='unverified';limit=131072}}
    # ReadAllText detects UTF-16/UTF-8 BOMs. Values are evidence, never executable input.
    $text=[IO.File]::ReadAllText($file.FullName)
    $fields=[ordered]@{}
    foreach($line in ($text -split "`r?`n")){
        if($line -match '^([A-Za-z0-9.\[\]_]+)=(.*)$'){
            if($Matches[1] -in @('AppName','AppPath','EventType','ReportIdentifier','ReportType','EventTime') -or $Matches[1] -match '^Sig\[\d+\]\.(Name|Value)$'){$fields[$Matches[1]]=$Matches[2]}
        }
    }
    $paths=@($Target.path,$Target.file.path | Where-Object {$_})
    $association=if($fields.AppPath -and @($paths|Where-Object {([string]$_).Equals([string]$fields.AppPath,[StringComparison]::OrdinalIgnoreCase)}).Count){'exact_application_path_match'}else{'unverified'}
    $kind=if($fields.EventType -match '^AppHang'){'hang'}elseif($fields.EventType -match '^(APPCRASH|BEX|CLR20r3|MoAppCrash)'){'crash'}else{'unclassified'}
    [pscustomobject]@{path=$file.FullName;status='observed';association=$association;kind=$kind;lastWriteUtc=$file.LastWriteTimeUtc.ToString('o');fields=$fields;rootCause='unproven'}
}
function Get-GdiagCrashDumpMetadata($Path,$Source,$Start,$End) {
    try{
        if(-not [IO.Path]::IsPathRooted($Path)){throw 'Dump selection must be an absolute path.'}
        if($Path.StartsWith('\\')){return [pscustomobject]@{path=$Path;status='unavailable';source=$Source;association='unverified';reason='network_path_requires_bounded_copy_or_dump_probe'}}
        $resolved=Assert-GdiagPlainPath $Path
        $file=Get-Item -LiteralPath $resolved -ErrorAction Stop
        if($file.PSIsContainer -or $file.Extension -notin @('.dmp','.mdmp','.hdmp')){throw 'Select a dump file, not a directory or unrelated file.'}
        [pscustomobject]@{path=$file.FullName;size=$file.Length;lastWriteUtc=$file.LastWriteTimeUtc.ToString('o');status='observed';source=$Source;
            association=$(if($Source -eq 'explicit_selection'){'explicit_selection_not_target_identity'}elseif($Source -eq 'wer_exact_application_path'){'wer_report_path_match_dump_identity_pending'}else{'filename_candidate_only'});
            intervalAssociation=$(if($file.LastWriteTimeUtc -ge $Start -and $file.LastWriteTimeUtc -le $End){'file_mtime_in_interval_not_exception_time'}else{'file_mtime_outside_interval'});dumpIdentity='requires_minidump_analysis'}
    }catch{
        $status=if($_.CategoryInfo.Category -eq 'ObjectNotFound'){'absent'}else{Get-GdiagErrorStatus $_}
        $native=Get-GdiagNativeError $_
        [pscustomobject]@{path=$Path;status=$status;source=$Source;association='unverified';error=@{domain=$native.domain;code=$native.code}}
    }
}
function Get-GdiagCrashEvidence {
    param([hashtable]$Context,$Target,[hashtable]$Options=@{})
    $start=[datetime]::UtcNow.AddHours(-2);$end=[datetime]::UtcNow
    if($Context.startUtc){$start=[datetime]::Parse($Context.startUtc).ToUniversalTime()};if($Context.endUtc){$end=[datetime]::Parse($Context.endUtc).ToUniversalTime()}
    if($end -le $start -or ($end-$start).TotalHours -gt 24){throw 'Crash incident interval must be positive and no longer than 24 hours.'}
    if(@($Options.dumpPaths).Count -gt 32){throw 'Select at most 32 explicit dumps.'}
    $targets=if($Target){@($Target)}else{@($Context.targets | Select-Object -First 32)}
    $exeNames=@($targets | ForEach-Object {if($_.file.path -match '(?i)\.exe$'){[IO.Path]::GetFileName($_.file.path)}elseif($_.path -match '(?i)\.exe$'){[IO.Path]::GetFileName($_.path)}} | Select-Object -Unique)
    $targetId=if($Target){$Target.id}else{$null}
    $roots=New-Object Collections.Generic.List[object]
    $local=$null
    if($Context.affectedSid -eq $Context.executorSid){$local=[Environment]::GetFolderPath('LocalApplicationData')}
    elseif($Context.affectedSid){
        $record=Get-GdiagRegistryRecord Users Registry64 ($Context.affectedSid+'\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders') $Context.affectedSid
        $local=Get-GdiagRegValue $record @('Local AppData')
        if($local -and $Context.profilePath){$local=([string]$local).Replace('%USERPROFILE%',[string]$Context.profilePath)}
        if($local -match '%'){$local=$null}
        New-GdiagCrashObservation 'crash.affected-user-path' $record.status @{affectedUserPathResolved=[bool]$local;scope='loaded_affected_user_shell_folder';nativeErrorDomain=$record.error.domain;nativeErrorCode=$record.error.code} @{registry=$record} $targetId
    }
    if($local){$roots.Add(@{path=(Join-Path $local 'CrashDumps');source='wer_default_candidate';filterNames=$true})}
    foreach($view in @('Registry64','Registry32')){
        $base='SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
        foreach($name in @('')+$exeNames){
            $key=$base;if($name){$key+='\'+$name}
            $record=Get-GdiagRegistryRecord LocalMachine $view $key $null
            $folder=Get-GdiagRegValue $record @('DumpFolder')
            $dumpType=Get-GdiagRegValue $record @('DumpType')
            New-GdiagCrashObservation 'crash.localdumps-configuration' $record.status @{view=$view;application=$name;configuredFolderPresent=[bool]$folder;dumpType=$dumpType;captureReadiness='configuration_only_not_proof_dump_will_be_written';nativeErrorDomain=$record.error.domain;nativeErrorCode=$record.error.code;source='Microsoft WER LocalDumps'} @{registry=$record} $targetId
            if($folder){
                $expanded=[string]$folder
                if($local){$expanded=$expanded.Replace('%LOCALAPPDATA%',$local)}
                if($Context.profilePath){$expanded=$expanded.Replace('%USERPROFILE%',[string]$Context.profilePath)}
                $expanded=$expanded.Replace('%SystemRoot%',[Environment]::GetFolderPath('Windows'))
                if($expanded -notmatch '%' -and [IO.Path]::IsPathRooted($expanded)){$roots.Add(@{path=$expanded;source=('wer_configured_'+$view);filterNames=$true})}
                else{New-GdiagCrashObservation 'crash.dump-location' 'unavailable' @{reason='affected_user_environment_expansion_unresolved'} @{rawFolder=$folder} $targetId}
            }
        }
    }
    $candidates=New-Object Collections.Generic.List[object];$seen=@{};$limited=$false
    foreach($path in @($Options.dumpPaths | Where-Object {$_})){
        $candidate=Get-GdiagCrashDumpMetadata ([string]$path) 'explicit_selection' $start $end
        $candidates.Add($candidate);$seen[[string]$candidate.path]=$true
    }
    foreach($root in @($roots | Sort-Object path -Unique)){
        if($candidates.Count -ge 64){$limited=$true;break}
        if(-not $exeNames.Count){continue}
        try{
            if($root.path.StartsWith('\\')){throw 'Configured network dump folder requires bounded explicit dump analysis.'}
            $resolved=Assert-GdiagPlainPath $root.path
            if(-not(Test-Path -LiteralPath $resolved -PathType Container)){New-GdiagCrashObservation 'crash.dump-location' 'absent' @{source=$root.source} @{path=$resolved} $targetId;continue}
            foreach($name in $exeNames){
                $files=@(Get-ChildItem -LiteralPath $resolved -File -Filter ($name+'*.*dmp') -ErrorAction Stop | Where-Object {$_.Extension -in @('.dmp','.mdmp','.hdmp')} | Select-Object -First 33)
                if($files.Count -gt 32){$limited=$true}
                foreach($file in @($files | Select-Object -First 32)){
                    if($candidates.Count -ge 64){$limited=$true;break}
                    if(-not $seen.ContainsKey($file.FullName)){$candidates.Add((Get-GdiagCrashDumpMetadata $file.FullName $root.source $start $end));$seen[$file.FullName]=$true}
                }
            }
        }catch{$native=Get-GdiagNativeError $_;New-GdiagCrashObservation 'crash.dump-location' (Get-GdiagErrorStatus $_) @{source=$root.source;nativeErrorDomain=$native.domain;nativeErrorCode=$native.code} @{path=$root.path} $targetId}
    }
    # WER folders: enumerate one bounded level, then only Report.wer and sibling dump files.
    $werRoots=@();if($local){$werRoots+=(Join-Path $local 'Microsoft\Windows\WER\ReportArchive');$werRoots+=(Join-Path $local 'Microsoft\Windows\WER\ReportQueue')}
    $common=[Environment]::GetFolderPath('CommonApplicationData');if($common){$werRoots+=(Join-Path $common 'Microsoft\Windows\WER\ReportArchive');$werRoots+=(Join-Path $common 'Microsoft\Windows\WER\ReportQueue')}
    $reportReads=0
    foreach($root in $werRoots){
        try{
            $root=Assert-GdiagPlainPath $root
            if(-not(Test-Path -LiteralPath $root -PathType Container)){continue}
            $folders=@(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop | Select-Object -First 65)
            if($folders.Count -gt 64){$limited=$true}
            foreach($folder in @($folders | Select-Object -First 64)){
                if(-not @($exeNames | Where-Object {$folder.Name.StartsWith('AppCrash_'+$_+'_',[StringComparison]::OrdinalIgnoreCase) -or $folder.Name.StartsWith('AppHang_'+$_+'_',[StringComparison]::OrdinalIgnoreCase)}).Count){continue}
                $reportPath=Join-Path (Assert-GdiagPlainPath $folder.FullName) 'Report.wer'
                if(-not(Test-Path -LiteralPath $reportPath -PathType Leaf)){continue}
                foreach($selected in $targets){
                    if($reportReads -ge 32){$limited=$true;break}
                    $reportReads++
                    $report=Read-GdiagWerReport $reportPath $selected
                    New-GdiagCrashObservation 'crash.wer-report' $report.status @{kind=$report.kind;association=$report.association;rootCause='unproven';callstack='requires_selected_dump_analysis'} @{report=$report} $selected.id
                    if($report.association -eq 'exact_application_path_match'){
                        foreach($file in @(Get-ChildItem -LiteralPath $folder.FullName -File -Filter '*.*dmp' | Where-Object {$_.Extension -in @('.dmp','.mdmp','.hdmp')} | Select-Object -First 8)){
                            if($candidates.Count -ge 64){$limited=$true;break}
                            if(-not $seen.ContainsKey($file.FullName)){$candidates.Add((Get-GdiagCrashDumpMetadata $file.FullName 'wer_exact_application_path' $start $end));$seen[$file.FullName]=$true}
                        }
                    }
                }
            }
        }catch{$native=Get-GdiagNativeError $_;New-GdiagCrashObservation 'crash.wer-location' (Get-GdiagErrorStatus $_) @{nativeErrorDomain=$native.domain;nativeErrorCode=$native.code} @{path=$root} $targetId}
    }
    New-GdiagCrashObservation 'crash.dump_candidates' $(if($limited){'truncated'}elseif($candidates.Count){'observed'}else{'absent'}) @{candidateCount=$candidates.Count;candidateLimit=64;fileContentCollected=$false;callstack='not_analyzed';nextAction='Select a relevant dump for offline exception-thread stack analysis. A filename or nearby time does not prove target identity or root cause.'} @{candidates=$candidates.ToArray()} $targetId
    try{
        $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';Id=@(1000,1001,1002);StartTime=$start;EndTime=$end} -MaxEvents 65 -ErrorAction Stop)
        $records=@(foreach($event in @($events | Select-Object -First 64)){
            $xml=[xml]$event.ToXml()
            $record=@{channel='Application';provider=$event.ProviderName;eventId=$event.Id;version=$event.Version;recordId=$event.RecordId;timeUtc=$event.TimeCreated.ToUniversalTime().ToString('o');activityId=[string]$xml.Event.System.Correlation.ActivityID;fields=@($xml.Event.EventData.Data | ForEach-Object {@{name=$_.Name;value=$_.'#text'}})}
            $record.kind=Get-GdiagCrashEventKind $record
            $record.associations=@(foreach($selected in $targets){Get-GdiagEventAssociation $record $selected @($Context.processIdentities)})
            $record
        })
        $kinds=@($records | Group-Object kind | ForEach-Object {@{kind=$_.Name;count=$_.Count}})
        $associated=@(foreach($record in $records){foreach($association in @($record.associations)){if($association.association -in @('path_pid_lifetime_match','path_match_process_lifetime_unverified')){@{recordId=$record.recordId;kind=$record.kind;targetId=$association.targetId;association=$association.association}}}})
        New-GdiagCrashObservation 'crash.application-events' $(if($events.Count -gt 64){'truncated'}else{'observed'}) @{eventCount=$records.Count;eventKinds=$kinds;scope='bounded_channel_includes_unrelated_records';associatedEvents=$associated;cause='unproven';publisherPidIsTargetPid=$false} @{events=$records} $targetId
    }catch{
        $status=if($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound'){'empty_completed'}else{Get-GdiagErrorStatus $_}
        $native=Get-GdiagNativeError $_
        New-GdiagCrashObservation 'crash.application-events' $status @{nativeErrorDomain=$native.domain;nativeErrorCode=$native.code;callstack='requires_dump_or_live_debugger_not_event_fault_module'} $null $targetId
    }
}
