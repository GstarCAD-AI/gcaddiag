# Windows PowerShell 5.1; no target runtime is imported into the collector.
$script:GdiagRegistryEvidence = @()
function New-GdiagNativeObservation {
    param($Source,$Status,$Observed,$ErrorRecord,$TargetId)
    $nativeError = $null
    if ($ErrorRecord) { $nativeError = Get-GdiagNativeError $ErrorRecord }
    $summary=@{collectionStatus=$Status}
    foreach($field in @('channel','startUtc','endUtc','stage','exitCode','timeoutSeconds','correlation','level','rootSource','tailBytes','intervalAssociation','databaseStatus','directoryAccess','writeAccess','termination')) {
        if($Observed -is [System.Collections.IDictionary] -and $Observed.Contains($field)){$summary[$field]=$Observed[$field]}
    }
    if($Observed -is [System.Collections.IDictionary] -and $Observed.Contains('events')){
        $summary.eventCount=@($Observed.events).Count
        $summary.associatedEvents=@(foreach($event in $Observed.events){foreach($association in @($event.associations)){if($association -and $association.targetId -and $association.association -in @('path_pid_lifetime_match','path_match_process_lifetime_unverified')){@{recordId=$event.recordId;eventId=$event.eventId;targetId=$association.targetId;association=$association.association;policyMeaning=$association.policyMeaning;cause='unproven'}}}})
    }
    if($Observed -is [System.Collections.IDictionary] -and $Observed.Contains('error') -and $Observed.error){$summary.nativeErrorDomain=$Observed.error.domain;$summary.nativeErrorCode=$Observed.error.code}
    if($Observed -is [System.Collections.IDictionary] -and $Observed.Contains('probe')){
        $summary.probeStatus=$Observed.probe.status
        if($Observed.probe.Contains('exitCode')){$summary.exitCode=$Observed.probe.exitCode}
        if($Observed.probe.Contains('nativeStages')){$summary.nativeStages=$Observed.probe.nativeStages}
        if($Observed.probe.Contains('termination')){$summary.termination=$Observed.probe.termination}
        if($Observed.probe.Contains('error') -and $Observed.probe.error){$summary.nativeErrorDomain=$Observed.probe.error.domain;$summary.nativeErrorCode=$Observed.probe.error.code}
    }
    if($nativeError){$summary.nativeErrorDomain=$nativeError.domain;$summary.nativeErrorCode=$nativeError.code;if($nativeError.domain -eq 'HRESULT'){$summary.hresult=$nativeError.code}}
    [pscustomobject]@{ source=$Source; status=$Status; summary=$summary; observed=$Observed; error=$nativeError; targetId=$TargetId; timeUtc=[DateTime]::UtcNow.ToString('o') }
}
function Get-GdiagWindowsFindings {
    param($Document)
    foreach($observation in @($Document.observations | Where-Object source -eq 'windows_events')){
        foreach($association in @($observation.summary.associatedEvents)){
            if(-not $association -or -not $association.targetId -or $association.association -notin @('path_pid_lifetime_match','path_match_process_lifetime_unverified')){continue}
            [pscustomobject]@{id=('finding-'+[guid]::NewGuid().ToString('N').Substring(0,12));targetId=$association.targetId;confidence='hypothesis';evidenceIds=@($observation.id);symptom='Windows event is associated with selected target identity.';impact=('Association: '+$association.association+'; policy meaning: '+$association.policyMeaning+'. This is not proof of root cause.');nextAction='Inspect structured event fields, activity/report identity and product startup stage; distinguish audit/detection records from enforced actions.';cause='unresolved'}
        }
    }
    foreach($target in @($Document.targets)) {
        $issues=@()
        if($target.file.status -eq 'absent'){$issues+=@{confidence=$(if($target.family -eq 'GstarAssistant' -and $target.modulePathSource -eq 'catalog_default_current_layout'){'hypothesis'}else{'confirmed'});symptom='Selected installation executable/module path is absent.';impact='Registration alone does not establish an installed or loadable product; a catalog-default path may differ in another package layout.';nextAction='Confirm selected release/root and inspect the matching trusted package; do not copy a DLL from another release.'}}
        if($target.payload -and @($target.payload.missing).Count){$issues+=@{confidence='hypothesis';symptom='Installed payload differs from the reviewed source baseline.';impact='The installed package may use another layout/version; missing baseline files alone do not prove this installed release is incomplete.';nextAction='Compare the installed release manifest and matching package before planning a coherent vendor repair.'}}
        if($target.manifest -and ($target.manifest.missingCount -gt 0 -or $target.manifest.mismatchCount -gt 0)){$issues+=@{symptom='Installed files differ from the local installed payload manifest.';impact='Declared files are absent or have different SHA256 values; the local manifest itself does not establish publisher authenticity or root cause.';nextAction='Compare with the selected trusted package and investigate this exact payload before repair.'}}
        if($target.startup -and $target.startup.status -eq 'observed') {
            $loader=Get-GdiagRegValue $target.startup @('LOADER')
            $expected=$target.file.path
            if($loader -and -not ([string]$loader).Equals($expected,[StringComparison]::OrdinalIgnoreCase)){$issues+=@{symptom='Startup loader differs from the selected registered module path.';impact='A different or stale payload may be selected at host startup; loading is unverified.';nextAction='Reconcile selected release/locale and the exact loader before proposing registration repair.'}}
        }
        foreach($issue in $issues) {
            [pscustomobject]@{id=('finding-'+[guid]::NewGuid().ToString('N').Substring(0,12));targetId=$target.id;confidence=$(if($issue.confidence){$issue.confidence}else{'confirmed'});evidenceIds=@($Document.observations | Where-Object source -eq 'registry' | ForEach-Object {$_.id});symptom=$issue.symptom;impact=$issue.impact;nextAction=$issue.nextAction;cause='unresolved';evidenceLocation='selected target file/payload/startup metadata'}
        }
    }
}
function Get-GdiagErrorException {
    param($Record)
    $failure=if($Record -is [Exception]){$Record}else{$Record.Exception}
    # PowerShell wraps .NET method/property failures in MethodInvocationException.
    # Classify the native cause, not the generic PowerShell wrapper HRESULT.
    while($failure.InnerException){$failure=$failure.InnerException}
    $failure
}
function Get-GdiagNativeError {
    param($Record)
    $failure=Get-GdiagErrorException $Record
    if($failure -is [ComponentModel.Win32Exception]){return @{domain='Win32';code=$failure.NativeErrorCode;message=$failure.Message}}
    @{domain='HRESULT';code=$failure.HResult;message=$failure.Message}
}
function Get-GdiagErrorStatus {
    param($Record)
    $failure=Get-GdiagErrorException $Record
    if ($failure -is [UnauthorizedAccessException] -or $failure -is [System.Security.SecurityException] -or ($failure -is [ComponentModel.Win32Exception] -and $failure.NativeErrorCode -eq 5)) { 'access_denied' } else { 'collection_error' }
}
function Get-GdiagRegistryRecord {
    param([string]$Hive,[string]$View,[string]$Key,[string]$UserSid)
    $base=$null; $node=$null
    try {
        $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$Hive,[Microsoft.Win32.RegistryView]::$View)
        $node=$base.OpenSubKey($Key)
        if (-not $node) { return [pscustomobject]@{hive=$Hive;view=$View;key=$Key;userSid=$UserSid;status='absent';values=@();subkeys=@()} }
        $values=@(foreach ($name in $node.GetValueNames()) {
            [pscustomobject]@{name=$name;type=$node.GetValueKind($name).ToString();raw=$node.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
        })
        [pscustomobject]@{hive=$Hive;view=$View;key=$Key;userSid=$UserSid;status='observed';values=$values;subkeys=@($node.GetSubKeyNames())}
    } catch {
        [pscustomobject]@{hive=$Hive;view=$View;key=$Key;userSid=$UserSid;status=(Get-GdiagErrorStatus $_);values=@();subkeys=@();error=(Get-GdiagNativeError $_)}
    } finally { if($node){$node.Dispose()}; if($base){$base.Dispose()} }
}
function Get-GdiagRegValue {
    param($Record,[string[]]$Names)
    foreach($name in $Names) { $value=@($Record.values | Where-Object name -eq $name); if($value.Count -and $value[0].raw){ return $value[0].raw } }
    return $null
}
function Get-GdiagFileIdentity {
    param([string]$Path)
    $stream=$null; $reader=$null
    try {
        $file=Get-Item -LiteralPath $Path -ErrorAction Stop
        $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $reader=New-Object IO.BinaryReader($stream)
        $architecture='not_pe'
        if($stream.Length -gt 64 -and $reader.ReadUInt16() -eq 0x5a4d) {
            $stream.Position=60; $offset=$reader.ReadInt32()
            if($offset -ge 0 -and ($offset+6) -le $stream.Length) {
                $stream.Position=$offset
                if($reader.ReadUInt32() -eq 0x4550) {
                    $machine=$reader.ReadUInt16()
                    $architecture=switch($machine){0x8664{'x64'} 0x14c{'x86'} 0xaa64{'arm64'} default{('unknown_{0:x}' -f $machine)}}
                }
            }
        }
        @{status='observed';path=$file.FullName;architecture=$architecture;fileVersion=$file.VersionInfo.FileVersion;length=$file.Length}
    } catch { @{status= $(if($_.CategoryInfo.Category -eq 'ObjectNotFound'){'absent'}else{Get-GdiagErrorStatus $_});path=$Path;error=(Get-GdiagNativeError $_)} }
    finally {if($reader){$reader.Dispose()}elseif($stream){$stream.Dispose()}}
}
function Get-GdiagInventory {
    param([hashtable]$Context)
    $catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../catalog/products.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $script:GdiagRegistryEvidence=@()
    $targets=New-Object System.Collections.Generic.List[object]
    $usersKey=[string]$Context.affectedSid
    $locations=@(@{hive='LocalMachine';prefix='SOFTWARE';sid=$null},@{hive='Users';prefix="$usersKey\Software";sid=$usersKey})
    foreach($view in @('Registry64','Registry32')) {
        foreach($location in $locations) {
            foreach($family in @('GstarCAD','GstarAssistant')) {
                $root="$($location.prefix)\Gstarsoft\$family"
                $record=Get-GdiagRegistryRecord $location.hive $view $root $location.sid
                $script:GdiagRegistryEvidence+=New-GdiagNativeObservation 'registry' $record.status $record $null $null
                foreach($release in $record.subkeys) {
                    $releaseRecord=Get-GdiagRegistryRecord $location.hive $view "$root\$release" $location.sid
                    $candidates=@($releaseRecord)
                    if($family -eq 'GstarCAD') {
                        foreach($locale in $releaseRecord.subkeys) {
                            $candidates+=Get-GdiagRegistryRecord $location.hive $view "$root\$release\$locale" $location.sid
                        }
                    }
                    foreach($candidate in $candidates) {
                        $path=Get-GdiagRegValue $candidate @('InstallDir','InstallLocation','LOCATION','InstallRoot')
                        if(-not $path){continue}
                        # Expand only the current executor's variables; another user's raw path stays unresolved.
                        if($Context.executorSid -eq $Context.affectedSid){$path=[Environment]::ExpandEnvironmentVariables([string]$path)}
                        $exe=if($family -eq 'GstarCAD'){Join-Path $path 'gcad.exe'}else{Join-Path $path 'modules\GstarAssistant.grx'}
                        $moduleSource='catalog_default_current_layout'
                        $payloadRoot=$path
                        if($family -eq 'GstarAssistant'){
                            $registeredModule=Get-GdiagRegValue $candidate @('RuntimeGrxPath','GrxPath')
                            if($registeredModule -and [IO.Path]::IsPathRooted([string]$registeredModule)){
                                $exe=[string]$registeredModule;$moduleSource='registered_module_path'
                                $moduleDir=[IO.Path]::GetDirectoryName($exe)
                                if([IO.Path]::GetFileName($moduleDir) -eq 'modules'){$payloadRoot=[IO.Path]::GetDirectoryName($moduleDir)}
                            }
                        }
                        $known=@($catalog.releases | Where-Object release -eq $release)
                        $target=[pscustomobject]@{family=$family;release=$release;locale=($candidate.key -split '\\')[-1];path=[string]$path;registry=$candidate;file=(Get-GdiagFileIdentity $exe);expectations= $(if($known.Count){$known[0]}else{$null});expectationStatus=$(if($known.Count){'known_release'}else{'unknown_release'});registered=$true;hostVerification='pending'}
                        if($family -eq 'GstarAssistant') {
                            $target | Add-Member modulePathSource $moduleSource
                            $target | Add-Member payloadRoot $payloadRoot
                            $startup=Get-GdiagRegValue $candidate @('GcadStartupKey')
                            if($startup){
                                if($location.hive -eq 'Users' -and -not ([string]$startup).StartsWith("$usersKey\")){$startup="$usersKey\$startup"}
                                $target | Add-Member startup (Get-GdiagRegistryRecord $location.hive $view $startup $location.sid)
                            }
                            $required=@($catalog.assistantPayload)
                            if($known.Count){$required+=@($known[0].additionalPayload)}
                            $missing=@(foreach($relative in $required){$relative=$relative.Replace('{year}',[string](Get-GdiagRegValue $candidate @('TargetYear'))); if(-not [IO.File]::Exists((Join-Path $payloadRoot $relative))){$relative}})
                            $target | Add-Member payload @{root=$payloadRoot;source=$catalog.source;missing=$missing;manifestPresent=[IO.File]::Exists((Join-Path $payloadRoot 'payload-manifest.json'));completeness='catalog_baseline_not_manifest_integrity'}
                            $target | Add-Member manifest (Test-GdiagInstalledManifest -Root $payloadRoot -TargetYear ([string](Get-GdiagRegValue $candidate @('TargetYear'))) -Version ([string](Get-GdiagRegValue $candidate @('DisplayVersion'))))
                        }
                        $targets.Add($target)
                    }
                }
            }
            $uninstall=Get-GdiagRegistryRecord $location.hive $view "$($location.prefix)\Microsoft\Windows\CurrentVersion\Uninstall" $location.sid
            if($uninstall.status -ne 'observed'){$script:GdiagRegistryEvidence+=New-GdiagNativeObservation 'uninstall_registry' $uninstall.status $uninstall $null $null}
            foreach($name in $uninstall.subkeys){
                $entry=Get-GdiagRegistryRecord $location.hive $view "$($uninstall.key)\$name" $location.sid
                $display=Get-GdiagRegValue $entry @('DisplayName')
                if($display -match 'Gstar|gcad-cli|WebView2|Visual C\+\+'){$script:GdiagRegistryEvidence+=New-GdiagNativeObservation 'uninstall_registry' 'observed' $entry $null $null}
            }
        }
    }
    foreach($command in @('gcad-cli','gcadcli','python','python3','py')) {
        $resolved=@(Get-Command $command -All -ErrorAction SilentlyContinue)
        $script:GdiagRegistryEvidence+=New-GdiagNativeObservation 'executor_command_resolution' $(if($resolved.Count){'observed'}else{'absent'}) @($resolved | Select-Object Name,CommandType,Source,Path) $null $null
        if($command -match '^gcad' ){foreach($entry in $resolved | Where-Object CommandType -eq 'Application'){$targets.Add([pscustomobject]@{family='gcad-cli';release='unknown';path=$entry.Path;file=(Get-GdiagFileIdentity $entry.Path);expectationStatus='unknown_release';hostVerification='pending'})}}
    }
    $targets.ToArray()
}
function Test-GdiagInstalledManifest {
    param([string]$Root,[string]$TargetYear,[string]$Version,[int64]$HashByteLimit=268435456,[int]$TimeLimitSeconds=5)
    $result=@{status='unavailable';schema='unverified';fileCount=0;checkedCount=0;missingCount=0;mismatchCount=0;unverifiedCount=0;hashedBytes=0;identityMatches=$null;details=@();authenticity='not_established_by_local_manifest'}
    try {
        $rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\','/')
        if(-not [IO.Directory]::Exists($rootPath)){$result.status='absent';return $result}
        $rootItem=Get-Item -LiteralPath $rootPath -ErrorAction Stop
        $ancestor=$rootItem
        while($ancestor){if($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint){$result.status='unavailable';$result.schema='reparse_root_not_followed';return $result};$ancestor=$ancestor.Parent}
        $manifestPath=Join-Path $rootPath 'payload-manifest.json'
        if(-not [IO.File]::Exists($manifestPath)){$result.status='absent';return $result}
        $manifestItem=Get-Item -LiteralPath $manifestPath -ErrorAction Stop
        if($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint){$result.status='unavailable';$result.schema='reparse_manifest_not_followed';return $result}
        if($manifestItem.Length -gt 2097152){$result.status='truncated';$result.schema='manifest_over_2MiB_limit';return $result}
        $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        if($manifest.schema_version -ne 2 -or $manifest.layout -ne 'gstarassistant-v1' -or $manifest.product -ne 'GstarAssistant' -or $manifest.files -isnot [pscustomobject]){$result.status='unsupported_schema';return $result}
        $result.schema='gstarassistant-v1/schema2';$result.status='observed'
        $result.identityMatches=(([string]$manifest.target_year -eq $TargetYear) -and ([string]$manifest.version -eq $Version))
        $entries=@($manifest.files.PSObject.Properties);$result.fileCount=$entries.Count
        $clock=[Diagnostics.Stopwatch]::StartNew()
        foreach($entry in ($entries | Select-Object -First 2000)) {
            $filePath=[IO.Path]::GetFullPath((Join-Path $rootPath $entry.Name))
            if(-not $filePath.StartsWith(($rootPath+'\'),[StringComparison]::OrdinalIgnoreCase)){$result.details+=@{path=$entry.Name;status='rejected_path_escape'};$result.unverifiedCount++;continue}
            if(([string]$entry.Value) -notmatch '^[0-9a-fA-F]{64}$'){$result.details+=@{path=$entry.Name;status='invalid_declared_sha256'};$result.unverifiedCount++;continue}
            $relative=$filePath.Substring($rootPath.Length+1);$parts=$relative -split '\\';$walk=$rootPath;$reparse=$false
            foreach($part in $parts){$walk=Join-Path $walk $part;if(Test-Path -LiteralPath $walk){if((Get-Item -LiteralPath $walk -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint){$reparse=$true;break}}}
            if($reparse){$result.details+=@{path=$entry.Name;status='reparse_not_followed'};$result.unverifiedCount++;continue}
            if(-not [IO.File]::Exists($filePath)){$result.details+=@{path=$entry.Name;status='absent'};$result.missingCount++;continue}
            $file=Get-Item -LiteralPath $filePath -ErrorAction Stop
            if(($result.hashedBytes+$file.Length) -gt $HashByteLimit -or $clock.Elapsed.TotalSeconds -gt $TimeLimitSeconds){$result.details+=@{path=$entry.Name;status='not_checked_budget'};$result.unverifiedCount++;continue}
            $stream=$null;$sha=$null
            try{$stream=[IO.File]::Open($filePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$sha=[Security.Cryptography.SHA256]::Create();$hash=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','');$result.hashedBytes+=$file.Length;$result.checkedCount++;if($hash -ne [string]$entry.Value){$result.mismatchCount++;$result.details+=@{path=$entry.Name;status='sha256_mismatch'}}}
            finally{if($sha){$sha.Dispose()};if($stream){$stream.Dispose()}}
        }
        $result.unverifiedCount += [Math]::Max(0,$entries.Count-2000)
        if($result.unverifiedCount){$result.status='truncated'}
        $result
    }catch{$result.status=Get-GdiagErrorStatus $_;$result.details+=@{status=$result.status;error=(Get-GdiagNativeError $_)};$result}
}
function Get-GdiagEventEvidence {
    param([hashtable]$Context,[int]$Limit=100)
    $start=[DateTime]::UtcNow.AddMinutes(-30); $end=[DateTime]::UtcNow
    if($Context.startUtc){$start=[DateTime]::Parse($Context.startUtc).ToUniversalTime()};if($Context.endUtc){$end=[DateTime]::Parse($Context.endUtc).ToUniversalTime()}
    if($end -le $start -or ($end-$start).TotalHours -gt 24){throw 'Incident interval must be positive and no longer than 24 hours.'}
    foreach($channel in @('Application','System','Microsoft-Windows-CodeIntegrity/Operational','Microsoft-Windows-AppLocker/EXE and DLL','Microsoft-Windows-Windows Defender/Operational')) {
        try {
            $info=Get-WinEvent -ListLog $channel -ErrorAction Stop
            if(-not $info.IsEnabled){New-GdiagNativeObservation 'windows_events' 'disabled' @{channel=$channel} $null $null;continue}
            $events=@(Get-WinEvent -FilterHashtable @{LogName=$channel;StartTime=$start;EndTime=$end} -MaxEvents ($Limit+1) -ErrorAction Stop)
            $data=@(foreach($event in ($events | Select-Object -First $Limit)) {
                $xml=[xml]$event.ToXml()
                $item=@{channel=$channel;provider=$event.ProviderName;eventId=$event.Id;version=$event.Version;recordId=$event.RecordId;timeUtc=$event.TimeCreated.ToUniversalTime().ToString('o');publisherProcessId=[string]$xml.Event.System.Execution.ProcessID;activityId=[string]$xml.Event.System.Correlation.ActivityID;fields=@($xml.Event.EventData.Data | ForEach-Object {@{name=$_.Name;value=$_.'#text'}});level=$event.Level}
                $item.associations=@(foreach($selected in @($Context.targets)){Get-GdiagEventAssociation $item $selected @($Context.processIdentities)})
                $item
            })
            New-GdiagNativeObservation 'windows_events' $(if($events.Count -gt $Limit){'truncated'}else{'observed'}) @{channel=$channel;startUtc=$start.ToString('o');endUtc=$end.ToString('o');events=$data} $null $null
        } catch {
            $status=if($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound'){'empty_completed'}elseif($_.FullyQualifiedErrorId -match 'NoMatchingLogsFound'){'unavailable'}else{Get-GdiagErrorStatus $_}
            New-GdiagNativeObservation 'windows_events' $status @{channel=$channel;startUtc=$start.ToString('o');endUtc=$end.ToString('o')} $_ $null
        }
    }
}
function Get-GdiagWindowsEvidence {
    param([hashtable]$Context)
    $script:GdiagRegistryEvidence
    $Context.processIdentities=@()
    foreach($process in Get-Process | Where-Object ProcessName -match '^(gcad|gcadcli|gcad-cli|Gstar|msedgewebview2)') {
        try {
            $modules=@($process.Modules | Select-Object -First 121 | ForEach-Object {$_.FileName})
            $Context.processIdentities+=@{pid=$process.Id;startUtc=$process.StartTime.ToUniversalTime().ToString('o');path=$process.Path;session=$process.SessionId}
            New-GdiagNativeObservation 'process' $(if($modules.Count -gt 120){'truncated'}else{'observed'}) @{pid=$process.Id;startUtc=$process.StartTime.ToUniversalTime().ToString('o');path=$process.Path;session=$process.SessionId;modules=@($modules | Select-Object -First 120);moduleLimit=120;ownership='not_owned_by_probe'} $null $null
        }catch{New-GdiagNativeObservation 'process' (Get-GdiagErrorStatus $_) @{pid=$process.Id} $_ $null}
    }
    New-GdiagNativeObservation 'state_root' 'observed' @{executorOverride=[Environment]::GetEnvironmentVariable('GCAD_STATE_ROOT','Process');scope='executor_environment_only';defaultTemplate='%LOCALAPPDATA%\GstarAssistant\{year}';affectedUserProfile=$Context.profilePath;effectiveProductRoot='unverified_without_host_evidence'} $null $null
    Get-GdiagEventEvidence $Context
    Get-GdiagProductLogs $Context
}
function Get-GdiagEventAssociation {
    param($Event,$Target,$Processes)
    $paths=@($Target.path);if($Target.file.path){$paths+=@($Target.file.path)}
    $fieldMap=@{};foreach($field in @($Event.fields)){if($field.name){$fieldMap[$field.name]=[string]$field.value}}
    $pathMatches=$false
    foreach($name in @('AppPath','ApplicationPath','ImageName','FileName','ProcessName','FaultingApplicationPath')){
        if($fieldMap[$name]){foreach($path in $paths){if($path -and $fieldMap[$name].Equals([string]$path,[StringComparison]::OrdinalIgnoreCase)){$pathMatches=$true}}}
    }
    $faultPid=$null
    foreach($name in @('ProcessId','ProcessID','FaultingProcessId')){if($fieldMap[$name]){try{if($fieldMap[$name] -match '^0x'){$faultPid=[Convert]::ToInt32($fieldMap[$name].Substring(2),16)}else{$faultPid=[int]$fieldMap[$name]}}catch{};break}}
    $startMatched=$false
    foreach($identity in @($Processes)) {
        if($null -ne $faultPid -and $identity.pid -eq $faultPid -and $paths -contains $identity.path -and [DateTime]::Parse($Event.timeUtc) -ge [DateTime]::Parse($identity.startUtc)){$startMatched=$true}
    }
    $policy='not_classified'
    if($Event.channel -match 'CodeIntegrity'){$policy=switch([int]$Event.eventId){3076{'audit_only'}3077{'enforced_block'}default{'not_classified'}}}
    elseif($Event.channel -match 'AppLocker'){$policy=switch([int]$Event.eventId){8003{'audit_only'}8006{'audit_only'}8004{'enforced_block'}8007{'enforced_block'}default{'not_classified'}}}
    elseif($Event.channel -match 'Defender'){$policy=switch([int]$Event.eventId){1116{'detection_only'}1117{'action_record_not_assumed_quarantine'}default{'not_classified'}}}
    @{targetId=$Target.id;association=$(if($pathMatches -and $startMatched){'path_pid_lifetime_match'}elseif($pathMatches){'path_match_process_lifetime_unverified'}else{'unattributed'});policyMeaning=$policy;faultProcessId=$faultPid;activityId=$Event.activityId;cause='unproven';note='Publisher PID and proximity alone are not target identity; PID may have been reused. Common fault modules do not establish cause.'}
}
function Get-GdiagProductLogs {
    param([hashtable]$Context)
    foreach($target in @($Context.targets | Where-Object family -eq 'GstarAssistant')) {
        $year=Get-GdiagRegValue $target.registry @('TargetYear')
        if(-not $year -and $target.expectations){$year=$target.expectations.year}
        $root=$null;$rootSource='profile_default_candidate_not_host_verified'
        $override=[Environment]::GetEnvironmentVariable('GCAD_STATE_ROOT','Process')
        if($Context.executorSid -eq $Context.affectedSid -and $override){
            if(-not [IO.Path]::IsPathRooted($override)){New-GdiagNativeObservation 'product_logs' 'collection_error' @{stage='state_root';note='Executor GCAD_STATE_ROOT is relative; the product rejects it.'} $null $target.id;continue}
            $root=$override;$rootSource='executor_override_candidate_not_host_verified'
        }elseif($Context.profilePath -and $year){$root=Join-Path $Context.profilePath "AppData\Local\GstarAssistant\$year"}
        if(-not $root){New-GdiagNativeObservation 'product_logs' 'unavailable' @{stage='state_root';note='Affected-user state root unavailable.'} $null $target.id;continue}
        try {
            if(-not (Test-Path -LiteralPath $root -PathType Container)){New-GdiagNativeObservation 'product_logs' 'absent' @{stateRoot=$root;rootSource=$rootSource} $null $target.id;continue}
            $rootItem=Get-Item -LiteralPath $root -ErrorAction Stop
            if($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint){New-GdiagNativeObservation 'product_logs' 'unavailable' @{stage='state_root';note='Reparse root is not followed by standard collection.'} $null $target.id;continue}
            $candidates=New-Object System.Collections.Generic.List[string]
            foreach($name in @('debug.logs','webview-bridge.log')){$candidates.Add((Join-Path $root $name))}
            $users=Join-Path $root 'users'
            $limited=$false
            if((Test-Path -LiteralPath $users -PathType Container) -and -not ((Get-Item -LiteralPath $users).Attributes -band [IO.FileAttributes]::ReparsePoint)){
                $userDirs=@(Get-ChildItem -LiteralPath $users -Directory -ErrorAction Stop | Where-Object {-not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)} | Select-Object -First 21)
                if($userDirs.Count -gt 20){$limited=$true}
                foreach($userDir in ($userDirs | Select-Object -First 20)) {
                    $sessions=Join-Path $userDir.FullName 'sessions'
                    if(-not (Test-Path -LiteralPath $sessions -PathType Container)){continue}
                    if((Get-Item -LiteralPath $sessions).Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
                    foreach($name in @('debug.logs','webview-bridge.log')){$candidates.Add((Join-Path $sessions $name))}
                    $sessionDirs=@(Get-ChildItem -LiteralPath $sessions -Directory -ErrorAction Stop | Where-Object {-not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)} | Select-Object -First 21)
                    if($sessionDirs.Count -gt 20){$limited=$true}
                    foreach($session in ($sessionDirs | Select-Object -First 20)){foreach($name in @('debug.logs','webview-bridge.log')){$candidates.Add((Join-Path $session.FullName $name))}}
                }
            }
            $found=@(foreach($candidate in $candidates){if([IO.File]::Exists($candidate)){Get-Item -LiteralPath $candidate -ErrorAction Stop}})
            $files=@($found | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 9)
            if($files.Count -gt 8){$limited=$true}
            if(-not $files.Count){New-GdiagNativeObservation 'product_logs' 'absent' @{stateRoot=$root;rootSource=$rootSource;note='Known log names absent; this does not establish healthy startup.'} $null $target.id}
            foreach($file in ($files | Select-Object -First 8)) {
                if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
                $stream=$null
                try {
                    $stream=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                    $length=[Math]::Min(65536,$stream.Length);$stream.Position=$stream.Length-$length
                    $buffer=New-Object byte[] ([int]$length);$read=$stream.Read($buffer,0,$buffer.Length)
                    $text=[Text.Encoding]::UTF8.GetString($buffer,0,$read)
                    $start=[DateTime]::Parse($Context.startUtc).ToUniversalTime();$end=[DateTime]::Parse($Context.endUtc).ToUniversalTime()
                    $modified=$file.LastWriteTimeUtc -ge $start -and $file.LastWriteTimeUtc -le $end
                    New-GdiagNativeObservation 'product_log' $(if($file.Length -gt 65536){'truncated'}else{'observed'}) @{path=$file.FullName;rootSource=$rootSource;lastWriteUtc=$file.LastWriteTimeUtc.ToString('o');length=$file.Length;tailBytes=$read;intervalAssociation=$(if($modified){'file_modified_in_interval_entries_unverified'}else{'outside_interval_baseline'});content=$text;authority='untrusted_data_only';cause='unproven'} $null $target.id
                }finally{if($stream){$stream.Dispose()}}
            }
            if($limited){New-GdiagNativeObservation 'product_logs' 'truncated' @{stage='directory_selection';note='At most 20 users, 20 sessions per user and 8 known log files.'} $null $target.id}
        }catch{New-GdiagNativeObservation 'product_logs' (Get-GdiagErrorStatus $_) @{stage='read_logs';stateRoot=$root;rootSource=$rootSource} $_ $target.id}
    }
}
function Get-GdiagWindowsPowerShellPath([string]$Architecture) {
    $windows=[Environment]::GetFolderPath('Windows')
    $folder='System32'
    if([Environment]::Is64BitOperatingSystem -and $Architecture -eq 'x86'){$folder='SysWOW64'}
    elseif([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and $Architecture -eq 'x64'){$folder='Sysnative'}
    Join-Path $windows "$folder\WindowsPowerShell\v1.0\powershell.exe"
}
function Invoke-GdiagOwnedProcess {
    param([string]$Executable,[string]$Arguments,[int]$TimeoutSeconds=10)
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Executable;$info.Arguments=$Arguments;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.StandardOutputEncoding=New-Object Text.UTF8Encoding($false)
    $info.StandardErrorEncoding=New-Object Text.UTF8Encoding($false)
    $process=New-Object Diagnostics.Process; $process.StartInfo=$info
    $started=$false;$stage='process_start'
    $result=@{status='collection_error';stage=$stage;stdout='';stderr='';truncated=$false}
    $stdout=New-Object Text.StringBuilder;$stderr=New-Object Text.StringBuilder
    try {
        $started=$process.Start()
        if(-not $started){throw 'Probe did not start.'}
        $stage='owned_child';$result.stage=$stage;$result.pid=$process.Id
        $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        # Fixed-size concurrent reads bound memory even for output without newlines.
        $outBuffer=New-Object char[] 1024;$errBuffer=New-Object char[] 1024
        $out=$process.StandardOutput.ReadAsync($outBuffer,0,1024);$err=$process.StandardError.ReadAsync($errBuffer,0,1024)
        $outEnded=$false;$errEnded=$false
        while([DateTime]::UtcNow -lt $deadline){
            foreach($channel in @('stdout','stderr')){
                if($channel -eq 'stdout'){$task=$out;$ended=$outEnded;$buffer=$outBuffer;$builder=$stdout;$limit=8192}
                else{$task=$err;$ended=$errEnded;$buffer=$errBuffer;$builder=$stderr;$limit=4096}
                if($ended -or -not $task.IsCompleted){continue}
                $n=$task.Result
                if($n -eq 0){if($channel -eq 'stdout'){$outEnded=$true}else{$errEnded=$true};continue}
                $remaining=$limit-$builder.Length
                [void]$builder.Append($buffer,0,[Math]::Min($remaining,$n))
                if($n -gt $remaining){$result.status='truncated';$result.truncated=$true;break}
                if($channel -eq 'stdout'){$out=$process.StandardOutput.ReadAsync($outBuffer,0,1024)}else{$err=$process.StandardError.ReadAsync($errBuffer,0,1024)}
            }
            if($result.truncated){break}
            if($outEnded -and $errEnded -and $process.HasExited){
                $result.status=if($process.ExitCode -eq 0){'observed'}else{'probe_failed'}
                $result.exitCode=$process.ExitCode;$result.errorDomain='process_exit';break
            }
            Start-Sleep -Milliseconds 10
        }
        if($result.status -eq 'collection_error'){$result.status='timeout';$result.timeoutSeconds=$TimeoutSeconds}
    }catch{$result.status=Get-GdiagErrorStatus $_;$result.stage=$stage;$result.error=Get-GdiagNativeError $_}
    finally{
        $result.stdout=$stdout.ToString();$result.stderr=$stderr.ToString()
        if($started){
            try{
                if(-not $process.HasExited){$process.Kill();if(-not $process.WaitForExit(1000)){throw 'Owned child termination did not complete.'};$result.termination='owned_process_terminated_descendants_not_verified'}
                else{$result.termination='owned_process_exited_descendants_not_verified'}
            }catch{$result.termination='owned_process_termination_failed';$result.terminationError=Get-GdiagNativeError $_}
        }
        $process.Dispose()
    }
    $result
}
function Test-GdiagComHostIdentity {
    param($Expected,$Observed)
    $reasons=@()
    if(-not $Expected.pid -or [int]$Expected.pid -ne [int]$Observed.pid){$reasons+='pid_changed'}
    if($null -eq $Expected.sessionId -or $null -eq $Observed.sessionId -or [int]$Expected.sessionId -ne [int]$Observed.sessionId){$reasons+='session_changed'}
    $expectedTime=[DateTimeOffset]::MinValue;$observedTime=[DateTimeOffset]::MinValue
    if(-not [DateTimeOffset]::TryParse([string]$Expected.creationUtc,[ref]$expectedTime) -or -not [DateTimeOffset]::TryParse([string]$Observed.creationUtc,[ref]$observedTime) -or $expectedTime.UtcDateTime.Ticks -ne $observedTime.UtcDateTime.Ticks){$reasons+='process_start_changed'}
    try{if(-not $Expected.path -or -not $Observed.path -or [IO.Path]::GetFullPath($Expected.path) -ne [IO.Path]::GetFullPath($Observed.path)){$reasons+='image_changed'}}catch{$reasons+='invalid_image_identity'}
    @{matches=($reasons.Count -eq 0);status=$(if($reasons.Count){'host_selection_unresolved'}else{'host_identity_verified'});reasons=$reasons}
}
function Get-GdiagComHostSelection {
    param([string]$Executable,[hashtable]$Context)
    $currentSession=(Get-Process -Id $PID).SessionId
    $result=@{status='host_selection_unresolved';stage='host_candidate_preflight';candidates=@();inspectionGaps=@();currentSessionId=$currentSession}
    if($null -eq $Context.sessionId -or [int]$Context.sessionId -ne $currentSession){$result.reason='executor_session_changed_or_missing_recollect_case';return $result}
    if(-not [IO.Path]::IsPathRooted($Executable)){throw 'Selected host executable must be absolute.'}
    $path=[IO.Path]::GetFullPath($Executable)
    $name=[IO.Path]::GetFileNameWithoutExtension($path)
    $processes=@(Get-Process -ErrorAction Stop | Where-Object ProcessName -eq $name | Select-Object -First 65)
    if($processes.Count -gt 64){$result.reason='candidate_limit_exceeded';return $result}
    foreach($process in $processes){
        try{
            if($process.HasExited){continue}
            $image=$process.Path
            if(-not $image){throw 'Process image is inaccessible.'}
            if([IO.Path]::GetFullPath($image) -ne $path){continue}
            if($process.SessionId -ne $currentSession){continue}
            $result.candidates+=@([pscustomobject]@{pid=$process.Id;path=$image;sessionId=$process.SessionId;creationUtc=$process.StartTime.ToUniversalTime().ToString('o')})
        }catch{$native=Get-GdiagNativeError $_;$result.inspectionGaps+=@{pid=$process.Id;domain=$native.domain;code=$native.code}}
    }
    if($result.inspectionGaps.Count){$result.reason='candidate_identity_inaccessible';$result.error=$result.inspectionGaps[0]}
    elseif($result.candidates.Count -eq 0){$result.status='host_verification_pending';$result.reason='no_selected_host_in_executor_session'}
    elseif($result.candidates.Count -gt 1){$result.reason='multiple_selected_host_instances'}
    else{$result.status='singleton_verified';$result.selected=$result.candidates[0]}
    $result
}
function Invoke-GdiagProbe {
    param([hashtable]$Context,$Target,[string]$Probe,[int]$TimeoutSeconds=10)
    if($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 60){throw 'Probe timeout must be 1..60 seconds.'}
    if($Probe -eq 'Runtime' -or $Probe -eq 'Python') {
        $python=$Target.pythonPath
        if(-not $python -and $Target.path -match '(?i)python(?:w)?\.exe$'){$python=$Target.path}
        if(-not $python -and $Target.family -eq 'GstarAssistant'){$runtimeRoot=$Target.path;if($Target.payloadRoot){$runtimeRoot=$Target.payloadRoot};$python=Join-Path $runtimeRoot 'python\runtime\Python311\python.exe'}
        if(-not $python -or -not [IO.File]::Exists($python)){
            if($Target.family -eq 'GstarAssistant'){
                $runtimeRoot=$Target.path;if($Target.payloadRoot){$runtimeRoot=$Target.payloadRoot}
                $dll=Join-Path $runtimeRoot 'python\runtime\Python311\python311.dll'
                if([IO.File]::Exists($dll)){
                    $result=Invoke-GdiagNativeDllProbe -DllPath $dll -PythonInitialize -TimeoutSeconds $TimeoutSeconds
                    New-GdiagNativeObservation 'python_runtime' $result.status @{metadata=(Get-GdiagFileIdentity $dll);probe=$result;hostBinding='not_tested';startupMode='isolated_dll_explicit_home_no_site'} $null $Target.id;return
                }
            }
            New-GdiagNativeObservation 'python_runtime' 'unavailable' @{note='Select an explicit interpreter or an installed private Python DLL; file presence alone does not establish startup.'} $null $Target.id;return
        }
        $metadata=Get-GdiagFileIdentity $python
        $result=Invoke-GdiagOwnedProcess $python '-I -X utf8 -c "import sys,json,sqlite3,ssl; print(json.dumps(dict(executable=sys.executable,version=sys.version,stdlib=True,prefix=sys.prefix)))"' $TimeoutSeconds
        New-GdiagNativeObservation 'python_runtime' $result.status @{metadata=$metadata;probe=$result;hostBinding='not_tested';webviewCreation='not_tested'} $null $Target.id
    } elseif($Probe -eq 'Automation') {
        if($Target.progId){Get-GdiagComEvidence -Context $Context -Target $Target}
        if(-not $Target.pythonPath){New-GdiagNativeObservation 'automation_import' 'unavailable' @{note='An explicit dedicated interpreter is required; no global pip mutation is performed.'} $null $Target.id;return}
        $result=Invoke-GdiagOwnedProcess $Target.pythonPath '-I -c "import sys,json,importlib.metadata as m; import pygcadwin; print(json.dumps(dict(executable=sys.executable,prefix=sys.prefix,pygcadwin=m.version(''pygcadwin''))))"' $TimeoutSeconds
        New-GdiagNativeObservation 'automation_import' $result.status $result $null $Target.id
        New-GdiagNativeObservation 'automation_host' 'host_verification_pending' @{note='Package import does not prove COM attachment. Use Attach only after selecting a verified ProgID and host executable.'} $null $Target.id
    } elseif($Probe -eq 'Attach') {
        if(-not $Target.progId -or -not $Target.path){throw 'Attach requires an explicit target ProgID and host executable path.'}
        Get-GdiagComEvidence -Context $Context -Target $Target
        $selectedExecutable=$Target.path
        if($Target.family -eq 'GstarCAD' -and $Target.file.path){$selectedExecutable=$Target.file.path}
        $selection=Get-GdiagComHostSelection -Executable $selectedExecutable -Context $Context
        if($selection.status -ne 'singleton_verified'){
            $observation=New-GdiagNativeObservation 'com_attach' $selection.status $selection $null $Target.id
            $observation.summary.reason=$selection.reason;$observation.summary.candidateCount=$selection.candidates.Count
            $observation.summary.nextAction='Select a unique existing host in the affected executor session using fresh evidence; do not close unrelated drawings or start a host for this probe.'
            $observation;return
        }
        $expected=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($selection.selected|ConvertTo-Json -Compress)))
        # An owned child checks the ROT object against HWND owner PID/start/session.
        # FullName alone cannot select between two instances of the same executable.
        $code=@'
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
. 'MODULE_LITERAL'
$expected=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('EXPECTED_B64')))|ConvertFrom-Json
$app=$null;$stage='window_identity_api'
try{
 Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class GdiagComWindowOwner {
 [DllImport("user32.dll",SetLastError=true)] public static extern uint GetWindowThreadProcessId(IntPtr handle,out uint pid);
}
"@ | Out-Null
 $stage='get_active_object'
 $app=[Runtime.InteropServices.Marshal]::GetActiveObject('SELECTED_PROGID')
 $stage='executable_identity'
 if([IO.Path]::GetFullPath([string]$app.FullName) -ne [IO.Path]::GetFullPath($expected.path)){throw 'ROT object executable differs from selected host.'}
 $stage='window_owner_identity'
 $handle=[IntPtr]([long]$app.HWND);[uint32]$ownerPid=0
 if($handle -eq [IntPtr]::Zero){throw 'Selected COM object has no usable HWND.'}
 $thread=[GdiagComWindowOwner]::GetWindowThreadProcessId($handle,[ref]$ownerPid)
 if($thread -eq 0 -or $ownerPid -eq 0){throw (New-Object ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))}
 $stage='process_identity'
 $owner=Get-Process -Id $ownerPid -ErrorAction Stop
 $actual=@{pid=$owner.Id;sessionId=$owner.SessionId;path=$owner.Path;creationUtc=$owner.StartTime.ToUniversalTime().ToString('o')}
 $identity=Test-GdiagComHostIdentity $expected $actual
 $record=@{status=$(if($identity.matches){'attached'}else{'host_selection_unresolved'});stage=$stage;identity=$identity;host=$actual;documentAccess='not_attempted';hostCreatedOrClosed=$false}
}catch{
 $native=$_.Exception
 for($i=0;$i -lt 8 -and $native.InnerException;$i++){$native=$native.InnerException}
 $record=@{status='host_selection_unresolved';stage=$stage;nativeErrorDomain='HRESULT';nativeErrorCode=$native.HResult}
 if($native -is [ComponentModel.Win32Exception]){$record.nativeErrorDomain='Win32';$record.nativeErrorCode=$native.NativeErrorCode}
}finally{
 if($app){try{[void][Runtime.InteropServices.Marshal]::ReleaseComObject($app)}catch{$record.cleanupError=Get-GdiagNativeError $_}}
}
$record|ConvertTo-Json -Depth 8 -Compress
'@
        $code=$code.Replace('MODULE_LITERAL',(Join-Path $PSScriptRoot 'Windows.ps1').Replace("'","''")).Replace('EXPECTED_B64',$expected).Replace('SELECTED_PROGID',([string]$Target.progId))
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
        $result=Invoke-GdiagOwnedProcess (Get-GdiagWindowsPowerShellPath) "-NoProfile -NonInteractive -EncodedCommand $encoded" $TimeoutSeconds
        if($result.status -eq 'observed'){
            try{
                $attached=ConvertFrom-Json -InputObject $result.stdout -ErrorAction Stop
                $result.status=$attached.status;$result.stage=$attached.stage
                if($attached.nativeErrorDomain){$result.error=@{domain=$attached.nativeErrorDomain;code=$attached.nativeErrorCode}}
            }catch{$result.status='collection_error';$result.stage='attach_result_json'}
        }
        $observation=New-GdiagNativeObservation 'com_attach' $result.status $result $null $Target.id
        $observation.summary.selectedProcessId=$selection.selected.pid;$observation.summary.selectedSessionId=$selection.selected.sessionId;$observation.summary.selectedProcessStartUtc=$selection.selected.creationUtc
        $observation
    }elseif($Probe -eq 'Events'){Get-GdiagEventEvidence $Context}
    elseif($Probe -eq 'Native' -or $Probe -eq 'PythonDll'){
        $dll=$Target.nativePath
        if(-not $dll -and $Target.family -eq 'GstarAssistant'){$runtimeRoot=$Target.path;if($Target.payloadRoot){$runtimeRoot=$Target.payloadRoot};$dll=Join-Path $runtimeRoot 'python\runtime\Python311\python311.dll'}
        if(-not $dll){throw 'Select an explicit nativePath or a GstarAssistant target.'}
        $result=Invoke-GdiagNativeDllProbe -DllPath $dll -PythonInitialize:($Probe -eq 'PythonDll') -TimeoutSeconds $TimeoutSeconds
        New-GdiagNativeObservation 'native_runtime' $result.status @{metadata=(Get-GdiagFileIdentity $dll);probe=$result;hostBinding='not_tested'} $null $Target.id
    }elseif($Probe -eq 'WebView'){
        Get-GdiagWebViewEvidence -Context $Context -Target $Target
    }elseif($Probe -eq 'Storage' -or $Probe -eq 'StorageWrite'){
        Get-GdiagStorageEvidence -Target $Target -WriteProbe:($Probe -eq 'StorageWrite')
    }else{throw "Unsupported Windows probe: $Probe"}
}
function Invoke-GdiagNativeDllProbe {
    param([string]$DllPath,[switch]$PythonInitialize,[int]$TimeoutSeconds=10)
    $metadata=Get-GdiagFileIdentity $DllPath
    if($metadata.status -ne 'observed'){return @{status=$metadata.status;stage='dll_metadata';error=$metadata.error}}
    if(-not [IO.Path]::IsPathRooted($DllPath)){throw 'Native probe requires an absolute DLL path.'}
    if($DllPath -notmatch '(?i)\.dll$'){throw 'Select a DLL; generic-process GRX loading is not a valid host probe.'}
    $child=(Join-Path $PSScriptRoot 'NativeChild.ps1').Replace("'","''")
    $literal=$DllPath.Replace("'","''")
    $code="& '$child' -DllPath '$literal'"
    if($PythonInitialize){$code+=' -PythonInitialize'}
    $exe=Get-GdiagWindowsPowerShellPath $metadata.architecture
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $result=Invoke-GdiagOwnedProcess $exe "-NoProfile -NonInteractive -EncodedCommand $encoded" $TimeoutSeconds
    $result.nativeStages=@(foreach($line in ([string]$result.stdout -split '\r?\n')){try{$record=$line | ConvertFrom-Json -ErrorAction Stop;if($record.stage){@{stage=$record.stage;nativeErrorDomain=$record.nativeErrorDomain;nativeErrorCode=$record.nativeErrorCode}}}catch{}})
    $result
}
function Get-GdiagStorageEvidence {
    param($Target,[switch]$WriteProbe)
    $path=$Target.storagePath
    if(-not $path -or -not [IO.Path]::IsPathRooted([string]$path)){throw 'Storage probe requires an explicit absolute storagePath directory.'}
    $ownedPath=$null;$stream=$null
    try {
        $directory=Get-Item -LiteralPath $path -ErrorAction Stop
        if(-not $directory.PSIsContainer){throw 'Select a directory; this probe never opens a conversation database.'}
        $parent=$directory
        while($parent){if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){New-GdiagNativeObservation 'storage_directory' 'unavailable' @{stage='reparse_boundary';databaseStatus='not_tested'} $null $Target.id;return};$parent=$parent.Parent}
        if(-not $WriteProbe){New-GdiagNativeObservation 'storage_directory' 'observed' @{stage='metadata_only';path=$directory.FullName;databaseStatus='not_tested';writeAccess='not_tested'} $null $Target.id;return}
        $ownedPath=Join-Path $directory.FullName ('.gcaddiag-probe-'+[guid]::NewGuid().ToString('N')+'.tmp')
        $stream=[IO.FileStream]::new($ownedPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None,4096,[IO.FileOptions]::DeleteOnClose)
        $stream.WriteByte(0x47);$stream.Flush();$stream.Position=0
        if($stream.ReadByte() -ne 0x47){throw 'Owned directory probe readback mismatch.'}
        $stream.Dispose();$stream=$null
        $ownedPath=$null
        New-GdiagNativeObservation 'storage_directory' 'observed' @{stage='owned_file_read_write_delete';databaseStatus='not_tested';directoryAccess='verified_for_executor_only'} $null $Target.id
    }catch{New-GdiagNativeObservation 'storage_directory' $(if($_.CategoryInfo.Category -eq 'ObjectNotFound'){'absent'}else{Get-GdiagErrorStatus $_}) @{stage='directory_access';databaseStatus='not_tested';ownedProbeResidue=$ownedPath} $_ $Target.id}
    finally{if($stream){$stream.Dispose()}}
}
function Get-GdiagWebViewEvidence {
    param([hashtable]$Context,$Target)
    $catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../catalog/products.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach($view in @('Registry32','Registry64')){
        foreach($location in @(@{hive='LocalMachine';prefix='SOFTWARE';sid=$null},@{hive='Users';prefix="$($Context.affectedSid)\Software";sid=$Context.affectedSid})){
            $subkey=([string]$catalog.webview.registrySubkey).Replace('/','\')
            $record=Get-GdiagRegistryRecord $location.hive $view "$($location.prefix)\$subkey" $location.sid
            $version=Get-GdiagRegValue $record @('pv')
            $valid=$false;$parsedVersion=$null
            if($version -and [Version]::TryParse([string]$version,[ref]$parsedVersion)){$valid=$parsedVersion -gt [Version]'0.0.0.0'}
            $observation=New-GdiagNativeObservation 'webview_registration' $record.status @{registry=$record;registeredVersion=$version;runtimeAdvertised=$valid;environmentCreation='not_tested';controllerCreation='not_tested';fixedVersionRuntime='not_inferred_from_evergreen_registration'} $null $Target.id
            $observation.summary.runtimeAdvertised=$valid;$observation.summary.registeredVersion=$(if($parsedVersion){$parsedVersion.ToString()}else{'invalid_or_absent'})
            $observation
        }
    }
    New-GdiagNativeObservation 'webview_creation' 'host_verification_pending' @{stage='independent_webview_creation';note='No independent shipped WebView creation helper was found in reviewed product sources. Evergreen registration is metadata, not controller or product profile health.'} $null $Target.id
}
function Get-GdiagComEvidence {
    param([hashtable]$Context,$Target)
    if(([string]$Target.progId) -notmatch '^[A-Za-z][A-Za-z0-9_.-]{0,127}$'){throw 'Invalid selected COM ProgID.'}
    foreach($view in @('Registry64','Registry32')) {
        foreach($location in @(@{hive='Users';prefix="$($Context.affectedSid)\Software\Classes";sid=$Context.affectedSid},@{hive='LocalMachine';prefix='SOFTWARE\Classes';sid=$null})) {
            $registration=Get-GdiagRegistryRecord $location.hive $view "$($location.prefix)\$($Target.progId)\CLSID" $location.sid
            $clsid=Get-GdiagRegValue $registration @('')
            $servers=@()
            if($clsid -and ([string]$clsid) -match '^\{[0-9a-fA-F-]{36}\}$') {
                foreach($model in @('LocalServer32','InprocServer32')) {
                    $server=Get-GdiagRegistryRecord $location.hive $view "$($location.prefix)\CLSID\$clsid\$model" $location.sid
                    $servers+=@{model=$model;record=$server}
                }
            }
            New-GdiagNativeObservation 'com_registration' $registration.status @{progId=$Target.progId;registration=$registration;servers=$servers;precedence='selected-user registration may override machine registration';architecture='InprocServer32 must match client; LocalServer32 bitness alone is not a failure';sessionIntegrity='executor context recorded; actual server identity requires host process evidence'} $null $Target.id
        }
    }
}
