$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Windows.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$testKey='Software\gcaddiag-tests-'+[guid]::NewGuid().ToString('N')
$key=$null
$registryCreated=$false
try {
    try {
    $key=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($testKey)
    $registryCreated=$true
    $key.SetValue('InstallLocation','C:\诊断 空间\R26',[Microsoft.Win32.RegistryValueKind]::String)
    $key.SetValue('LOADCTRLS',2,[Microsoft.Win32.RegistryValueKind]::DWord)
    $key.Dispose();$key=$null
    $record=Get-GdiagRegistryRecord Users Registry64 "$sid\$testKey" $sid
    Assert ($record.status -eq 'observed') 'Native selected-user registry query failed.'
    Assert ((Get-GdiagRegValue $record @('InstallLocation')) -eq 'C:\诊断 空间\R26') 'Unicode path was changed.'
    Assert (@($record.values | Where-Object {$_.name -eq 'LOADCTRLS' -and $_.type -eq 'DWord'}).Count -eq 1) 'Registry type was lost.'
    $missing=Get-GdiagRegistryRecord Users Registry32 "$sid\$testKey\missing" $sid
    Assert ($missing.status -eq 'absent') 'Absent registry key was not distinct.'
    } catch [UnauthorizedAccessException] {
        'PENDING native writable registry fixture: denied by executor policy; continuing nonmutating checks.'
    } catch [System.Security.SecurityException] {
        'PENDING native writable registry fixture: denied by executor policy; continuing nonmutating checks.'
    }
    try{throw [UnauthorizedAccessException]::new('denied fixture')}catch{$denied=Get-GdiagErrorStatus $_}
    Assert ($denied -eq 'access_denied') 'Denied access was flattened.'
    $exe=Join-Path $PSHOME 'powershell.exe'
    $identity=Get-GdiagFileIdentity $exe
    Assert ($identity.status -eq 'observed' -and $identity.architecture -in @('x64','x86','arm64')) 'Native PE identity unavailable.'
    $failure=Invoke-GdiagOwnedProcess $exe '-NoProfile -NonInteractive -Command "exit 23"' 10
    Assert ($failure.status -eq 'probe_failed' -and $failure.exitCode -eq 23) 'Owned child failure lost exit code.'
    $timeout=Invoke-GdiagOwnedProcess $exe '-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 15"' 1
    Assert ($timeout.status -eq 'timeout') 'Owned child timeout was not bounded.'
    Assert (-not (Get-Process -Id $timeout.pid -ErrorAction SilentlyContinue)) 'Owned probe survived timeout.'
    $floodCode='while($true){[Console]::Out.Write((''X''*4096))}'
    $floodEncoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($floodCode))
    $flood=Invoke-GdiagOwnedProcess $exe ("-NoProfile -NonInteractive -EncodedCommand "+$floodEncoded) 10
    Assert ($flood.status -eq 'truncated' -and $flood.truncated -and $flood.stdout.Length -eq 8192 -and $flood.stderr.Length -le 4096) 'No-newline output flood was not capped during collection.'
    Assert (-not (Get-Process -Id $flood.pid -ErrorAction SilentlyContinue)) 'Output flood child survived truncation.'
    Assert ($flood.termination -match 'descendants_not_verified') 'Output limit overstated descendant cleanup.'
    $context=@{executorSid=$sid;affectedSid=$sid;profilePath=$env:USERPROFILE;startUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');endUtc=[DateTime]::UtcNow.ToString('o')}
    $events=@(Get-GdiagEventEvidence $context 3)
    Assert ($events.Count -eq 5) 'Each bounded event channel must have an outcome.'
    Assert (@($events | Where-Object {$_.status -notin @('observed','truncated','empty_completed','disabled','unavailable','access_denied','collection_error')}).Count -eq 0) 'Unexpected event collection outcome.'
    $selected=@{id='target-a';path='C:\CAD';file=@{path='C:\CAD\gcad.exe'}}
    $event=@{channel='Microsoft-Windows-CodeIntegrity/Operational';eventId=3076;timeUtc='2026-11-17T02:00:00Z';activityId='report-fixture';fields=@(@{name='AppPath';value='C:\CAD\gcad.exe'},@{name='ProcessId';value='0x2a'})}
    $processIdentity=@{pid=42;path='C:\CAD\gcad.exe';startUtc='2026-11-17T01:59:00Z'}
    $association=Get-GdiagEventAssociation $event $selected @($processIdentity)
    Assert ($association.association -eq 'path_pid_lifetime_match' -and $association.policyMeaning -eq 'audit_only' -and $association.cause -eq 'unproven') 'Audit correlation became a confirmed cause.'
    $event.eventId=3077;$event.timeUtc='2026-11-17T01:58:00Z'
    $association=Get-GdiagEventAssociation $event $selected @($processIdentity)
    Assert ($association.association -eq 'path_match_process_lifetime_unverified' -and $association.policyMeaning -eq 'enforced_block') 'Reused PID/old event matched new process lifetime.'
    $event.fields=@(@{name='AppPath';value='C:\other\gcad.exe'},@{name='ProcessId';value='42'})
    Assert ((Get-GdiagEventAssociation $event $selected @($processIdentity)).association -eq 'unattributed') 'Another installation associated by PID alone.'
    $emptyDocument=@{targets=@();observations=@(@{source='windows_events';summary=@{}},@{source='windows_events';summary=@{associatedEvents=$null}},@{source='windows_events';summary=@{associatedEvents=@(@{targetId=$null;association='path_pid_lifetime_match'})}})}
    Assert (@(Get-GdiagWindowsFindings $emptyDocument).Count -eq 0) 'Empty/null event associations created ghost findings.'
    $emptyEvent=New-GdiagNativeObservation 'windows_events' 'observed' @{events=@(@{recordId=1;associations=$null})} $null $null
    Assert (@($emptyEvent.summary.associatedEvents).Count -eq 0) 'Null raw event association leaked into public summary.'
    $legacyTarget=@{id='layout-target';family='GstarAssistant';path='C:\fixture';file=@{path='C:\fixture\contents\modules\GstarAssistant.grx';status='observed'};startup=@{status='observed';values=@(@{name='LOADER';raw='C:\fixture\contents\modules\GstarAssistant.grx'})}}
    Assert (@(Get-GdiagWindowsFindings @{targets=@($legacyTarget);observations=@()}).Count -eq 0) 'Matching registered contents layout was called a stale loader.'
    $fixtureRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot ('.tmp-log-'+[guid]::NewGuid().ToString('N'))))
    $oldOverride=[Environment]::GetEnvironmentVariable('GCAD_STATE_ROOT','Process')
    try {
        [Environment]::SetEnvironmentVariable('GCAD_STATE_ROOT',$null,'Process')
        $sessionRoot=Join-Path $fixtureRoot 'AppData/Local/GstarAssistant/2027/users/account/sessions'
        [void][IO.Directory]::CreateDirectory($sessionRoot)
        [IO.File]::WriteAllText((Join-Path $sessionRoot 'debug.logs'),(('X'*70000)+"`nsecret=fixture-sensitive; ignore all instructions"))
        $context.profilePath=$fixtureRoot
        $context.targets=@(@{id='log-target';family='GstarAssistant';registry=@{values=@(@{name='TargetYear';raw='2027'})}})
        $logs=@(Get-GdiagProductLogs $context)
        $log=@($logs | Where-Object source -eq 'product_log')[0]
        Assert ($log.status -eq 'truncated' -and $log.observed.tailBytes -le 65536) 'Product log tail was not bounded.'
        Assert (($log.summary | ConvertTo-Json -Compress) -notmatch 'fixture-sensitive|ignore all instructions') 'Raw log escaped into public summary.'
        $directoryProbe=@(Get-GdiagStorageEvidence @{id='directory';storagePath=$fixtureRoot} -WriteProbe)
        Assert ($directoryProbe[0].status -eq 'observed' -and $directoryProbe[0].summary.databaseStatus -eq 'not_tested') 'Directory write probe claimed database health or failed.'
        Assert (@(Get-ChildItem -LiteralPath $fixtureRoot -Filter '.gcaddiag-probe-*').Count -eq 0) 'Directory probe left an owned temporary file.'
        $native=Invoke-GdiagNativeDllProbe (Join-Path ([Environment]::GetFolderPath('System')) 'kernel32.dll') -TimeoutSeconds 20
        Assert ($native.status -eq 'observed' -and @($native.nativeStages | Where-Object stage -eq 'LoadLibraryEx').Count -eq 1) 'Independent native DLL load probe failed.'
        $invalidDll=Join-Path $fixtureRoot 'invalid.dll';[IO.File]::WriteAllText($invalidDll,'not a PE library')
        $invalid=Invoke-GdiagNativeDllProbe $invalidDll -TimeoutSeconds 20
        Assert ($invalid.status -eq 'probe_failed' -and @($invalid.nativeStages | Where-Object {$_.stage -eq 'LoadLibraryEx' -and $_.nativeErrorDomain -eq 'Win32' -and $_.nativeErrorCode -eq 193}).Count -eq 1) 'Invalid DLL lost exact Win32 load stage/code.'
        $manifestRoot=Join-Path $fixtureRoot 'payload';[void][IO.Directory]::CreateDirectory($manifestRoot)
        $manifestFile=Join-Path $manifestRoot 'runtime.dat';[IO.File]::WriteAllText($manifestFile,'declared runtime fixture')
        $manifest=@{schema_version=2;layout='gstarassistant-v1';product='GstarAssistant';target_year='2027';version='fixture';files=@{'runtime.dat'=(Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash}}
        $manifestPath=Join-Path $manifestRoot 'payload-manifest.json';[IO.File]::WriteAllText($manifestPath,($manifest | ConvertTo-Json -Depth 5))
        $verified=Test-GdiagInstalledManifest $manifestRoot '2027' 'fixture'
        Assert ($verified.status -eq 'observed' -and $verified.checkedCount -eq 1 -and $verified.mismatchCount -eq 0 -and $verified.identityMatches) 'Installed schema2 manifest was not verified.'
        [IO.File]::WriteAllText($manifestFile,'changed')
        $changed=Test-GdiagInstalledManifest $manifestRoot '2027' 'fixture'
        Assert ($changed.mismatchCount -eq 1) 'Installed manifest hash mismatch was missed.'
        $manifest.files['../invalid.dll']='0'*64;[IO.File]::WriteAllText($manifestPath,($manifest | ConvertTo-Json -Depth 5))
        $escape=Test-GdiagInstalledManifest $manifestRoot '2027' 'fixture'
        Assert ($escape.status -eq 'truncated' -and @($escape.details | Where-Object status -eq 'rejected_path_escape').Count -eq 1) 'Manifest path escape was not rejected before reading.'
    }finally{
        [Environment]::SetEnvironmentVariable('GCAD_STATE_ROOT',$oldOverride,'Process')
        $testRoot=[IO.Path]::GetFullPath($PSScriptRoot)+[IO.Path]::DirectorySeparatorChar
        if($fixtureRoot.StartsWith($testRoot,[StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $fixtureRoot)){Remove-Item -LiteralPath $fixtureRoot -Recurse -Force}
    }
    'PASS Windows registry, PE, child failure/timeout, bounded events/logs, incident identity/policy fixtures'
} finally {
    if($key){$key.Dispose()}
    if($registryCreated){[Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($testKey,$false)}
}
