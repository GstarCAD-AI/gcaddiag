# Windows PowerShell 5.1; typed file/package operations only.
if(-not (Get-Command Assert-GdiagPlainPath -ErrorAction SilentlyContinue)){. (Join-Path $PSScriptRoot 'Evidence.ps1')}
function Get-GdiagFileHash($Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}
function Get-GdiagTree($Path) {
    $root = Assert-GdiagPlainPath $Path
    $result = @()
    if (Test-Path -LiteralPath $root) {
        # Explicit stack so a junction is rejected before descending through it.
        $stack = New-Object 'Collections.Generic.Stack[string]'; $stack.Push($root)
        while ($stack.Count) {
            foreach ($item in Get-ChildItem -LiteralPath $stack.Pop() -Force -ErrorAction Stop) {
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point inside selected tree refused.' }
                if ($item.PSIsContainer) { $stack.Push($item.FullName) }
                else { $result += [pscustomobject]@{relative=$item.FullName.Substring($root.TrimEnd('\').Length+1);hash=(Get-GdiagFileHash $item.FullName);size=$item.Length} }
            }
        }
    }
    @($result | Sort-Object relative)
}
function Get-GdiagTreeHash($Tree) {
    $canonical = (@($Tree | Sort-Object relative | ForEach-Object { $_.relative.Replace('\','/') + ':' + $_.hash }) -join "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical)))).Replace('-','') } finally { $sha.Dispose() }
}
function Write-GdiagLifeJson($Path,$Value) {
    $destination=Assert-GdiagPlainPath $Path
    $temporary=Assert-GdiagPlainPath (Join-Path (Split-Path -Parent $destination) ('.gcaddiag-state-'+[guid]::NewGuid()+'.tmp'))
    $json=ConvertTo-Json -InputObject $Value -Depth 24
    $stream=$null;$created=$false
    try {
        # Commit complete bytes on the same volume. Failed serialization, writes,
        # or replacement must leave the last usable recovery state intact.
        $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$created=$true
        $encoding=New-Object Text.UTF8Encoding($true)
        $bytes=[byte[]]($encoding.GetPreamble()+$encoding.GetBytes($json+[Environment]::NewLine))
        $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true);$stream.Dispose();$stream=$null
        [void](Assert-GdiagPlainPath $destination)
        if(Test-Path -LiteralPath $destination){
            # Same-directory journals normally inherit identical permissions.
            # Avoid requiring WRITE_DAC to merge those identical ACLs, but never
            # discard a destination's distinct restrictions on a merge failure.
            $access=[Security.AccessControl.AccessControlSections]::Access
            $currentAcl=(Get-Acl -LiteralPath $destination -ErrorAction Stop).GetSecurityDescriptorSddlForm($access)
            $stagedAcl=(Get-Acl -LiteralPath $temporary -ErrorAction Stop).GetSecurityDescriptorSddlForm($access)
            [IO.File]::Replace($temporary,$destination,[NullString]::Value,($currentAcl -ceq $stagedAcl))
        }
        else{[IO.File]::Move($temporary,$destination)}
    } finally {
        if($stream){$stream.Dispose()}
        if($created -and (Test-Path -LiteralPath $temporary)){Remove-Item -LiteralPath $temporary -Force -ErrorAction Stop}
    }
}
function Test-GdiagProtectedPackageFile($Relative) {
    ($Relative -match '(^|[\\/])(GUIDELINE\.md|TASKS\.md|\.git|\.gcaddiag-package\.json|\.env|credentials(?:\.json)?|id_rsa|id_ed25519)([\\/]|$)' -or $Relative -match '\.(dwg|dxf|db|sqlite|pfx|key)$')
}
function Invoke-GdiagLifeProcess($Executable,[string[]]$Arguments,$CasePath,[int]$TimeoutSeconds,[bool]$Interactive=$false) {
    $logId=[guid]::NewGuid().ToString()
    $stdout=Join-Path $CasePath ($logId+'.probe.stdout');$stderr=Join-Path $CasePath ($logId+'.probe.stderr')
    $quoted=@($Arguments | ForEach-Object {
        if($_ -match '["\r\n]'){throw 'Unsupported quote/newline in typed process argument.'}
        '"'+([regex]::Replace($_,'(\\+)$','$1$1'))+'"'
    }) -join ' '
    $priorBytecode=$env:PYTHONDONTWRITEBYTECODE;$priorCachePrefix=$env:PYTHONPYCACHEPREFIX
    try {
        # Child ensurepip processes inherit these; -B alone is not inherited by them.
        $env:PYTHONDONTWRITEBYTECODE='1';$env:PYTHONPYCACHEPREFIX=$null
        $windowStyle=if($Interactive){'Normal'}else{'Hidden'}
        $process=Start-Process -FilePath $Executable -ArgumentList $quoted -WindowStyle $windowStyle -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ErrorAction Stop
    } finally {$env:PYTHONDONTWRITEBYTECODE=$priorBytecode;$env:PYTHONPYCACHEPREFIX=$priorCachePrefix}
    # Retain the native handle before WaitForExit; PS5 Start-Process otherwise loses ExitCode.
    $nativeHandle=$process.Handle
    $clock=[Diagnostics.Stopwatch]::StartNew();$status='completed';$terminationGap=$null
    while (-not $process.WaitForExit(100)) {
        $size=0L;foreach($path in @($stdout,$stderr)){if(Test-Path -LiteralPath $path){$size+=(Get-Item -LiteralPath $path).Length}}
        if ($clock.Elapsed.TotalSeconds -gt $TimeoutSeconds -or $size -gt 65536) {
            $status=if($size -gt 65536){'truncated'}else{'timeout'}
            $terminationGap='Manual attention required: descendants are not contained by a process job; confirm no owned child remains before recovery.'
            # Capture descendant identities while the owned root is still live.
            $owned=@($process)
            try {
                $queue=New-Object 'Collections.Generic.Queue[object]';$queue.Enqueue($process)
                while($queue.Count -and $owned.Count -lt 64){
                    $parentProcess=$queue.Dequeue()
                    if($parentProcess.HasExited){continue}
                    $childRecords=@(Get-CimInstance Win32_Process -Filter ('ParentProcessId='+$parentProcess.Id) -OperationTimeoutSec 2 -ErrorAction Stop)
                    if($parentProcess.HasExited){continue}
                    foreach($child in $childRecords){
                        $childProcess=Get-Process -Id $child.ProcessId -ErrorAction Stop
                        $childHandle=$childProcess.Handle
                        $observedStart=([datetime]$child.CreationDate).ToUniversalTime()
                        $actualStart=$childProcess.StartTime.ToUniversalTime()
                        if($actualStart -ge $parentProcess.StartTime.ToUniversalTime() -and [Math]::Abs(($actualStart-$observedStart).Ticks) -le 10){$owned+=$childProcess;$queue.Enqueue($childProcess)}
                        else{$childProcess.Dispose();$terminationGap='A descendant process identity changed; unverified processes were not terminated.'}
                    }
                }
                if($queue.Count){$terminationGap='Owned descendant enumeration exceeded bound.'}
            } catch {$terminationGap='Descendant inspection unavailable; only known owned processes can be stopped.'}
            foreach($ownedProcess in @($owned | Sort-Object StartTime -Descending)){
                try{if(-not $ownedProcess.HasExited){$ownedProcess.Kill()}}catch{$terminationGap='An owned process could not be stopped; inspect local process state.'}
            }
            $process.WaitForExit(5000) | Out-Null;break
        }
    }
    $text=New-Object Text.StringBuilder
    $finalSize=0L;foreach($path in @($stdout,$stderr)){if(Test-Path -LiteralPath $path){$finalSize+=(Get-Item -LiteralPath $path).Length}}
    if($finalSize -gt 65536 -and $status -eq 'completed'){$status='truncated'}
    foreach($path in @($stdout,$stderr)) {
        if(Test-Path -LiteralPath $path){$reader=[IO.File]::OpenText($path);try{$buffer=New-Object char[] 32768;$count=$reader.Read($buffer,0,$buffer.Length);[void]$text.Append($buffer,0,$count)}finally{$reader.Dispose()}}
    }
    $exitCode=if($process.HasExited){$process.ExitCode}else{$null}
    $processResult=[pscustomobject]@{status=$status;exitCode=$exitCode;output=$text.ToString();stdout=$stdout;stderr=$stderr;terminationGap=$terminationGap}
    Write-GdiagLifeJson (Join-Path $CasePath ($logId+'.probe.json')) $processResult
    $processResult
}
function Test-GdiagAutomationEnvironment($Plan) {
    $python=Join-Path $Plan.destination 'Scripts/python.exe'
    $pins=(@($Plan.dependencies) -join ',')
    # Pins contain only validated name/version characters, never Python source.
    $code="import sys,json,sqlite3,ssl,venv,importlib.metadata as m; pins='$pins'.split(',') if '$pins' else []; versions={p.split('==')[0]:m.version(p.split('==')[0]) for p in pins}; assert all(versions[p.split('==')[0]]==p.split('==')[1] for p in pins); __import__('pygcadwin') if any(p.split('==')[0].lower()=='pygcadwin' for p in pins) else None; assert sys.prefix != sys.base_prefix; print(json.dumps({'python':sys.executable,'versions':versions,'automation':'package-import-only' if pins else 'stdlib-only','host':'pending'}))"
    Invoke-GdiagLifeProcess $python @('-I','-B','-c',$code) $Plan.casePath $Plan.timeoutSeconds
}
function Assert-GdiagAutomationIdle($Destination,[string[]]$RelevantProcessNames=@('python','pythonw')) {
    foreach($running in Get-Process -ErrorAction Stop){
        $image=$null
        try{$image=$running.Path}catch{
            if($running.ProcessName -in $RelevantProcessNames){throw 'Cannot resolve a relevant running process; selected-target use is unverified.'}
        }
        if(-not $image -and $running.ProcessName -in $RelevantProcessNames){throw 'Cannot resolve a relevant running process; collect with sufficient selected-target access.'}
        if($image -and $image.StartsWith($Destination.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Selected installation/environment is in use; close only the affected process before applying.'}
    }
}
function Get-GdiagVendorManifest($Path,$Hash,$Release) {
    $Path=Assert-GdiagPlainPath $Path
    $manifestFile=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($manifestFile.PSIsContainer -or $manifestFile.Length -gt 16777216){throw 'Payload manifest must be a file of at most 16 MiB; full inventory cannot be truncated.'}
    if(-not $Hash -or (Get-GdiagFileHash $Path) -ne $Hash){throw 'Trusted payload-manifest SHA256 mismatch.'}
    $manifest=Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    $catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../catalog/products.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $releaseInfo=@($catalog.releases|Where-Object release -eq $Release)
    if($Release -notin @('R26','R27') -or $releaseInfo.Count -ne 1){throw 'Only reviewed R26/R27 package contracts are executable; B27 compatibility pending.'}
    if($manifest.schema_version -ne 2 -or $manifest.product -ne 'GstarAssistant' -or $manifest.layout -ne 'gstarassistant-v1' -or [string]$manifest.target_year -ne $releaseInfo[0].year -or -not $manifest.version){throw 'Payload manifest product/layout/release mismatch.'}
    $entries=@($manifest.files.PSObject.Properties)
    if(-not $entries.Count -or $entries.Count -gt 100000){throw 'Complete payload inventory requires 1..100000 entries; inventory cannot be truncated.'}
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach($entry in $entries){
        if([IO.Path]::IsPathRooted($entry.Name) -or $entry.Name -match '[<>:"|?*\x00-\x1F]' -or $entry.Value -notmatch '^[A-Fa-f0-9]{64}$'){throw 'Unsafe payload inventory entry.'}
        $canonical=$entry.Name.Replace('/','\')
        foreach($segment in @($canonical -split '\\')){
            if(-not $segment -or $segment -in @('.','..') -or $segment.EndsWith('.') -or $segment.EndsWith(' ') -or $segment -match '^(?i:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9\u00B9\u00B2\u00B3]|LPT[1-9\u00B9\u00B2\u00B3])(?:\.|$)'){throw 'Payload path contains a noncanonical or Windows device component.'}
        }
        if(-not $seen.Add($canonical)){throw 'Payload inventory contains duplicate Windows file identities.'}
    }
    foreach($relative in @($catalog.assistantPayload)+@($releaseInfo[0].additionalPayload)){
        if($relative -eq 'payload-manifest.json'){continue}
        $relative=$relative.Replace('{year}',[string]$manifest.target_year).Replace('\','/')
        if(-not @($entries|Where-Object {$_.Name.Replace('\','/') -eq $relative}).Count){throw "Incomplete payload inventory: $relative"}
    }
    $manifest
}
function Assert-GdiagVendorTrust($Path,$Hash,$Publisher,$Version) {
    if([IO.Path]::GetExtension($Path) -ne '.exe' -or -not $Hash -or (Get-GdiagFileHash (Assert-GdiagPlainPath $Path)) -ne $Hash){throw 'Selected installer executable/hash mismatch.'}
    $signature=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if(-not $Publisher -or $signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -ne $Publisher){throw 'Installer Authenticode trust/publisher mismatch.'}
    $metadata=[Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $productName=[string][char]0x6D69+[char]0x8FB0+'AI'+[char]0x52A9+[char]0x624B
    if($metadata.ProductName -ne $productName -or $metadata.ProductVersion -ne $Version){throw 'Installer product/version does not match reviewed GstarAssistant package.'}
}
function Get-GdiagVendorRegistration($Release,$Locale) {
    if($Release -notin @('R26','R27') -or $Locale -notmatch '^[A-Za-z0-9_-]+$'){throw 'Unsupported release/locale registration component.'}
    $root=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryView]::Registry64)
    $snapshots=@()
    try{
        foreach($key in @("Software\Gstarsoft\GstarAssistant\$Release","Software\Microsoft\Windows\CurrentVersion\Uninstall\GstarAssistant $Release","Software\Gstarsoft\GstarCAD\$Release\$Locale\Applications\GstarAssistant")){
            $opened=$root.OpenSubKey($key)
            $values=@();try{if($opened){foreach($name in @($opened.GetValueNames()|Sort-Object)){$values+=[pscustomobject]@{name=$name;kind=$opened.GetValueKind($name).ToString();value=$opened.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}}}}finally{if($opened){$opened.Dispose()}}
            $snapshots+=[pscustomobject]@{hive='HKCU';view='Registry64';key=$key;exists=($null -ne $opened);values=$values}
        }
    }finally{$root.Dispose()}
    $snapshots
}
function Get-GdiagRegistrationHash($Snapshot){
    $sha=[Security.Cryptography.SHA256]::Create()
    try{([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($Snapshot|ConvertTo-Json -Depth 12 -Compress))))).Replace('-','')}finally{$sha.Dispose()}
}
function Test-GdiagVendorInstalled($Plan){
    $manifest=Get-GdiagVendorManifest $Plan.payloadManifestPath $Plan.payloadManifestHash $Plan.release
    if((Get-GdiagFileHash (Join-Path $Plan.destination 'payload-manifest.json')) -ne $Plan.payloadManifestHash){return $false}
    foreach($entry in $manifest.files.PSObject.Properties){
        $path=Assert-GdiagPlainPath (Join-Path $Plan.destination $entry.Name)
        if(-not $path.StartsWith($Plan.destination.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or (Get-GdiagFileHash $path) -ne $entry.Value){return $false}
    }
    # The NSIS release contract writes three related HKCU64 keys. Validate their
    # location/version/startup relationship, including the uninstall entry;
    # payload presence must not hide a partially failed registration.
    $productRelease=$Plan.hostTarget.release
    if($productRelease -notin @('R26','R27') -or $productRelease -ne $Plan.release){return $false}
    $startupKey="Software\Gstarsoft\GstarCAD\$productRelease\$($Plan.locale)\Applications\GstarAssistant"
    $loader=Join-Path $Plan.destination 'modules/GstarAssistant.grx'
    $uninstaller=Assert-GdiagPlainPath (Join-Path $Plan.destination 'uninstall.exe')
    if(-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)){return $false}
    $expected=@(
        @{key="Software\Gstarsoft\GstarAssistant\$($Plan.release)";strings=@{
            InstallDir=$Plan.destination;InstallLocation=$Plan.destination;DisplayVersion=$manifest.version;
            TargetYear=[string]$manifest.target_year;Release=$Plan.release;GrxPath=$loader;RuntimeGrxPath=$loader;
            SkillsPath=(Join-Path $Plan.destination 'skills');GcadLocale=$Plan.locale;
            GcadProductRelease=$productRelease;GcadStartupKey=$startupKey};dwords=@{}},
        @{key="Software\Microsoft\Windows\CurrentVersion\Uninstall\GstarAssistant $($Plan.release)";strings=@{
            InstallLocation=$Plan.destination;DisplayVersion=$manifest.version;UninstallString=('"'+$uninstaller+'"')};dwords=@{NoModify=1;NoRepair=1}},
        @{key=$startupKey;strings=@{DESCRIPTION='Gstar Assistant';LOADER=$loader};dwords=@{LOADCTRLS=2}}
    )
    $registration=@(Get-GdiagVendorRegistration $Plan.release $Plan.locale)
    foreach($required in $expected){
        $records=@($registration|Where-Object {$_.hive -eq 'HKCU' -and $_.view -eq 'Registry64' -and $_.key -eq $required.key})
        if($records.Count -ne 1 -or -not $records[0].exists){return $false}
        foreach($name in $required.strings.Keys){
            $values=@($records[0].values|Where-Object name -eq $name)
            if($values.Count -ne 1 -or $values[0].kind -ne 'String' -or $values[0].value -ne $required.strings[$name]){return $false}
        }
        foreach($name in $required.dwords.Keys){
            $values=@($records[0].values|Where-Object name -eq $name)
            if($values.Count -ne 1 -or $values[0].kind -ne 'DWord' -or $values[0].value -ne $required.dwords[$name]){return $false}
        }
    }
    $true
}
function New-GdiagPlan {
    param($Context,$Target,[string]$Operation,[hashtable]$Options)
    if (-not $Options) { $Options=@{} }
    if (-not $Target -and $Operation -eq 'Setup' -and $Options.destinationPath) {
        $family=if($Options.recipe -eq 'automation-venv'){'AutomationEnvironment'}elseif($Options.recipe -eq 'vendor-package'){'GstarAssistant'}elseif($Options.recipe -eq 'cli-package'){'gcad-cli'}else{'Skill'}
        $Target=[pscustomobject]@{id=('intended-'+[guid]::NewGuid().ToString());family=$family;path=[IO.Path]::GetFullPath($Options.destinationPath);release=$null;state='intended'}
    }
    $plan = [ordered]@{schemaVersion=1;planId=[guid]::NewGuid().ToString();caseId=$Context.caseId;casePath=$Context.casePath;machine=$Context.machine;executorSid=$Context.executorSid;affectedSid=$Context.affectedSid;target=$Target;operation=$Operation;recipe=$Options.recipe;createdUtc=[DateTime]::UtcNow.ToString('o');status='planned';privilege='affected-user';processRequirement='No affected host may be using the selected skill files.';reversible=$true;restartRequired=$false;verification='File integrity only; actual external-host discovery/operation remains pending.';changes=@();limits=@()}
    if ($Context.executorSid -ne $Context.affectedSid) { throw 'Per-user planning requires affected-user execution; recollect using that user.' }
    if($Operation -eq 'Repair' -and $Options.recipe -eq 'codex-mcp-stdio'){
        if(-not (Get-Command New-GdiagCodexMcpPlan -ErrorAction SilentlyContinue)){. (Join-Path $PSScriptRoot 'CodexMcpRepair.ps1')}
        return New-GdiagCodexMcpPlan $Context $Target $Options
    }
    if($Options.recipe -eq 'cli-package' -and $Operation -in @('Setup','Repair','Update')){
        if(-not (Get-Command New-GdiagCliPlan -ErrorAction SilentlyContinue)){. (Join-Path $PSScriptRoot 'CliPackage.ps1')}
        return New-GdiagCliPlan $Context $Target $Operation $Options
    }
    if($Operation -eq 'Repair' -and $Options.recipe -eq 'vc-redist-x64'){
        if(-not (Get-Command New-GdiagPrerequisitePlan -ErrorAction SilentlyContinue)){. (Join-Path $PSScriptRoot 'PrerequisiteRepair.ps1')}
        return New-GdiagPrerequisitePlan $Context $Target $Options
    }
    if ($Operation -eq 'Cleanup' -and $Options.recipe -eq 'installer-artifact') {return New-GdiagCleanupPlan -Context $Context -Target $Target -Options $Options}
    if ($Operation -eq 'Repair' -and $Options.recipe -eq 'trace-logging') {return New-GdiagTracePlan -Context $Context -Target $Target -Options $Options}
    if ($Operation -eq 'Uninstall') {
        if(-not (Get-Command Get-GdiagUninstallPreparation -ErrorAction SilentlyContinue)){. (Join-Path $PSScriptRoot 'UninstallPreparation.ps1')}
        $plan.status='guidance_only';$plan.reversible=$false
        $plan.preparation=Get-GdiagUninstallPreparation -Context $Context -Target $Target
        $plan.limits=@('Vendor uninstall execution pending isolated installation acceptance. Review the selected installation inventory and resolve preservation/ownership gaps before any vendor uninstall. No files have been backed up or removed.')
        return [pscustomobject]$plan
    }
    if($Operation -eq 'Repair' -and $Options.recipe -eq 'webview-profile'){
        $catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../catalog/products.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $plan.status='guidance_only';$plan.reversible=$false;$plan.profileContract=$catalog.webviewProfile
        $plan.limits=@('The reviewed product requests a new profile per host instance; a historical profile reset is not a verified repair mechanism.',
            'Establish the installed contract, effective host state root, exact profile and browser PID/start identity. Executor defaults or names alone do not establish ownership.',
            'Use an owned temporary WebViewCreate probe and product diagnostics to identify the failing creation stage. Preserve existing profiles and authentication state.')
        return [pscustomobject]$plan
    }
    if ($Options.recipe -eq 'vendor-package' -and $Operation -in @('Setup','Repair','Update')) {
        if($Target.family -ne 'GstarAssistant' -or $Options.setupContract -ne 'gstarassistant-nsis-v1'){throw 'vendor-package requires the reviewed GstarAssistant NSIS contract and selected assistant target.'}
        foreach($name in @('silent','agreementsAccepted')){if($Options.ContainsKey($name) -and $Options[$name] -isnot [bool]){throw "$name must be a JSON boolean."}}
        $targets=if($Context.targets){@($Context.targets)}else{@((Get-Content -LiteralPath (Join-Path $Context.casePath 'case.json') -Raw -Encoding UTF8|ConvertFrom-Json).targets)}
        $hostTarget=@($targets|Where-Object id -eq $Options.hostTargetId)
        if($hostTarget.Count -ne 1 -or $hostTarget[0].family -ne 'GstarCAD' -or $hostTarget[0].release -notin @('R26','R27')){throw 'Select one case-local supported GstarCAD host; unknown/B27 package applicability is pending.'}
        $hostTarget=$hostTarget[0];$release=$hostTarget.release
        if($Options.packageRelease -ne $release){throw 'Selected trusted package release metadata must match the chosen host release; executable product/version alone does not establish target-year compatibility.'}
        if($Target.release -and $Target.release -ne $release){throw 'Selected assistant and host releases differ.'};$Target.release=$release
        $locale=$hostTarget.locale
        if($locale -notmatch '^[A-Za-z0-9_-]+$' -or $locale -in @('R26','R27','B27')){throw 'Selected host locale is unresolved.'}
        $hostRoot=Assert-GdiagPlainPath $hostTarget.path
        $hostExe=Join-Path $hostRoot 'gcad.exe';if(-not(Test-Path -LiteralPath $hostExe)){$hostExe=Join-Path $hostRoot 'GstarCAD.exe'}
        if(-not $Options.expectedHostHash -or (Get-GdiagFileHash $hostExe) -ne $Options.expectedHostHash){throw 'Selected host executable identity/hash mismatch.'}
        $destination=Assert-GdiagPlainPath $Target.path
        if($destination -eq $hostRoot -or $destination.StartsWith($hostRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $hostRoot.StartsWith($destination.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Assistant package must remain separate from its CAD host installation.'}
        if([IO.Path]::GetFullPath($Context.casePath).StartsWith($destination.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $destination -eq [IO.Path]::GetFullPath($Context.casePath)){throw 'Product destination cannot contain its diagnostic case.'}
        $manifest=Get-GdiagVendorManifest $Options.payloadManifestPath $Options.payloadManifestHash $release
        Assert-GdiagVendorTrust $Options.packagePath $Options.expectedPackageHash $Options.expectedPublisher $manifest.version
        if($Options.silent -eq $true -and $Options.agreementsAccepted -ne $true){throw 'Silent vendor execution requires user-selected agreements acceptance captured in the concrete plan.'}
        $tree=@(Get-GdiagTree $destination)
        if($Operation -eq 'Setup' -and $tree.Count){throw 'Setup requires an empty product destination; use reconciled Repair/Update for an installed release.'}
        if($Operation -ne 'Setup'){
            $oldManifestPath=Join-Path $destination 'payload-manifest.json'
            $oldManifest=$null
            try{$oldManifest=Get-GdiagVendorManifest $oldManifestPath (Get-GdiagFileHash $oldManifestPath) $release}
            catch{
                if($Operation -ne 'Repair' -or $Options.recoverMissingManifest -ne $true){throw}
                . (Join-Path $PSScriptRoot 'LegacyRecovery.ps1')
                $plan.legacyRecovery=Get-GdiagLegacyRecoveryAssessment $Target $manifest $tree $(if(Test-Path -LiteralPath $oldManifestPath){'invalid'}else{'absent'})
                if(-not $plan.legacyRecovery.canOverlay){
                    $plan.status='guidance_only';$plan.reversible=$false;$plan.destination=$destination
                    $plan.preparation=$plan.legacyRecovery;$plan.limits=$plan.legacyRecovery.limits
                    return [pscustomobject]$plan
                }
            }
            if($oldManifest){
            foreach($entry in $oldManifest.files.PSObject.Properties){
                $current=Get-GdiagFileHash (Join-Path $destination $entry.Name)
                if($current -and $current -ne $entry.Value){throw "Locally changed product payload/config requires explicit preservation/migration: $($entry.Name)"}
            }
            foreach($entry in $manifest.files.PSObject.Properties){
                $current=Get-GdiagFileHash (Join-Path $destination $entry.Name)
                $prior=@($oldManifest.files.PSObject.Properties|Where-Object Name -eq $entry.Name)
                if($current -and -not $prior.Count -and $current -ne $entry.Value){throw "New payload collides with a custom file: $($entry.Name)"}
            }
            }
        }
        $registration=@(Get-GdiagVendorRegistration $release $locale)
        $registeredLocation=@($registration[0].values|Where-Object name -eq 'InstallLocation')
        if($registeredLocation.Count -eq 1 -and $registeredLocation[0].value -and $registeredLocation[0].value -ne $destination){throw 'Selected release registration points to another installation; relocation is not an implicit setup/update action.'}
        $plan.destination=$destination;$plan.release=$release;$plan.locale=$locale;$plan.hostTarget=$hostTarget;$plan.hostExe=$hostExe;$plan.hostHash=$Options.expectedHostHash
        $plan.packagePath=Assert-GdiagPlainPath $Options.packagePath;$plan.packageHash=$Options.expectedPackageHash;$plan.publisher=$Options.expectedPublisher;$plan.version=$manifest.version;$plan.packageRelease=$Options.packageRelease
        $plan.payloadManifestPath=Assert-GdiagPlainPath $Options.payloadManifestPath;$plan.payloadManifestHash=$Options.payloadManifestHash;$plan.targetYear=[string]$manifest.target_year
        $plan.beforeTree=$tree;$plan.beforeTreeHash=Get-GdiagTreeHash $tree;$plan.registrationBefore=$registration;$plan.registrationBeforeHash=Get-GdiagRegistrationHash $registration
        $plan.silent=($Options.silent -eq $true);$plan.agreementsAccepted=($Options.agreementsAccepted -eq $true);$plan.timeoutSeconds=300;$plan.reversible=$false
        $plan.changes=@([pscustomobject]@{path=$destination;action='vendor-payload-and-registration-reinstall';version=$manifest.version;host=$hostRoot;year=$plan.targetYear;registration=$registration;generatedFiles=@('app_icon.ico','uninstall.exe');originals='Full selected installation file snapshot, including existing generated icon/uninstaller, plus typed HKCU64 values in local case';privilege='Per-user installer; embedded prerequisite may request machine privilege through vendor UI'})
        $plan.verification='Complete supplied payload manifest and selected HKCU64 installation/startup values; runtime startup and licensed CAD host loading remain pending.'
        $plan.limits=@('Package release and installer/manifest hash association must come from the selected trusted release/offline package; Authenticode/product-version metadata alone does not attest embedded target-year payload.','Vendor prerequisite/migration changes are not automatically reversible; embedded VC++ installer may run /quiet /norestart and require UAC.','Reviewed NSIS prerequisite 3010 can be consumed internally without propagation; installed-prerequisite/reboot readiness remains unverified even after installer exit 0.','No automatic Undo for vendor installation or schema migrations. Local originals are recovery material, not a transactional rollback.','Actual vendor package acceptance pending isolated supported installation; fixture checks are not product recovery evidence.')
    } elseif ($Options.recipe -eq 'automation-venv' -and $Operation -in @('Setup','Repair','Update')) {
        if ($Target.family -ne 'AutomationEnvironment' -or -not $Target.path) { throw 'automation-venv requires a selected dedicated AutomationEnvironment target.' }
        if ($Options.standalonePython -ne $true) { throw 'Explicit standalone Python selection is required; product-private/global environments are never modified.' }
        $python=Assert-GdiagPlainPath $Options.pythonPath
        if (-not $Options.expectedPythonHash -or (Get-GdiagFileHash $python) -ne $Options.expectedPythonHash) { throw 'Selected base interpreter hash mismatch.' }
        if ($python -match '(?i)[\\/](GstarAssistant|gcad-cli)[\\/]') { throw 'Product-private Python is not a supported automation base.' }
        $destination=Assert-GdiagPlainPath $Target.path
        $isProfileRoot=$false
        if($Context.profilePath){$isProfileRoot=$destination.TrimEnd('\') -eq ([IO.Path]::GetFullPath($Context.profilePath)).TrimEnd('\')}
        if ($destination.TrimEnd('\') -eq [IO.Path]::GetPathRoot($destination).TrimEnd('\') -or $isProfileRoot) { throw 'A profile or volume root cannot be a dedicated environment.' }
        if ([IO.Path]::GetFullPath($Context.casePath).StartsWith($destination.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $destination -eq [IO.Path]::GetFullPath($Context.casePath)) { throw 'A dedicated environment cannot contain its diagnostic case.' }
        if ($python.StartsWith($destination.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Base interpreter cannot be inside the managed environment.' }
        if ($Operation -eq 'Setup' -and (Test-Path -LiteralPath $destination)) { throw 'Fresh dedicated environment requires an absent destination.' }
        if ($Operation -ne 'Setup') {
            $marker=Get-Content -LiteralPath (Join-Path $destination 'gcaddiag-environment.json') -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
            if ($marker.owner -ne 'gcaddiag' -or $marker.recipe -ne 'automation-venv') { throw 'Existing environment is not owned by this recipe.' }
        }
        $wheels=@()
        foreach($wheel in @($Options.wheels)) {
            if (-not $wheel) { continue }
            $wheelPath=Assert-GdiagPlainPath $wheel.path
            if ([IO.Path]::GetExtension($wheelPath) -ne '.whl' -or -not $wheel.sha256 -or (Get-GdiagFileHash $wheelPath) -ne $wheel.sha256) { throw 'Each selected offline wheel requires an exact SHA256.' }
            $wheels += [pscustomobject]@{path=$wheelPath;sha256=$wheel.sha256}
        }
        $dependencies=@($Options.dependencies | Where-Object {$_})
        foreach($dep in $dependencies) { if ($dep -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9][A-Za-z0-9_.+!-]*$') { throw 'Dependencies must be exact package==version pins, without URLs/options.' } }
        if ($dependencies.Count -and -not $wheels.Count) { throw 'Pinned dependencies require supplied trusted offline wheels.' }
        $plan.destination=$destination;$plan.pythonPath=$python;$plan.pythonHash=$Options.expectedPythonHash;$plan.wheels=$wheels;$plan.dependencies=$dependencies
        $plan.beforeTreeHash=Get-GdiagTreeHash @(Get-GdiagTree $destination)
        $plan.stagePath=$destination+'.gcaddiag-stage-'+$plan.planId;$plan.previousPath=$destination+'.gcaddiag-previous-'+$plan.planId
        $plan.timeoutSeconds=if($Options.timeoutSeconds){[int]$Options.timeoutSeconds}else{120}
        if($plan.timeoutSeconds -lt 1 -or $plan.timeoutSeconds -gt 300){throw 'timeoutSeconds must be 1..300.'}
        $plan.changes=@([pscustomobject]@{path=$destination;action='create-dedicated-venv';launcher=(Join-Path $destination 'Scripts/python.exe');basePython=$python;dependencies=$dependencies;previousEnvironment=$plan.previousPath})
        $plan.verification='Exact venv interpreter, stdlib startup, pinned package metadata and pygcadwin import when selected; selected CAD attach remains pending.'
        $plan.limits=@('Requires explicitly selected standalone base Python and trusted offline wheels. No network/package resolver and no host launch.','Existing environment is preserved beside the destination; custom files remain there and are not migrated into a different runtime.','Stop affected automation before Apply. No process is closed automatically. Imported packages are trusted selected code.','No dependencies selected means stdlib-only readiness, not gcadclaw automation readiness.')
    } elseif ($Options.recipe -eq 'skill-package' -and $Operation -in @('Setup','Repair','Update')) {
        if (-not $Target.path) { throw 'Skill target requires an explicit destination path.' }
        if ($Target.family -ne 'Skill') { throw 'skill-package requires an intended or inventoried Skill target.' }
        $destination = Assert-GdiagPlainPath $Target.path
        $source = Assert-GdiagPlainPath $Options.sourcePath
        if ($source -eq $destination -or $destination.StartsWith($source.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $source.StartsWith($destination.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Source and destination trees must be separate.' }
        if (-not (Test-Path -LiteralPath (Join-Path $source 'SKILL.md') -PathType Leaf)) { throw 'Source package lacks SKILL.md.' }
        $sourceTree = @(Get-GdiagTree $source)
        $packageHash = Get-GdiagTreeHash $sourceTree
        if (-not $Options.expectedPackageHash -or $Options.expectedPackageHash -ne $packageHash) { throw "Trusted package tree SHA256 required; measured tree hash: $packageHash" }
        $existing = @(Get-GdiagTree $destination)
        $ownedFile = Join-Path $destination '.gcaddiag-package.json'
        $owned = $null
        if (Test-Path -LiteralPath $ownedFile) { $owned=Get-Content -LiteralPath $ownedFile -Raw -Encoding UTF8 | ConvertFrom-Json }
        if ($Operation -ne 'Setup' -and -not $owned) { throw 'Repair/update requires an installation originally recorded by gcaddiag; inspect/import existing local edits manually.' }
        if ($Operation -eq 'Setup' -and $existing.Count) { throw 'Setup requires an empty destination; existing installation must be reconciled first.' }
        foreach ($file in $sourceTree) {
            if (Test-GdiagProtectedPackageFile $file.relative) { throw 'Source package includes maintainer data or protected user/credential files.' }
            $path=Join-Path $destination $file.relative
            $current=Get-GdiagFileHash $path
            if ($current -and $owned) {
                $prior=@($owned.files | Where-Object relative -eq $file.relative)
                if ($current -ne $file.hash -and ($prior.Count -ne 1 -or $current -ne $prior[0].hash)) { throw "Local edit would be overwritten: $($file.relative)" }
            }
            if ($current -ne $file.hash) { $plan.changes += [pscustomobject]@{path=$path;relative=$file.relative;beforeHash=$current;afterHash=$file.hash;source=(Join-Path $source $file.relative)} }
        }
        # Removed files are deliberately retained, never inferred disposable.
        $plan.source=$source;$plan.packageHash=$packageHash;$plan.sourceTree=$sourceTree;$plan.destination=$destination;$plan.beforeTreeHash=Get-GdiagTreeHash $existing;$plan.metadataBeforeHash=Get-GdiagFileHash $ownedFile
        $plan.limits=@('Superseded resources are retained for explicit review. No credential/config migration or host process termination.','Source package authenticity must be established outside this checksum (trusted vendor or reviewed user package).','gcaddiag self-update must run after the active incident and from a separate installed copy.')
        $activeRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..')).TrimEnd('\')
        if ($destination.TrimEnd('\') -eq $activeRoot) { throw 'Active gcaddiag distribution cannot update itself; finish incident and run a separate copy.' }
    } elseif ($Options.recipe -eq 'old-case' -and $Operation -eq 'Cleanup') {
        if ($Target.family -ne 'Case') { throw 'old-case requires an explicitly selected Case target.' }
        $destination=Assert-GdiagPlainPath $Target.path
        if ($destination -eq [IO.Path]::GetFullPath($Context.casePath)) { throw 'Cannot clean the active case.' }
        $caseFile=Join-Path $destination 'case.json'
        $old=Get-Content -LiteralPath $caseFile -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
        if (-not $old.caseId -or $old.formatVersion -ne 1 -or -not $old.context) { throw 'Selected directory is not a gcaddiag case.' }
        if ($old.context.affectedSid -ne $Context.affectedSid -or $old.context.machine -ne $Context.machine) { throw 'Old case belongs to a different machine or affected user.' }
        $tree=@(Get-GdiagTree $destination)
        foreach($file in $tree) { if ($file.relative -notmatch '^(case\.json|report\.md|observations\.json|findings\.json|actions\.jsonl)$') { throw 'Custom or unrecognized case files must be preserved/resolved before cleanup.' } }
        $plan.destination=$destination;$plan.beforeTreeHash=Get-GdiagTreeHash $tree;$plan.quarantine=$destination+'.gcaddiag-quarantine-'+$plan.planId
        $plan.changes=@([pscustomobject]@{path=$destination;action='quarantine';bytes=($tree | Measure-Object size -Sum).Sum;ownership="Selected gcaddiag case $($old.caseId)"})
        $plan.verification='Selected case quarantined; no product installation touched.'
    } else {
        $plan.status='guidance_only';$plan.reversible=$false
        $plan.limits=@('No executable recipe for this product/remedy. Reconcile release, user, package identity and supported installer arguments before applying vendor maintenance.','GstarAssistant setup wrapper /REPAIR is payload/registration reinstallation, not a cause-specific repair. Exact installed setup version and full payload verification required.')
    }
    [pscustomobject]$plan
}
function Invoke-GdiagPlan {
    param([string]$PlanPath,[ValidateSet('Apply','Verify','Undo')][string]$Mode)
    $p=Get-Content -LiteralPath $PlanPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
    if ($p.schemaVersion -ne 1 -or $p.status -ne 'planned') { throw 'Plan is unsupported or guidance-only.' }
    $parsedPlanId=[guid]::Empty
    if(-not [guid]::TryParse([string]$p.planId,[ref]$parsedPlanId) -or $p.planId -notmatch '^[a-fA-F0-9-]{36}$'){throw 'Invalid plan identity; artifact paths must remain case-local.'}
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($p.machine -ne [Environment]::MachineName -or $p.executorSid -ne $sid -or $p.affectedSid -ne $sid) { throw 'Plan machine/affected-user identity is stale or belongs to another executor.' }
    $planDirectory=Assert-GdiagPlainPath (Split-Path -Parent ([IO.Path]::GetFullPath($PlanPath)))
    if ($planDirectory -ne [IO.Path]::GetFullPath($p.casePath)) { throw 'Plans must remain in their original local case.' }
    $case=Get-Content -LiteralPath (Join-Path $planDirectory 'case.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($case.caseId -ne $p.caseId) { throw 'Plan case identity mismatch.' }
    if($case.PSObject.Properties['kind'] -and $case.kind -ne 'local'){throw 'Analysis or shared customer evidence cannot authorize live maintenance.'}
    if ($case.formatVersion -ne 1 -or $case.context.machine -ne $p.machine -or $case.context.affectedSid -ne $sid -or $case.context.executorSid -ne $sid) { throw 'Case is imported, unsupported, or belongs to another context; recollect locally.' }
    $savedTarget=@($case.targets | Where-Object id -eq $p.target.id)
    if ($savedTarget.Count -ne 1 -or $savedTarget[0].path -ne $p.target.path -or $savedTarget[0].family -ne $p.target.family) { throw 'Plan target does not match its saved case identity.' }
    $destination=Assert-GdiagPlainPath $p.destination
    if (-not $p.target.path -or $destination -ne [IO.Path]::GetFullPath($p.target.path)) { throw 'Plan destination does not match selected target.' }
    if (($p.recipe -eq 'skill-package' -and ($p.target.family -ne 'Skill' -or $p.operation -notin @('Setup','Repair','Update'))) -or ($p.recipe -eq 'old-case' -and ($p.target.family -ne 'Case' -or $p.operation -ne 'Cleanup')) -or ($p.recipe -eq 'automation-venv' -and ($p.target.family -ne 'AutomationEnvironment' -or $p.operation -notin @('Setup','Repair','Update')))) { throw 'Plan operation does not match its typed recipe.' }
    if($p.recipe -eq 'old-case'){
        if($p.quarantine -ne $destination+'.gcaddiag-quarantine-'+$p.planId){throw 'Case quarantine must be the exact same-parent owned path.'}
        Assert-GdiagPlainPath $p.quarantine | Out-Null
    }
    if ($p.recipe -eq 'automation-venv') {
        if($p.timeoutSeconds -lt 1 -or $p.timeoutSeconds -gt 300){throw 'Invalid process timeout.'}
        foreach($dep in @($p.dependencies)){if($dep -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9][A-Za-z0-9_.+!-]*$'){throw 'Invalid dependency pin.'}}
        if($p.previousPath -ne $destination+'.gcaddiag-previous-'+$p.planId){throw 'Invalid preserved environment path.'}
        Assert-GdiagPlainPath $p.previousPath | Out-Null
    }
    if($p.recipe -eq 'vendor-package'){
        if($p.target.family -ne 'GstarAssistant' -or $p.operation -notin @('Setup','Repair','Update') -or $p.release -notin @('R26','R27') -or $p.packageRelease -ne $p.release){throw 'Invalid typed vendor recipe.'}
        if($p.silent -isnot [bool] -or $p.agreementsAccepted -isnot [bool]){throw 'Vendor silent/agreement choices must be JSON booleans.'}
        if($p.silent -and -not $p.agreementsAccepted){throw 'Silent agreement scope missing.'}
        if($p.timeoutSeconds -ne 300){throw 'Invalid vendor process bound.'}
        $savedHost=@($case.targets|Where-Object id -eq $p.hostTarget.id)
        if($savedHost.Count -ne 1 -or $savedHost[0].family -ne 'GstarCAD' -or $savedHost[0].path -ne $p.hostTarget.path -or $savedHost[0].release -ne $p.release -or $savedHost[0].locale -ne $p.locale){throw 'Selected CAD host identity changed.'}
        if($p.targetYear -ne ('20'+$p.release.Substring(1)) -or $p.hostExe -notin @((Join-Path $p.hostTarget.path 'gcad.exe'),(Join-Path $p.hostTarget.path 'GstarCAD.exe'))){throw 'Vendor host/release argument mismatch.'}
    }
    $statePath=Assert-GdiagPlainPath (Join-Path $planDirectory ($p.planId+'.state.json'))
    $journal=Assert-GdiagPlainPath (Join-Path $planDirectory 'actions.jsonl')
    $state=$null
    if (Test-Path -LiteralPath $statePath) { $state=Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json }
    $result=[ordered]@{planId=$p.planId;mode=$Mode;status='started';timeUtc=[DateTime]::UtcNow.ToString('o');restartRequired=$false;hostVerification='pending';changes=@()}
    ($result | ConvertTo-Json -Compress -Depth 8) | Add-Content -LiteralPath $journal -Encoding UTF8
    try {
        if($p.recipe -eq 'codex-mcp-stdio'){
            if(-not (Get-Command Invoke-GdiagCodexMcpPlan -ErrorAction SilentlyContinue)){. (Join-Path $PSScriptRoot 'CodexMcpRepair.ps1')}
            $mcpResult=Invoke-GdiagCodexMcpPlan $p $Mode $planDirectory
            foreach($property in $mcpResult.PSObject.Properties){$result[$property.Name]=$property.Value}
        } elseif($p.recipe -eq 'cli-package'){
            if(-not (Get-Command Invoke-GdiagCliPlan -ErrorAction SilentlyContinue)){. (Join-Path $PSScriptRoot 'CliPackage.ps1')}
            $cliResult=Invoke-GdiagCliPlan $p $Mode $planDirectory
            foreach($property in $cliResult.PSObject.Properties){$result[$property.Name]=$property.Value}
        } elseif($p.recipe -eq 'vc-redist-x64'){
            if(-not (Get-Command Invoke-GdiagPrerequisitePlan -ErrorAction SilentlyContinue)){. (Join-Path $PSScriptRoot 'PrerequisiteRepair.ps1')}
            $prerequisiteResult=Invoke-GdiagPrerequisitePlan $p $Mode $planDirectory
            foreach($property in $prerequisiteResult.PSObject.Properties){$result[$property.Name]=$property.Value}
        } elseif ($p.recipe -eq 'installer-artifact') {
            $cleanupResult=Invoke-GdiagCleanupPlan -Plan $p -Mode $Mode -PlanDirectory $planDirectory
            foreach ($property in $cleanupResult.PSObject.Properties) {$result[$property.Name]=$property.Value}
        } elseif($p.recipe -eq 'trace-logging'){
            $traceResult=Invoke-GdiagTracePlan -Plan $p -Mode $Mode -PlanDirectory $planDirectory
            foreach($property in $traceResult.PSObject.Properties){$result[$property.Name]=$property.Value}
        } elseif ($Mode -eq 'Apply') {
            if ($state) { throw 'Prior execution exists; inspect actual state and Verify/Undo before making a new plan.' }
            $currentTree=@(Get-GdiagTree $destination)
            if ((Get-GdiagTreeHash $currentTree) -ne $p.beforeTreeHash) { throw 'Stale plan: target files changed since planning.' }
            if($p.recipe -eq 'old-case'){
                # Saved plan hashes do not replace the recipe's ownership/disposability checks.
                $fresh=New-GdiagPlan @{caseId=$p.caseId;casePath=$planDirectory;machine=$p.machine;executorSid=$sid;affectedSid=$sid} $savedTarget[0] Cleanup @{recipe='old-case'}
                if($fresh.beforeTreeHash -ne $p.beforeTreeHash){throw 'Selected case changed during cleanup validation.'}
            }
            $state=[pscustomobject]@{planId=$p.planId;status='started';originals=@();afterTreeHash=$null;restartRequired=$false}
            Write-GdiagLifeJson $statePath $state
            if($p.recipe -eq 'vendor-package'){
                Assert-GdiagAutomationIdle $destination @('GstarAssistant','embedded_python');Assert-GdiagAutomationIdle $p.hostTarget.path @('gcad','gstarcad')
                if((Get-GdiagFileHash (Assert-GdiagPlainPath $p.hostExe)) -ne $p.hostHash){throw 'CAD host executable changed.'}
                $registrationBefore=@(Get-GdiagVendorRegistration $p.release $p.locale)
                if((Get-GdiagRegistrationHash $registrationBefore) -ne $p.registrationBeforeHash){throw 'Selected product registration changed since planning.'}
                $vendorManifest=Get-GdiagVendorManifest $p.payloadManifestPath $p.payloadManifestHash $p.release
                Assert-GdiagVendorTrust $p.packagePath $p.packageHash $p.publisher $vendorManifest.version
                if($p.legacyRecovery){
                    if($p.operation -ne 'Repair'){throw 'Unknown installed metadata cannot authorize an Update.'}
                    . (Join-Path $PSScriptRoot 'LegacyRecovery.ps1')
                    $recovery=Get-GdiagLegacyRecoveryAssessment $savedTarget[0] $vendorManifest $currentTree $p.legacyRecovery.installedManifestStatus
                    if(-not $recovery.canOverlay){throw 'Recovery now requires preservation/migration; recollect and replan.'}
                }
                $backupRoot=Assert-GdiagPlainPath (Join-Path $planDirectory ($p.planId+'.originals'))
                # Preserve the exact hash-matched live snapshots, not mutable preview arrays.
                foreach($file in $currentTree){
                    $original=Assert-GdiagPlainPath (Join-Path $destination $file.relative)
                    $backup=Assert-GdiagPlainPath (Join-Path $backupRoot $file.relative)
                    if(-not $original.StartsWith($destination.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or -not $backup.StartsWith($backupRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Backup entry escapes selected installation.'}
                    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $backup)|Out-Null
                    Copy-Item -LiteralPath $original -Destination $backup -ErrorAction Stop
                    if((Get-GdiagFileHash $backup) -ne $file.hash){throw 'Original backup does not match the selected file snapshot; installer was not launched.'}
                    $state.originals+=[pscustomobject]@{path=$original;beforeHash=$file.hash;backup=$backup}
                }
                Write-GdiagLifeJson $statePath $state
                Write-GdiagLifeJson (Join-Path $planDirectory ($p.planId+'.registry-originals.json')) $registrationBefore
                # Large backups leave time for a local editor or another installer to change state.
                # Recheck after preserving originals, before allowing the vendor to overwrite anything.
                if((Get-GdiagTreeHash @(Get-GdiagTree $destination)) -ne $p.beforeTreeHash){throw 'Selected installation changed during backup; preserve the current edits and replan before installing.'}
                if((Get-GdiagRegistrationHash @(Get-GdiagVendorRegistration $p.release $p.locale)) -ne $p.registrationBeforeHash){throw 'Selected registration changed during backup; installer was not launched.'}
                $installerArguments=@(('/TARGET='+$p.targetYear),('/TARGETPATH='+$p.hostTarget.path),('/INSTALLDIR='+$destination),('/LOGFILE='+(Join-Path $planDirectory ($p.planId+'.vendor.log'))))
                if($p.silent){$installerArguments=@('/S')+$installerArguments}
                if($p.operation -eq 'Repair'){$installerArguments+= '/REPAIR'}
                $installed=Invoke-GdiagLifeProcess $p.packagePath $installerArguments $p.casePath $p.timeoutSeconds (-not $p.silent)
                $result.nativeExitCode=$installed.exitCode;$result.installerLog=(Join-Path $planDirectory ($p.planId+'.vendor.log'))
                if($installed.status -ne 'completed' -or $installed.exitCode -notin @(0,3010)){throw "Vendor installer $($installed.status), exit $($installed.exitCode). $($installed.terminationGap) Inspect actual state before recovery."}
                $state.restartRequired=($installed.exitCode -eq 3010);$result.restartRequired=$state.restartRequired
                if(-not(Test-GdiagVendorInstalled $p)){throw 'Installer exited successfully but complete payload/selected registration verification failed.'}
                foreach($file in $currentTree){
                    # NSIS separately writes its icon and uninstaller. Their prior bytes
                    # are in originals; changed generated bytes are part of the preview.
                    if($file.relative -in @('payload-manifest.json','app_icon.ico','uninstall.exe')){continue}
                    if(-not @($vendorManifest.files.PSObject.Properties|Where-Object {$_.Name.Replace('\','/') -eq $file.relative.Replace('\','/')}).Count -and (Get-GdiagFileHash (Join-Path $destination $file.relative)) -ne $file.hash){throw 'Installer altered an unrelated/custom installation file; recovery originals retained.'}
                }
                $state.afterTreeHash=Get-GdiagTreeHash @(Get-GdiagTree $destination);$result.componentVerification='payload-and-registration-verified';$result.runtimeVerification='pending';$result.prerequisiteRebootStatus='unverified-vendor-may-consume-reboot-code'
            } elseif ($p.recipe -eq 'automation-venv') {
                Assert-GdiagAutomationIdle $destination
                if((Get-GdiagFileHash $p.pythonPath) -ne $p.pythonHash){throw 'Base Python changed.'}
                foreach($wheel in @($p.wheels)){if([IO.Path]::GetExtension($wheel.path) -ne '.whl' -or (Get-GdiagFileHash (Assert-GdiagPlainPath $wheel.path)) -ne $wheel.sha256){throw 'Offline wheel changed.'}}
                $identity=Invoke-GdiagLifeProcess $p.pythonPath @('-I','-B','-c','import sys; assert sys.prefix == sys.base_prefix; print(sys.executable)') $p.casePath $p.timeoutSeconds
                if($identity.status -ne 'completed' -or $identity.exitCode -ne 0){throw 'Selected interpreter is not a usable standalone base Python.'}
                if(Test-Path -LiteralPath $p.previousPath){throw 'Preserved environment destination already exists.'}
                if(Test-Path -LiteralPath $destination){Move-Item -LiteralPath $destination -Destination $p.previousPath -ErrorAction Stop}
                $created=Invoke-GdiagLifeProcess $p.pythonPath @('-I','-B','-m','venv',$destination) $p.casePath $p.timeoutSeconds
                if($created.status -ne 'completed' -or $created.exitCode -ne 0){throw "Dedicated venv creation $($created.status); $($created.terminationGap) Inspect local probe logs and preserved environment."}
                $venvPython=Join-Path $destination 'Scripts/python.exe'
                if(@($p.wheels).Count){
                    $installArguments=@('-I','-B','-m','pip','--isolated','install','--no-index','--no-deps','--no-cache-dir','--disable-pip-version-check','--force-reinstall')+@($p.wheels|ForEach-Object{$_.path})
                    $installed=Invoke-GdiagLifeProcess $venvPython $installArguments $p.casePath $p.timeoutSeconds
                    if($installed.status -ne 'completed' -or $installed.exitCode -ne 0){throw "Offline wheel install $($installed.status); $($installed.terminationGap) No host readiness claim."}
                }
                $checked=Test-GdiagAutomationEnvironment $p
                if($checked.status -ne 'completed' -or $checked.exitCode -ne 0){throw "Environment/package startup failed; $($checked.terminationGap) Inspect local probe logs."}
                Write-GdiagLifeJson (Join-Path $destination 'gcaddiag-environment.json') @{owner='gcaddiag';recipe='automation-venv';python=$p.pythonPath;dependencies=$p.dependencies;wheels=$p.wheels;launcher=$venvPython;hostVerification='pending'}
                $state.afterTreeHash=Get-GdiagTreeHash @(Get-GdiagTree $destination)
                $result.launcher=$venvPython;$result.readiness=if(@($p.dependencies).Count){'package-import-only'}else{'stdlib-only'}
            } elseif ($p.recipe -eq 'skill-package') {
                if ((Get-GdiagTreeHash @(Get-GdiagTree $p.source)) -ne $p.packageHash) { throw 'Source package changed since planning.' }
                foreach ($file in $p.changes) {
                    if (Test-GdiagProtectedPackageFile $file.relative) { throw 'Plan includes protected files.' }
                    if (-not $file.source -or -not $file.afterHash) { throw 'Payload changes require source and hash.' }
                }
                $backupRoot=Assert-GdiagPlainPath (Join-Path $planDirectory ($p.planId+'.originals'))
                New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
                $files=@($p.changes)+@([pscustomobject]@{path=(Join-Path $destination '.gcaddiag-package.json');relative='.gcaddiag-package.json';beforeHash=$p.metadataBeforeHash;afterHash=$null;source=$null})
                foreach($file in $files) {
                    $path=Assert-GdiagPlainPath $file.path
                    if (-not $path.StartsWith($destination.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'File change escapes target.' }
                    if ($path -ne [IO.Path]::GetFullPath((Join-Path $destination $file.relative))) { throw 'Plan relative path mismatch.' }
                    if ($file.source) {
                        $expectedSource=Assert-GdiagPlainPath (Join-Path $p.source $file.relative)
                        if ($file.source -ne $expectedSource -or -not $expectedSource.StartsWith($p.source.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Source file escapes package.' }
                        if ((Get-GdiagFileHash $expectedSource) -ne $file.afterHash) { throw 'Planned payload hash mismatch.' }
                    }
                    if ((Get-GdiagFileHash $path) -ne $file.beforeHash) { throw 'File precondition changed.' }
                    $backup=Assert-GdiagPlainPath (Join-Path $backupRoot ([guid]::NewGuid().ToString()+'.bin'))
                    if ($file.beforeHash) { Copy-Item -LiteralPath $path -Destination $backup -ErrorAction Stop }
                    $entry=[pscustomobject]@{path=$path;beforeHash=$file.beforeHash;backup=$backup;afterHash=$file.afterHash;completed=$false}
                    $state.originals+= $entry;Write-GdiagLifeJson $statePath $state
                    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
                    if ($file.source) { Copy-Item -LiteralPath $file.source -Destination $path -ErrorAction Stop }
                    else { Write-GdiagLifeJson $path ([pscustomobject]@{schemaVersion=1;owner='gcaddiag';packageHash=$p.packageHash;files=$p.sourceTree}) }
                    $entry.afterHash=Get-GdiagFileHash $path;$entry.completed=$true;Write-GdiagLifeJson $statePath $state
                }
                $state.afterTreeHash=Get-GdiagTreeHash @(Get-GdiagTree $destination)
            } elseif ($p.recipe -eq 'old-case') {
                if (Test-Path -LiteralPath $p.quarantine) { throw 'Quarantine destination already exists.' }
                # Both resolved absolute paths share the verified selected-case parent.
                $quarantine=Assert-GdiagPlainPath $p.quarantine
                if ((Split-Path -Parent $quarantine) -ne (Split-Path -Parent $destination)) { throw 'Quarantine must stay beside selected case.' }
                Move-Item -LiteralPath $destination -Destination $quarantine -ErrorAction Stop
                $state.afterTreeHash=$p.beforeTreeHash
            } else { throw 'Unknown executable recipe.' }
            $state.status='applied';Write-GdiagLifeJson $statePath $state
            $result.status=if($state.restartRequired){'restart_required'}elseif ($p.changes.Count) {'applied'} else {'already_correct'}
        } elseif ($Mode -eq 'Verify') {
            if (-not $state -or $state.status -ne 'applied') { throw 'No completed apply; inspect partial state before recovery.' }
            if ($p.recipe -eq 'old-case') { $ok= (-not (Test-Path -LiteralPath $destination)) -and ((Get-GdiagTreeHash @(Get-GdiagTree $p.quarantine)) -eq $state.afterTreeHash) }
            else { $ok=(Get-GdiagTreeHash @(Get-GdiagTree $destination)) -eq $state.afterTreeHash }
            if($ok -and $p.recipe -eq 'automation-venv'){$checked=Test-GdiagAutomationEnvironment $p;$ok=$checked.status -eq 'completed' -and $checked.exitCode -eq 0}
            if($ok -and $p.recipe -eq 'vendor-package'){$ok=Test-GdiagVendorInstalled $p;$result.runtimeVerification='pending';$result.componentVerification=if($ok){'payload-and-registration-verified'}else{'failed'};$result.restartRequired=$state.restartRequired}
            $result.status=if(-not $ok){'verification_failed'}elseif($state.restartRequired){'restart_required'}else{'verified'}
        } else {
            if (-not $state -or $state.status -ne 'applied') { throw 'Only completed supported operations can be undone; inspect interrupted state manually.' }
            if(-not $p.reversible){throw 'Vendor/prerequisite/migration rollback is unsupported. Originals remain for reviewed recovery; no automatic Undo.'}
            if ($p.recipe -eq 'automation-venv') {
                Assert-GdiagAutomationIdle $destination
                if((Get-GdiagTreeHash @(Get-GdiagTree $destination)) -ne $state.afterTreeHash){throw 'Undo preserves intervening environment changes.'}
                $retired=$destination+'.gcaddiag-undone-'+$p.planId;Assert-GdiagPlainPath $retired | Out-Null
                if(Test-Path -LiteralPath $retired){throw 'Undo preservation path exists.'}
                if(Test-Path -LiteralPath $p.previousPath){if((Get-GdiagTreeHash @(Get-GdiagTree $p.previousPath)) -ne $p.beforeTreeHash){throw 'Preserved original environment changed.'}}
                elseif($p.operation -ne 'Setup'){throw 'Preserved environment missing.'}
                Move-Item -LiteralPath $destination -Destination $retired -ErrorAction Stop
                if(Test-Path -LiteralPath $p.previousPath){Move-Item -LiteralPath $p.previousPath -Destination $destination -ErrorAction Stop}
            } elseif ($p.recipe -eq 'old-case') {
                if (Test-Path -LiteralPath $destination) { throw 'Undo preserves intervening replacement directory.' }
                if ((Get-GdiagTreeHash @(Get-GdiagTree $p.quarantine)) -ne $state.afterTreeHash) { throw 'Quarantined case changed; undo refused.' }
                Move-Item -LiteralPath $p.quarantine -Destination $destination -ErrorAction Stop
            } else {
                foreach($entry in $state.originals) {
                    $entryPath=Assert-GdiagPlainPath $entry.path
                    if (-not $entryPath.StartsWith($destination.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Undo entry escapes target.' }
                    if ($entry.path -eq (Join-Path $destination '.gcaddiag-package.json')) { $expectedBefore=$p.metadataBeforeHash }
                    else {
                        $planned=@($p.changes | Where-Object path -eq $entry.path)
                        if ($planned.Count -ne 1 -or $entry.afterHash -ne $planned[0].afterHash) { throw 'Undo state differs from planned payload changes.' }
                        $expectedBefore=$planned[0].beforeHash
                    }
                    if ($entry.beforeHash -ne $expectedBefore) { throw 'Undo original state differs from plan.' }
                    $backupPath=Assert-GdiagPlainPath $entry.backup
                    if (-not $backupPath.StartsWith((Join-Path $planDirectory ($p.planId+'.originals')).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Backup escapes plan originals.' }
                    if ((Get-GdiagFileHash $entry.path) -ne $entry.afterHash) { throw 'Undo preserves intervening user changes.' }
                    if($entry.beforeHash -and (Get-GdiagFileHash $entry.backup) -ne $entry.beforeHash) { throw 'Original backup integrity failed.' }
                }
                foreach($entry in $state.originals) { if($entry.beforeHash){Copy-Item -LiteralPath $entry.backup -Destination $entry.path -ErrorAction Stop}else{Remove-Item -LiteralPath $entry.path -ErrorAction Stop} }
            }
            $state.status='undone';Write-GdiagLifeJson $statePath $state;$result.status='undone'
        }
    } catch { $result.status='failed';$result.error=$_.Exception.Message }
    ($result | ConvertTo-Json -Compress -Depth 8) | Add-Content -LiteralPath $journal -Encoding UTF8
    [pscustomobject]$result
}
