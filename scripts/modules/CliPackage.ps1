# Portable gcad-cli-v1 distribution from IntelliDesign/scripts/products.py.
# Shared lifecycle primitives and Windows PE inspection are loaded by the entry.
function Get-GdiagCliRoot($Target) {
    if($Target.family -ne 'gcad-cli' -or -not $Target.path){throw 'cli-package requires the selected gcad-cli target.'}
    $path=Assert-GdiagPlainPath $Target.path
    if([IO.Path]::GetExtension($path) -eq '.exe'){
        if([IO.Path]::GetFileName($path) -notin @('gcad-cli.exe','gcad-tui.exe','gcad-batch.exe') -or (Split-Path -Leaf (Split-Path -Parent $path)) -ne 'bin'){throw 'Selected executable is not in the reviewed CLI bin layout.'}
        $path=Split-Path -Parent (Split-Path -Parent $path)
    }
    if($path.StartsWith('\\') -or $path.TrimEnd('\') -eq [IO.Path]::GetPathRoot($path).TrimEnd('\')){throw 'Select a dedicated local CLI directory.'}
    $path.TrimEnd('\')
}
function Get-GdiagCliManifest($Root,$ExpectedHash) {
    $path=Assert-GdiagPlainPath (Join-Path $Root 'payload-manifest.json')
    if(-not $ExpectedHash -or (Get-GdiagFileHash $path) -ne $ExpectedHash){throw 'Trusted CLI payload manifest SHA256 mismatch.'}
    if((Get-Item -LiteralPath $path).Length -gt 16777216){throw 'CLI manifest exceeds 16 MiB.'}
    $manifest=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if($manifest.schema_version -ne 2 -or $manifest.layout -ne 'gcad-cli-v1' -or $manifest.product -ne 'gcad-cli' -or $manifest.target_year -notin @('2026','2027') -or $manifest.files -isnot [pscustomobject]){throw 'Unsupported CLI payload manifest contract/year.'}
    $entries=@($manifest.files.PSObject.Properties)
    if(-not $entries.Count -or $entries.Count -gt 100000){throw 'CLI manifest needs 1..100000 complete entries.'}
    $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach($entry in $entries){
        $relative=$entry.Name.Replace('/','\')
        if([IO.Path]::IsPathRooted($relative) -or $relative -match '[<>:"|?*\x00-\x1f]' -or $entry.Value -notmatch '^[0-9a-fA-F]{64}$'){throw 'Unsafe CLI manifest entry.'}
        foreach($segment in @($relative -split '\\')){if(-not $segment -or $segment -in @('.','..') -or $segment.EndsWith('.') -or $segment.EndsWith(' ') -or $segment -match '^(?i:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9\u00B9\u00B2\u00B3]|LPT[1-9\u00B9\u00B2\u00B3])(?:\.|$)'){throw 'CLI manifest has a noncanonical Windows path.'}}
        if(-not $seen.Add($relative)){throw 'Duplicate CLI manifest file identity.'}
        if($relative -match '(?i)(^|\\)(?:\.env(?:\..*)?|auth\.json|credentials(?:\.json)?|id_rsa|id_ed25519|\.git|TASKS\.md|GUIDELINE\.md)(\\|$)' -or $relative -eq '.gcaddiag-cli.json' -or $relative -eq 'payload-manifest.json' -or $relative -match '\.grx$'){throw 'CLI package contains protected/unexpected product material.'}
    }
    $required=@('bin/gcad-cli.exe','bin/gcad.cp311-win_amd64.pyd','bin/arch2d.cp311-win_amd64.pyd','bin/architect2d-headless.dll','resources/configs/products/gcad-cli.json','resources/configs/agents/main-agent-cad-v1.json','resources/data/main_agent/runtime_manifest.json','resources/data/main_agent/prompts/main-agent-core-v1.md','resources/skills/gcad-skill-manager/SKILL.md','resources/python/runtime/Python311/python311.dll','python/pygcad/__init__.py','python/pygcadwin/__init__.py','python/pygcadwin/api.py','python/pygcadwin/types.py','python/pygcadwin/_com.py','share/licenses/pygcadwin/LICENSE')
    foreach($relative in @('pythoncom.py','win32com/client/__init__.py','win32/lib/pywintypes.py','pywin32_system32/pythoncom311.dll','pywin32_system32/pywintypes311.dll')){$required+='resources/python/runtime/Python311/Lib/site-packages/'+$relative}
    foreach($name in @('architecture_object_layer_rules.yaml','drawing_layer_assignment_rules.yaml','architecture_layers.xml')){$required+='resources/architect2d/rules/core/'+$name}
    foreach($relative in $required){if(-not $seen.Contains($relative.Replace('/','\'))){throw ('Incomplete CLI payload inventory: '+$relative)}}
    $manifest
}
function Get-GdiagCliTree($Root) {
    $rootPath=Assert-GdiagPlainPath $Root;$files=New-Object Collections.Generic.List[object];$bytes=0L;$count=0
    if(Test-Path -LiteralPath $rootPath){
        $stack=New-Object 'Collections.Generic.Stack[string]';$stack.Push($rootPath)
        while($stack.Count){foreach($path in [IO.Directory]::EnumerateFileSystemEntries($stack.Pop())){
            $count++;if($count -gt 100000){throw 'CLI tree exceeds 100000 entries; no truncated inventory can authorize replacement.'}
            $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'CLI tree contains a reparse point.'}
            if($item.PSIsContainer){$stack.Push($item.FullName);continue}
            $bytes+=$item.Length;if($bytes -gt 8589934592){throw 'CLI tree exceeds 8 GiB; select a supported bounded package.'}
            $files.Add([pscustomobject]@{relative=$item.FullName.Substring($rootPath.TrimEnd('\').Length+1);hash=(Get-GdiagFileHash $item.FullName);size=$item.Length})
        }}
    }
    @($files.ToArray() | Sort-Object relative)
}
function Assert-GdiagCliPayload($Root,$Manifest,$ManifestHash,[switch]$Exact) {
    $tree=@(Get-GdiagCliTree $Root);$expected=@{}
    foreach($entry in $Manifest.files.PSObject.Properties){$expected[$entry.Name.Replace('/','\')]=$entry.Value}
    $expected['payload-manifest.json']=$ManifestHash
    foreach($file in $tree){
        if($expected.ContainsKey($file.relative)){if($file.hash -ne $expected[$file.relative]){throw ('CLI payload hash mismatch: '+$file.relative)};$expected.Remove($file.relative)}
        elseif($Exact){throw 'Unlisted file in source CLI distribution; reconcile the selected package before copying.'}
    }
    if($expected.Count){throw ('CLI payload has missing files: '+$expected.Count)}
    $runtimePath=Assert-GdiagPlainPath (Join-Path $Root 'resources/data/main_agent/runtime_manifest.json')
    if((Get-Item -LiteralPath $runtimePath).Length -gt 1048576){throw 'CLI runtime manifest exceeds 1 MiB.'}
    $runtime=Get-Content -LiteralPath $runtimePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if($runtime.cad_backend -ne 'svg_headless' -or $runtime.product_capabilities.mcp_stdio_server -ne $true){throw 'CLI runtime manifest is not the headless/MCP product.'}
    foreach($relative in @('bin/gcad-cli.exe','resources/python/runtime/Python311/python311.dll')){if((Get-GdiagFileIdentity (Join-Path $Root $relative)).architecture -ne 'x64'){throw 'CLI executable/private Python architecture must match the reviewed x64 package.'}}
    return ,$tree
}
function New-GdiagCliPlan {
    param($Context,$Target,[string]$Operation,[hashtable]$Options)
    if($Operation -notin @('Setup','Repair','Update') -or $Options.recipe -ne 'cli-package' -or $Context.executorSid -ne $Context.affectedSid){throw 'Unsupported CLI operation or affected-user context.'}
    $destination=Get-GdiagCliRoot $Target;$source=Assert-GdiagPlainPath $Options.sourcePath
    foreach($other in @($source,[IO.Path]::GetFullPath($Context.casePath))){if($other -eq $destination -or $other.StartsWith($destination+'\',[StringComparison]::OrdinalIgnoreCase) -or $destination.StartsWith($other.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'CLI source, installation and case trees must be separate.'}}
    if($Context.profilePath -and $destination -eq [IO.Path]::GetFullPath($Context.profilePath).TrimEnd('\')){throw 'A user profile is not a dedicated installation.'}
    foreach($other in @($Context.targets)){if($other.id -eq $Target.id -or -not $other.path){continue};$otherPath=[IO.Path]::GetFullPath($other.path).TrimEnd('\');if($otherPath -eq $destination -or $otherPath.StartsWith($destination+'\',[StringComparison]::OrdinalIgnoreCase) -or $destination.StartsWith($otherPath+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Selected CLI tree overlaps another saved target.'}}
    $manifest=Get-GdiagCliManifest $source $Options.payloadManifestHash
    $sourceTree=Assert-GdiagCliPayload $source $manifest $Options.payloadManifestHash -Exact
    $before=@(Get-GdiagCliTree $destination);$previousManifest=$null;$previousHash=$null;$priorVersion=$null;$custom=@()
    if($Operation -eq 'Setup'){if(Test-Path -LiteralPath $destination){throw 'CLI Setup needs an absent dedicated destination.'}}
    else{
        $markerPath=Join-Path $destination '.gcaddiag-cli.json'
        if(Test-Path -LiteralPath $markerPath){$marker=Read-GdiagJson $markerPath;if($marker.owner -ne 'gcaddiag' -or $marker.recipe -ne 'cli-package'){throw 'CLI ownership record mismatch.'};$previousHash=$marker.payloadManifestHash}
        elseif($Options.installedManifestHash){$previousHash=$Options.installedManifestHash}
        else{throw 'Existing CLI needs its gcaddiag ownership record or an explicitly trusted installedManifestHash; do not infer ownership from the directory name.'}
        $previousManifest=Get-GdiagCliManifest $destination $previousHash;$priorVersion=$previousManifest.version
        if($previousManifest.target_year -ne $manifest.target_year){throw 'Cross-year CLI migration requires a separately planned destination; compatibility is unverified.'}
        $old=@{};foreach($entry in $previousManifest.files.PSObject.Properties){$old[$entry.Name.Replace('/','\')]=$entry.Value}
        $next=@{};foreach($entry in $manifest.files.PSObject.Properties){$next[$entry.Name.Replace('/','\')]=$entry.Value}
        foreach($file in $before){
            if($file.relative -in @('payload-manifest.json','.gcaddiag-cli.json')){continue}
            if($old.ContainsKey($file.relative)){
                if($file.hash -ne $old[$file.relative]){throw ('Installed package file is locally changed; preserve/reconcile before replacement: '+$file.relative)}
            }else{
                if($next.ContainsKey($file.relative)){throw ('New package collides with a custom file: '+$file.relative)}
                $custom+=$file
            }
        }
    }
    $candidateVersion=if($manifest.version){[string]$manifest.version}else{'undeclared'}
    $comparison='not_comparable';$oldVersion=$null;$newVersion=$null
    if($priorVersion -and [Version]::TryParse([string]$priorVersion,[ref]$oldVersion) -and [Version]::TryParse([string]$manifest.version,[ref]$newVersion)){
        $comparison=if($newVersion -gt $oldVersion){'newer'}elseif($newVersion -lt $oldVersion){'older'}else{'same_declared_version'}
        if($comparison -eq 'older' -and $Options.allowDowngrade -ne $true){throw 'Candidate is older; explicitly select allowDowngrade only for a requested downgrade.'}
    }
    $id=[guid]::NewGuid().ToString()
    [pscustomobject]@{schemaVersion=1;planId=$id;caseId=$Context.caseId;casePath=$Context.casePath;machine=$Context.machine;executorSid=$Context.executorSid;affectedSid=$Context.affectedSid;target=$Target;operation=$Operation;recipe='cli-package';status='planned';createdUtc=[datetime]::UtcNow.ToString('o');
      destination=$Target.path;installationRoot=$destination;source=$source;payloadManifestHash=$Options.payloadManifestHash;sourceTreeHash=(Get-GdiagTreeHash $sourceTree);beforeTreeHash=(Get-GdiagTreeHash $before);previousManifestHash=$previousHash;observed=@{customFiles=$custom};allowDowngrade=($Options.allowDowngrade -eq $true);
      stagePath=$destination+'.gcaddiag-stage-'+$id;previousPath=$destination+'.gcaddiag-previous-'+$id;retiredPath=$destination+'.gcaddiag-undone-'+$id;reversible=$true;privilege='affected-user';restartRequired=$false;processRequirement='Selected CLI and processes using its private runtime must be closed normally.';
      preview=@{installedVersion=$(if($priorVersion){$priorVersion}else{'unrecorded'});candidateVersion=$candidateVersion;comparison=$comparison;channel='not_declared_by_payload_manifest';configuration=$manifest.configuration;targetYear=$manifest.target_year;architecture='x64';available='explicit_selected_local_package';applicability='reviewed portable headless layout; licensed CAD and migration compatibility not inferred';customFileCount=$custom.Count};
      changes=@(@{path=$destination;action='replace-coherent-cli-tree';launcher=(Join-Path $destination 'bin/gcad-cli.exe');previousTree='retained whole beside destination';customFiles='copied unchanged into new tree after collision checks'});
      verification='Exact full payload plus preserved custom file hashes. Runtime startup, MCP and original symptom recovery are separate explicit probes.';
      limits=@('Manifest hash must come from the selected trusted release or reviewed offline export; checksum alone is not publisher authentication.','No model/runtime launch, PATH or MCP/provider edits, registry registration, global dependencies or user-state migration.','All prior files remain in the preserved tree; shipped files absent from the new manifest are not mixed into the new runtime.','Failure after staging/swap requires inspection; never replay or automatically undo a partial action.','Product version can remain undeclared; manifest configuration is not a release channel. External state/schema rollback is not established by restoring binaries.')}
}
function Invoke-GdiagCliPlan {
    param($Plan,[ValidateSet('Apply','Verify','Undo')][string]$Mode,[string]$PlanDirectory)
    $p=$Plan;$root=Get-GdiagCliRoot $p.target
    if($p.recipe -ne 'cli-package' -or $p.operation -notin @('Setup','Repair','Update') -or $p.installationRoot -ne $root -or $p.destination -ne $p.target.path){throw 'CLI typed target/operation mismatch.'}
    foreach($pair in @(@{field='stagePath';suffix='stage'},@{field='previousPath';suffix='previous'},@{field='retiredPath';suffix='undone'})){if($p.($pair.field) -ne $root+'.gcaddiag-'+$pair.suffix+'-'+$p.planId){throw 'Invalid CLI recovery path.'};Assert-GdiagPlainPath $p.($pair.field) | Out-Null}
    $statePath=Join-Path $PlanDirectory ($p.planId+'.state.json');$state=$null;if(Test-Path -LiteralPath $statePath){$state=Read-GdiagJson $statePath}
    $result=[ordered]@{planId=$p.planId;mode=$Mode;status='started';timeUtc=[datetime]::UtcNow.ToString('o');restartRequired=$false;hostVerification='pending';changes=@()}
    try{
        Assert-GdiagAutomationIdle $root @('gcad-cli','gcad-tui','gcad-batch','python','pythonw')
        if($Mode -eq 'Apply'){
            if($state){throw 'Prior CLI action exists; inspect actual state before recovery or replanning.'}
            if((Get-GdiagTreeHash @(Get-GdiagCliTree $root)) -ne $p.beforeTreeHash){throw 'Installed CLI changed since planning.'}
            # Rebuild all package/current-state decisions from verified inputs; do not trust mutable customFiles or preview.
            $fresh=New-GdiagCliPlan @{caseId=$p.caseId;casePath=$p.casePath;machine=$p.machine;executorSid=$p.executorSid;affectedSid=$p.affectedSid;targets=@((Read-GdiagJson (Join-Path $PlanDirectory 'case.json')).targets)} $p.target $p.operation @{recipe='cli-package';sourcePath=$p.source;payloadManifestHash=$p.payloadManifestHash;installedManifestHash=$p.previousManifestHash;allowDowngrade=$p.allowDowngrade}
            if($fresh.sourceTreeHash -ne $p.sourceTreeHash){throw 'Selected CLI package changed.'}
            foreach($path in @($p.stagePath,$p.previousPath,$p.retiredPath)){if(Test-Path -LiteralPath $path){throw 'CLI staging/recovery path already exists.'}}
            $manifest=Get-GdiagCliManifest $p.source $p.payloadManifestHash
            $state=[pscustomobject]@{planId=$p.planId;status='started';stagePath=$p.stagePath;previousPath=$p.previousPath;beforeTreeHash=$p.beforeTreeHash;afterTreeHash=$null;customFiles=$fresh.observed.customFiles;installedBefore=(Test-Path -LiteralPath $root)}
            Write-GdiagLifeJson $statePath $state
            New-Item -ItemType Directory -Path $p.stagePath | Out-Null
            foreach($entry in $manifest.files.PSObject.Properties){$to=Assert-GdiagPlainPath (Join-Path $p.stagePath $entry.Name);New-Item -ItemType Directory -Path (Split-Path -Parent $to) -Force|Out-Null;Copy-Item -LiteralPath (Assert-GdiagPlainPath (Join-Path $p.source $entry.Name)) -Destination $to -ErrorAction Stop}
            Copy-Item -LiteralPath (Join-Path $p.source 'payload-manifest.json') -Destination (Join-Path $p.stagePath 'payload-manifest.json') -ErrorAction Stop
            foreach($file in $fresh.observed.customFiles){$to=Assert-GdiagPlainPath (Join-Path $p.stagePath $file.relative);New-Item -ItemType Directory -Path (Split-Path -Parent $to) -Force|Out-Null;Copy-Item -LiteralPath (Assert-GdiagPlainPath (Join-Path $root $file.relative)) -Destination $to -ErrorAction Stop;if((Get-GdiagFileHash $to) -ne $file.hash){throw 'Custom file changed during staging.'}}
            Write-GdiagLifeJson (Join-Path $p.stagePath '.gcaddiag-cli.json') @{owner='gcaddiag';recipe='cli-package';payloadManifestHash=$p.payloadManifestHash;version=$manifest.version;targetYear=$manifest.target_year}
            Assert-GdiagCliPayload $p.stagePath $manifest $p.payloadManifestHash | Out-Null
            if((Get-GdiagTreeHash @(Get-GdiagCliTree $root)) -ne $p.beforeTreeHash){throw 'Installed CLI changed during staging; original remains in place.'}
            Assert-GdiagAutomationIdle $root @('gcad-cli','gcad-tui','gcad-batch','python','pythonw')
            if(Test-Path -LiteralPath $root){Move-Item -LiteralPath (Assert-GdiagPlainPath $root) -Destination $p.previousPath -ErrorAction Stop}
            Move-Item -LiteralPath (Assert-GdiagPlainPath $p.stagePath) -Destination $root -ErrorAction Stop
            $state.afterTreeHash=Get-GdiagTreeHash @(Get-GdiagCliTree $root);$state.status='applied';Write-GdiagLifeJson $statePath $state;$result.status='applied'
        }elseif($Mode -eq 'Verify'){
            if(-not $state -or $state.status -ne 'applied' -or $state.planId -ne $p.planId){throw 'CLI action is not completed.'}
            $manifest=Get-GdiagCliManifest $root $p.payloadManifestHash
            Assert-GdiagCliPayload $root $manifest $p.payloadManifestHash | Out-Null
            if((Get-GdiagTreeHash @(Get-GdiagCliTree $root)) -ne $state.afterTreeHash){throw 'Installed CLI or preserved custom files changed after Apply.'}
            $result.status='verified';$result.componentVerification='coherent-cli-payload-and-preserved-custom-files';$result.runtimeVerification='not_launched';$result.launcher=Join-Path $root 'bin/gcad-cli.exe'
        }else{
            if(-not $state -or $state.status -ne 'applied' -or $state.planId -ne $p.planId -or $state.previousPath -ne $p.previousPath -or $state.beforeTreeHash -ne $p.beforeTreeHash){throw 'CLI Undo requires a completed matching action.'}
            if((Get-GdiagTreeHash @(Get-GdiagCliTree $root)) -ne $state.afterTreeHash -or (Test-Path -LiteralPath $p.retiredPath)){throw 'CLI Undo preserves intervening changes.'}
            if($state.installedBefore){Assert-GdiagAutomationIdle $p.previousPath @('gcad-cli','gcad-tui','gcad-batch','python','pythonw');if(-not(Test-Path -LiteralPath $p.previousPath) -or (Get-GdiagTreeHash @(Get-GdiagCliTree $p.previousPath)) -ne $p.beforeTreeHash){throw 'Preserved previous CLI tree changed.'}}
            elseif($p.operation -ne 'Setup' -or (Test-Path -LiteralPath $p.previousPath)){throw 'CLI previous-tree absence mismatch.'}
            Move-Item -LiteralPath (Assert-GdiagPlainPath $root) -Destination $p.retiredPath -ErrorAction Stop
            if($state.installedBefore){Move-Item -LiteralPath (Assert-GdiagPlainPath $p.previousPath) -Destination $root -ErrorAction Stop}
            $state.status='undone';Write-GdiagLifeJson $statePath $state;$result.status='undone'
        }
    }catch{$result.status='failed';$result.error=$_.Exception.Message}
    [pscustomobject]$result
}
