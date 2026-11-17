# Typed repair for an existing Codex stdio MCP launch reference. Lifecycle.ps1
# supplies hashing, checked paths, JSON writes and the sole action journal.
function Invoke-GdiagCodexConfigRpc($Settings,[ValidateSet('Read','Write')][string]$Operation,$WriteParams=$null) {
    $process=New-Object Diagnostics.Process
    $process.StartInfo.FileName=$Settings.codexExecutable;$process.StartInfo.Arguments='app-server --stdio'
    $process.StartInfo.WorkingDirectory=$Settings.projectPath
    $process.StartInfo.EnvironmentVariables['CODEX_HOME']=$Settings.codexHome
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardInput=$true;$process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    $process.StartInfo.StandardOutputEncoding=New-Object Text.UTF8Encoding($false)
    $process.StartInfo.StandardErrorEncoding=New-Object Text.UTF8Encoding($false)
    $started=$false;$writer=$null;$pending='';$total=0;$reply=$null;$stage='initialize'
    try {
        $started=$process.Start();if(-not $started){throw 'Codex configuration host did not start.'}
        $writer=New-Object IO.StreamWriter($process.StandardInput.BaseStream,(New-Object Text.UTF8Encoding($false)))
        $outBuffer=New-Object char[] 2048;$errBuffer=New-Object char[] 2048
        $outTask=$process.StandardOutput.ReadAsync($outBuffer,0,2048);$errTask=$process.StandardError.ReadAsync($errBuffer,0,2048)
        $outEnded=$false;$errEnded=$false;$deadline=[datetime]::UtcNow.AddSeconds(25)
        $writer.WriteLine('{"id":1,"method":"initialize","params":{"clientInfo":{"name":"gcaddiag-mcp-repair","version":"0.1"}}}');$writer.Flush()
        while([datetime]::UtcNow -lt $deadline -and $null -eq $reply){
            if(-not $outEnded -and $outTask.IsCompleted){$n=$outTask.Result;$total+=$n;if(-not $n){$outEnded=$true}else{$pending+=(-join $outBuffer[0..($n-1)]);$outTask=$process.StandardOutput.ReadAsync($outBuffer,0,2048)}}
            if(-not $errEnded -and $errTask.IsCompleted){$n=$errTask.Result;$total+=$n;if(-not $n){$errEnded=$true}else{$errTask=$process.StandardError.ReadAsync($errBuffer,0,2048)}}
            if($total -gt 1048576){throw 'Codex configuration response exceeded 1 Mi characters; operation requires local inspection.'}
            while($pending.Contains("`n")){
                $index=$pending.IndexOf("`n");$line=$pending.Substring(0,$index);$pending=$pending.Substring($index+1)
                if(-not $line.Trim()){continue}
                try{$message=$line | ConvertFrom-Json -ErrorAction Stop}catch{throw 'Codex returned invalid protocol JSON; raw response withheld.'}
                if($message.id -eq 1 -and $stage -eq 'initialize'){
                    if($message.error -or $null -eq $message.result){throw 'Codex initialization rejected; native error text withheld.'}
                    $writer.WriteLine('{"method":"initialized"}')
                    if($Operation -eq 'Read'){$request=@{id=2;method='config/read';params=@{includeLayers=$true;cwd=$Settings.projectPath}}}
                    else{$request=@{id=2;method='config/batchWrite';params=$WriteParams}}
                    $writer.WriteLine(($request | ConvertTo-Json -Depth 40 -Compress));$writer.Flush();$stage='configuration'
                }elseif($message.id -eq 2 -and $stage -eq 'configuration'){
                    if($message.error -or $null -eq $message.result){
                        if($message.error.data.config_write_error_code -eq 'configLayerReadonly'){throw 'Native Codex API permits only user-config writes; selected layer is read-only for this API.'}
                        throw 'Codex configuration API rejected the request; no automatic retry. Inspect native configuration/version/policy locally.'
                    }
                    $reply=$message.result
                }
            }
            if($outEnded -and $null -eq $reply){throw 'Codex configuration host ended before returning a result.'}
            if($null -eq $reply){Start-Sleep -Milliseconds 20}
        }
        if($null -eq $reply){throw 'Codex configuration API timed out; inspect actual file state before retrying.'}
        $reply
    }finally{
        if($started){
            try{if($writer){$writer.Dispose()}else{$process.StandardInput.Close()}}finally{if(-not $process.WaitForExit(1000)){$process.Kill();if(-not $process.WaitForExit(1000)){throw 'Owned Codex configuration host termination unconfirmed.'}}}
        }
        $process.Dispose()
    }
}
function ConvertTo-GdiagMcpCanonical($Value) {
    if($null -eq $Value){return 'null'}
    if($Value -is [System.Collections.IDictionary]){$names=@($Value.Keys|Sort-Object);$pieces=@(foreach($key in $names){(ConvertTo-Json -InputObject ([string]$key) -Compress)+':'+(ConvertTo-GdiagMcpCanonical $Value[$key])});return '{'+($pieces -join ',')+'}'}
    if($Value -is [pscustomobject]){$pieces=@(foreach($property in $Value.PSObject.Properties|Sort-Object Name){(ConvertTo-Json -InputObject $property.Name -Compress)+':'+(ConvertTo-GdiagMcpCanonical $property.Value)});return '{'+($pieces -join ',')+'}'}
    if($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]){$pieces=@(foreach($item in $Value){ConvertTo-GdiagMcpCanonical $item});return '['+($pieces -join ',')+']'}
    ConvertTo-Json -InputObject $Value -Compress
}
function Get-GdiagMcpValueHash($Value) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try{([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((ConvertTo-GdiagMcpCanonical $Value))))).Replace('-','')}finally{$sha.Dispose()}
}
function Get-GdiagMcpUnchangedHash($Config,[string]$Name) {
    $copy=$Config|ConvertTo-Json -Depth 60|ConvertFrom-Json
    $entry=$copy.mcp_servers.PSObject.Properties[$Name].Value
    if(-not $entry){throw 'Selected MCP entry missing from native configuration.'}
    $entry.PSObject.Properties.Remove('command');$entry.PSObject.Properties.Remove('args')
    Get-GdiagMcpValueHash $copy
}
function Get-GdiagMcpLayerFile($Name) {
    if($Name.type -eq 'user' -and -not $Name.profile){return [IO.Path]::GetFullPath([string]$Name.file)}
    if($Name.type -eq 'project'){return [IO.Path]::GetFullPath((Join-Path $Name.dotCodexFolder 'config.toml'))}
    return $null
}
function Get-GdiagCodexMcpSelection($Settings) {
    $read=Invoke-GdiagCodexConfigRpc $Settings Read
    $layers=@($read.layers|Where-Object {(Get-GdiagMcpLayerFile $_.name) -eq $Settings.destination})
    if($layers.Count -ne 1 -or $layers[0].disabledReason -or -not $layers[0].version){throw 'Selected config is not a unique active writable user/project layer; resolve native trust/policy first.'}
    $layer=$layers[0];$name=$Settings.serverName
    $entryProperty=$layer.config.mcp_servers.PSObject.Properties[$name]
    $effectiveProperty=$read.config.mcp_servers.PSObject.Properties[$name]
    if(-not $entryProperty -or -not $effectiveProperty -or $entryProperty.Name -cne $name -or $effectiveProperty.Name -cne $name){throw 'Select the exact case-sensitive existing MCP server key; no differently cased table will be written.'}
    $entry=$entryProperty.Value
    $effective=$effectiveProperty.Value
    if(-not $entry -or -not $entry.command -or $entry.url -or -not $effective -or -not $effective.command -or $effective.url){throw 'Repair requires an existing native stdio MCP entry in the selected active layer.'}
    foreach($field in @('command','args')){
        $key='mcp_servers.'+$name+'.'+$field
        $origin=@($read.origins.PSObject.Properties|Where-Object {$key -ceq $_.Name -or $_.Name.StartsWith($key+'.',[StringComparison]::Ordinal)})
        if(-not $origin.Count){$origin=@($read.origins.PSObject.Properties|Where-Object {$key.StartsWith($_.Name+'.',[StringComparison]::Ordinal)}|Sort-Object @{Expression={$_.Name.Length};Descending=$true}|Select-Object -First 1)}
        # Empty/omitted arrays can have no leaf origins. Adding args is still
        # scoped when no other active layer supplies that field for this server.
        $otherArgs=@()
        if($field -eq 'args' -and -not $origin.Count){$otherArgs=@($read.layers|Where-Object {-not $_.disabledReason -and (Get-GdiagMcpLayerFile $_.name) -ne $Settings.destination -and $_.config.mcp_servers.PSObject.Properties[$name].Name -ceq $name -and $_.config.mcp_servers.PSObject.Properties[$name].Value.PSObject.Properties['args']})}
        if(((-not $origin.Count) -and ($field -ne 'args' -or $otherArgs.Count)) -or @($origin|Where-Object {(Get-GdiagMcpLayerFile $_.Value.name) -ne $Settings.destination}).Count){throw 'Selected launch field is controlled by another configuration layer or has no native origin; no shadowed repair is applied.'}
        if((Get-GdiagMcpValueHash $entry.PSObject.Properties[$field].Value) -ne (Get-GdiagMcpValueHash $effective.PSObject.Properties[$field].Value)){throw 'Selected layer launch values differ from effective host values.'}
    }
    [pscustomobject]@{layer=$layer;entry=$entry;effective=$effective;config=$read.config}
}
function Assert-GdiagMcpSettings($Settings) {
    if($Settings.serverName -notmatch '^[A-Za-z0-9_-]{1,64}$'){throw 'Select one simple existing MCP server key (letters, digits, underscore, hyphen).'}
    foreach($field in @('destination','codexExecutable','codexHome','projectPath','commandPath')){
        $path=Assert-GdiagPlainPath $Settings.$field
        if($path -ne $Settings.$field){throw 'MCP paths must be absolute canonical local selections.'}
    }
    if((Split-Path -Leaf $Settings.destination) -ne 'config.toml' -or (Get-Item -LiteralPath $Settings.destination).Length -gt 1048576){throw 'Select an existing config.toml no larger than 1 MiB.'}
    if([IO.Path]::GetExtension($Settings.codexExecutable) -ne '.exe' -or (Get-GdiagFileHash $Settings.codexExecutable) -ne $Settings.codexHash){throw 'Selected native Codex executable/hash changed.'}
    if([IO.Path]::GetExtension($Settings.commandPath) -ne '.exe' -or (Get-GdiagFileHash $Settings.commandPath) -ne $Settings.commandHash){throw 'Selected native MCP launcher executable/hash changed.'}
    foreach($directory in @($Settings.codexHome,$Settings.projectPath)){if(-not(Test-Path -LiteralPath $directory -PathType Container)){throw 'Selected Codex home/project directory is missing.'}}
    if($Settings.destination -ne [IO.Path]::GetFullPath((Join-Path $Settings.codexHome 'config.toml'))){throw 'Native Codex API currently supports only the selected Codex home user config.toml; project-layer repair remains unavailable.'}
}
function New-GdiagCodexMcpPlan($Context,$Target,[hashtable]$Options) {
    if($Target.family -ne 'AgentConfig' -or $Options.recipe -ne 'codex-mcp-stdio'){throw 'Select an AgentConfig target and codex-mcp-stdio repair.'}
    if($Context.executorSid -ne $Context.affectedSid){throw 'Codex MCP repair requires the affected user context.'}
    $settings=[ordered]@{destination=(Assert-GdiagPlainPath $Target.path);serverName=[string]$Options.serverName;codexExecutable=(Assert-GdiagPlainPath $Options.codexExecutable);codexHash=[string]$Options.expectedCodexHash;codexHome=(Assert-GdiagPlainPath $Options.codexHome);projectPath=(Assert-GdiagPlainPath $Options.projectPath);commandPath=(Assert-GdiagPlainPath $Options.commandPath);commandHash=[string]$Options.expectedCommandHash}
    Assert-GdiagMcpSettings ([pscustomobject]$settings)
    $beforeHash=Get-GdiagFileHash $settings.destination
    if(-not $Options.expectedConfigHash -or $beforeHash -ne $Options.expectedConfigHash){throw 'Selected config checksum does not match reviewed input.'}
    $arguments=@($Options.arguments)
    if($arguments.Count -gt 64 -or @($arguments|Where-Object {$_ -isnot [string] -or $_.Length -gt 8192 -or $_.Contains([char]0)}).Count){throw 'MCP arguments must be at most 64 explicit strings of at most 8192 characters.'}
    $selection=Get-GdiagCodexMcpSelection ([pscustomobject]$settings)
    if((Get-GdiagFileHash $settings.destination) -ne $beforeHash){throw 'Selected config changed during planning.'}
    $id=[guid]::NewGuid().ToString();$directory=Assert-GdiagPlainPath $Context.casePath
    $specPath=Assert-GdiagPlainPath (Join-Path $directory ($id+'.mcp-launcher.json'))
    Write-GdiagLifeJson $specPath @{command=$settings.commandPath;args=$arguments}
    $plan=[ordered]@{schemaVersion=1;planId=$id;caseId=$Context.caseId;casePath=$directory;machine=$Context.machine;executorSid=$Context.executorSid;affectedSid=$Context.affectedSid;target=$Target;operation='Repair';recipe='codex-mcp-stdio';status='planned';createdUtc=[datetime]::UtcNow.ToString('o');privilege='affected-user';processRequirement='Coordinate with affected Codex sessions; no session is closed or hot-reloaded.';reversible=$true;restartRequired=$false;beforeHash=$beforeHash;beforeVersion=$selection.layer.version;specHash=(Get-GdiagFileHash $specPath);layerRemainderHash=(Get-GdiagMcpUnchangedHash $selection.layer.config $settings.serverName);effectiveRemainderHash=(Get-GdiagMcpUnchangedHash $selection.config $settings.serverName);verification='Native parsed launch fields and unchanged unrelated settings; MCP handshake/invocation pending.';changes=@(@{path=$settings.destination;action='native-config-batchWrite';keys=@(('mcp_servers.'+$settings.serverName+'.command'),('mcp_servers.'+$settings.serverName+'.args'));command=$settings.commandPath;argumentCount=$arguments.Count;arguments='Private case-local launcher spec; inspect selected input before Apply.'});limits=@('Only an existing stdio entry command/args are replaced; env, cwd, enabled, credentials and policy are retained.','No server launch, model request or loaded-thread hot reload; existing sessions may need normal reconnect/restart.','On failed/partial write inspect actual config before recovery; Undo restores exact bytes only when the written config remains unchanged.')}
    foreach($key in $settings.Keys){$plan[$key]=$settings[$key]}
    [pscustomobject]$plan
}
function Invoke-GdiagCodexMcpPlan($Plan,[ValidateSet('Apply','Verify','Undo')][string]$Mode,[string]$PlanDirectory) {
    $p=$Plan;$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if($p.recipe -ne 'codex-mcp-stdio' -or $p.operation -ne 'Repair' -or $p.schemaVersion -ne 1 -or $p.status -ne 'planned' -or $p.target.family -ne 'AgentConfig'){throw 'Invalid typed Codex MCP repair plan.'}
    $id=[guid]::Empty;if(-not[guid]::TryParse([string]$p.planId,[ref]$id) -or $p.planId -notmatch '^[a-fA-F0-9-]{36}$'){throw 'Invalid plan ID.'}
    $directory=Assert-GdiagPlainPath $PlanDirectory
    $case=Get-Content -LiteralPath (Assert-GdiagPlainPath (Join-Path $directory 'case.json')) -Raw -Encoding UTF8|ConvertFrom-Json
    $target=@($case.targets|Where-Object id -eq $p.target.id)
    if($directory -ne $p.casePath -or $case.kind -ne 'local' -or $case.formatVersion -ne 1 -or $case.caseId -ne $p.caseId -or $p.machine -ne [Environment]::MachineName -or $p.executorSid -ne $sid -or $p.affectedSid -ne $sid -or $case.context.machine -ne $p.machine -or $case.context.executorSid -ne $sid -or $case.context.affectedSid -ne $sid){throw 'MCP repair requires the same canonical local case and affected user.'}
    if($target.Count -ne 1 -or $target[0].family -ne 'AgentConfig' -or $target[0].path -ne $p.destination -or $p.target.path -ne $p.destination){throw 'MCP config target differs from saved case selection.'}
    Assert-GdiagMcpSettings $p
    $statePath=Assert-GdiagPlainPath (Join-Path $directory ($p.planId+'.state.json'))
    $specPath=Assert-GdiagPlainPath (Join-Path $directory ($p.planId+'.mcp-launcher.json'))
    $backup=Assert-GdiagPlainPath (Join-Path $directory ($p.planId+'.mcp-original.bin'))
    if((Get-GdiagFileHash $specPath) -ne $p.specHash){throw 'Private launcher specification changed.'}
    $spec=Get-Content -LiteralPath $specPath -Raw -Encoding UTF8|ConvertFrom-Json
    if($spec.command -ne $p.commandPath -or @($spec.args).Count -gt 64 -or @($spec.args|Where-Object {$_ -isnot [string] -or $_.Length -gt 8192 -or $_.Contains([char]0)}).Count){throw 'Invalid private launcher specification.'}
    $state=$null;if(Test-Path -LiteralPath $statePath){$state=Get-Content -LiteralPath $statePath -Raw -Encoding UTF8|ConvertFrom-Json}
    $result=[ordered]@{planId=$p.planId;mode=$Mode;status='started';timeUtc=[datetime]::UtcNow.ToString('o');restartRequired=$false;hostVerification='pending';changes=@()}
    try{
        if($Mode -eq 'Undo'){
            if(-not $state -or $state.planId -ne $p.planId -or $state.status -ne 'applied' -or (Get-GdiagFileHash $p.destination) -ne $state.afterHash -or (Get-GdiagFileHash $backup) -ne $p.beforeHash){throw 'Undo requires unchanged written config and exact preserved original.'}
            $original=[IO.File]::ReadAllBytes($backup)
            $locked=[IO.File]::Open($p.destination,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
            try{
                $sha=[Security.Cryptography.SHA256]::Create()
                try{$lockedHash=([BitConverter]::ToString($sha.ComputeHash($locked))).Replace('-','')}finally{$sha.Dispose()}
                if($lockedHash -ne $state.afterHash){throw 'Undo preserves a config edit observed while acquiring its write lock.'}
                $locked.Position=0;$locked.Write($original,0,$original.Length);$locked.SetLength($original.Length);$locked.Flush()
            }finally{$locked.Dispose()}
            if((Get-GdiagFileHash $p.destination) -ne $p.beforeHash){throw 'Original config restoration could not be verified.'}
            $state.status='undone';Write-GdiagLifeJson $statePath $state;$result.status='undone'
        }else{
            if($Mode -eq 'Apply'){
                if($state){throw 'Prior MCP repair action exists; inspect state before replanning.'}
                if((Get-GdiagFileHash $p.destination) -ne $p.beforeHash){throw 'Selected config changed since planning.'}
            }elseif(-not $state -or $state.planId -ne $p.planId -or $state.status -ne 'applied' -or (Get-GdiagFileHash $p.destination) -ne $state.afterHash){throw 'Written config changed or prior action is not complete.'}
            $selected=Get-GdiagCodexMcpSelection $p
            if((Get-GdiagMcpUnchangedHash $selected.layer.config $p.serverName) -ne $p.layerRemainderHash -or (Get-GdiagMcpUnchangedHash $selected.config $p.serverName) -ne $p.effectiveRemainderHash){throw 'Unrelated layer/effective settings changed; review before continuing.'}
            if($Mode -eq 'Apply'){
                if($selected.layer.version -ne $p.beforeVersion -or (Get-GdiagFileHash $p.destination) -ne $p.beforeHash){throw 'Native selected configuration version changed.'}
                [IO.File]::WriteAllBytes($backup,[IO.File]::ReadAllBytes($p.destination))
                if((Get-GdiagFileHash $backup) -ne $p.beforeHash){throw 'Original config changed during capture.'}
                $state=[pscustomobject]@{planId=$p.planId;status='started';afterHash=$null};Write-GdiagLifeJson $statePath $state
                $edits=@(@{keyPath=('mcp_servers.'+$p.serverName+'.command');mergeStrategy='replace';value=$spec.command},@{keyPath=('mcp_servers.'+$p.serverName+'.args');mergeStrategy='replace';value=@($spec.args)})
                $written=Invoke-GdiagCodexConfigRpc $p Write @{edits=$edits;filePath=$p.destination;expectedVersion=$p.beforeVersion;reloadUserConfig=$false}
                $state.afterHash=Get-GdiagFileHash $p.destination;Write-GdiagLifeJson $statePath $state
                if($written.status -ne 'ok' -or [IO.Path]::GetFullPath([string]$written.filePath) -ne $p.destination){throw 'Native write was overridden or targeted a different file; inspect actual config before recovery.'}
                $selected=Get-GdiagCodexMcpSelection $p
            }
            if($selected.entry.command -ne $spec.command -or (Get-GdiagMcpValueHash @($selected.entry.args)) -ne (Get-GdiagMcpValueHash @($spec.args)) -or (Get-GdiagMcpUnchangedHash $selected.layer.config $p.serverName) -ne $p.layerRemainderHash -or (Get-GdiagMcpUnchangedHash $selected.config $p.serverName) -ne $p.effectiveRemainderHash){throw 'Native launch/effective configuration verification failed; inspect originals and current state.'}
            if($Mode -eq 'Apply'){$state.status='applied';Write-GdiagLifeJson $statePath $state;$result.status='applied'}else{$result.status='verified'}
            $result.componentVerification='native-launch-fields-and-unrelated-settings-verified';$result.nextAction='Reconnect or restart the selected Codex session normally, then explicitly verify MCP initialization/discovery. Server has not been launched by this repair.'
        }
    }catch{$result.status='failed';$result.error=$_.Exception.Message}
    [pscustomobject]$result
}
