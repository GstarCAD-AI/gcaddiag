# Windows PowerShell 5.1; no target runtime is loaded by these collectors.
function New-GdiagIntegrationEvidence {
    param($Source,$Status,$Observed,$ErrorDetail=$null)
    $summary="$Source : $Status"
    if ($Observed -is [string]) { $summary=$Observed }
    if ($Observed -is [System.Collections.IDictionary]) {
        foreach ($field in @('httpStatus','stage','reason','initialize','discovery','toolCount','serverCount','transport','enabled','authStatus','launcher','next','effective','route','addressCount','tlsProtocol','utc','proxyType','skillCount','enabledCount','disabledCount','loadErrorCount','scope','exitCode')) {
            if ($Observed.Contains($field)) {
                if ($field -eq 'route' -and $Observed[$field] -is [System.Collections.IDictionary]) {$summary += '; route=effective .NET HTTP proxy policy; agent/GCAD routes unverified'}
                else {$summary += "; $field=$($Observed[$field])"}
            }
        }
        if ($Observed.Contains('missingResources')) {$summary += "; missing resource count=$(@($Observed.missingResources).Count)"}
    }
    if ($ErrorDetail -is [System.Collections.IDictionary]) {
        foreach ($field in @('domain','code','hresult')) {if ($ErrorDetail.Contains($field)) {$summary += "; $field=$($ErrorDetail[$field])"}}
    }
    [pscustomobject]@{source=$Source; status=$Status; publicSummary=$summary; observed=$Observed; error=$ErrorDetail; timeUtc=[DateTime]::UtcNow.ToString('o')}
}

function Get-GdiagAgentEvidence {
    param([hashtable]$Context,[hashtable]$Options=@{})
    $profile = $Context.profilePath
    if ($Context.executorSid -ne $Context.affectedSid) {
        New-GdiagIntegrationEvidence 'agent.launch-context' 'unavailable' 'Affected-user launch environment cannot be inferred from the executor. Supply permitted explicit configuration/skill paths.'
        return
    }
    $project = $Options.projectPath
    $workBuddyProject=($Options.host -eq 'WorkBuddyProject')
    if ($workBuddyProject -and -not $project) {throw 'WorkBuddyProject inspection requires the selected projectPath.'}
    $roots = @()
    if ($profile) { $roots += Join-Path $profile '.agents\skills' }
    if ($project) {
        $roots += Join-Path $project '.agents\skills'
        $roots += Join-Path $project '.codebuddy\skills'
    }
    if ($workBuddyProject -and $profile) {$roots+=Join-Path $profile '.codebuddy\skills'}
    if ($Options.skillRoots) { $roots += @($Options.skillRoots) }
    $names = @{}
    foreach ($root in ($roots | Select-Object -Unique)) {
        try {
            if (-not (Test-Path -LiteralPath $root)) { New-GdiagIntegrationEvidence 'agent.skills' 'absent' @{path=$root}; continue }
            foreach ($dir in Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop) {
                $entry=Join-Path $dir.FullName 'SKILL.md'
                if (-not (Test-Path -LiteralPath $entry)) { New-GdiagIntegrationEvidence 'agent.skills' 'incomplete' @{path=$dir.FullName;missing='SKILL.md'}; continue }
                $skillStream=$null;$skillReader=$null
                try {
                    $skillStream=[IO.File]::Open($entry,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                    if($skillStream.Length -gt 1048576){New-GdiagIntegrationEvidence 'agent.skills' 'truncated' @{path=$entry};continue}
                    # Bound decoded content as well: another process can grow a shared file after the length check.
                    $skillReader=New-Object IO.StreamReader($skillStream)
                    $skillBuffer=New-Object char[] 262145
                    $skillLength=$skillReader.ReadBlock($skillBuffer,0,$skillBuffer.Length)
                    if($skillLength -gt 262144){New-GdiagIntegrationEvidence 'agent.skills' 'truncated' @{path=$entry};continue}
                    $body=New-Object string($skillBuffer,0,$skillLength)
                }finally{if($skillReader){$skillReader.Dispose()}elseif($skillStream){$skillStream.Dispose()}}
                $match=[regex]::Match($body,'(?m)^name:\s*["'']?([a-z0-9-]+)["'']?\s*$')
                $name=$match.Groups[1].Value
                $missing=@()
                foreach ($link in [regex]::Matches($body,'\]\(([^)#]+)(?:#[^)]*)?\)')) {
                    $relative=$link.Groups[1].Value
                    if ($relative -match '^(https?:|mailto:|/|#)') { continue }
                    if (-not (Test-Path -LiteralPath (Join-Path $dir.FullName $relative))) { $missing += $relative }
                }
                $state='observed'; if (-not $match.Success -or $missing.Count) { $state='incomplete' }
                New-GdiagIntegrationEvidence 'agent.skills' $state @{path=$entry;name=$name;missingResources=$missing;discovery='candidate; actual host discovery pending'}
                if ($name) { if (-not $names.ContainsKey($name)) {$names[$name]=@()}; $names[$name]+=$entry }
            }
        } catch { New-GdiagIntegrationEvidence 'agent.skills' 'collection_error' @{path=$root} @{type=$_.Exception.GetType().FullName;hresult=$_.Exception.HResult} }
    }
    foreach ($name in $names.Keys) {
        if ($names[$name].Count -gt 1) { New-GdiagIntegrationEvidence 'agent.skills.duplicate' 'unknown' @{name=$name;paths=$names[$name];effective='host discovery must resolve; no copy selected for cleanup'} }
        if ($workBuddyProject) {
            $projectRoot=[IO.Path]::GetFullPath((Join-Path $project '.codebuddy\skills')).TrimEnd('\')+'\'
            $userRoot=if($profile){[IO.Path]::GetFullPath((Join-Path $profile '.codebuddy\skills')).TrimEnd('\')+'\'}else{$null}
            $projectCopies=@($names[$name] | Where-Object {$_.StartsWith($projectRoot,[StringComparison]::OrdinalIgnoreCase)})
            $userCopies=@($names[$name] | Where-Object {$userRoot -and $_.StartsWith($userRoot,[StringComparison]::OrdinalIgnoreCase)})
            if ($projectCopies.Count -eq 1) {
                New-GdiagIntegrationEvidence 'agent.workbuddy.project-precedence' 'observed' @{name=$name;expectedEffectivePath=$projectCopies[0];shadowed=$userCopies;effective='Selected WorkBuddy code-project scope: documented project skill takes precedence over same-name user skill. Actual host discovery/policy remains pending.'}
            } elseif ($projectCopies.Count -gt 1) {
                New-GdiagIntegrationEvidence 'agent.workbuddy.project-precedence' 'unknown' @{name=$name;reason='Duplicate names within selected project scope; no active copy inferred.'}
            }
        }
    }
    $configs=@()
    if ($profile) { $configs+=Join-Path $profile '.codex\config.toml' }
    if ($env:CODEX_HOME) {$configs+=Join-Path $env:CODEX_HOME 'config.toml'}
    if ($project) {$configs+=Join-Path $project '.codex\config.toml'}
    if ($workBuddyProject) {
        if($profile){$configs+=Join-Path $profile '.codebuddy\settings.json'}
        $configs+=Join-Path $project '.codebuddy\settings.json'
        $configs+=Join-Path $project '.codebuddy\settings.local.json'
        New-GdiagIntegrationEvidence 'agent.workbuddy.configuration-precedence' 'observed' @{effective='WorkBuddy code-project linked configuration: command-line overrides > project settings.local.json > project settings.json > user settings.json. CLI flags, organization policy and live host state not captured; no universal effective settings merge claimed.'}
    }
    if ($Options.configPaths) {$configs+=@($Options.configPaths)}
    foreach ($path in ($configs | Select-Object -Unique)) {
        try {
            if (-not (Test-Path -LiteralPath $path)) {New-GdiagIntegrationEvidence 'agent.configuration' 'absent' @{path=$path};continue}
            $file=Get-Item -LiteralPath $path
            if ($file.Length -gt 1048576) {New-GdiagIntegrationEvidence 'agent.configuration' 'truncated' @{path=$path};continue}
            $body=[IO.File]::ReadAllText($path)
            if ($file.Extension -eq '.json') {
                $config=ConvertFrom-Json -InputObject $body -ErrorAction Stop
                New-GdiagIntegrationEvidence 'agent.configuration' 'observed' @{path=$path;topLevelKeys=@($config.PSObject.Properties.Name);effective='candidate only; host precedence/policy not resolved'}
            } else {
                # PowerShell has no TOML parser. Do not misrepresent regex extraction as validation.
                $sections=@([regex]::Matches($body,'(?m)^\s*\[([^\]\r\n]+)\]') | ForEach-Object {$_.Groups[1].Value})
                New-GdiagIntegrationEvidence 'agent.configuration' 'unknown' @{path=$path;sections=$sections;next='Use installed Codex mcp list --json and host configuration diagnostics; full TOML/organization/trust precedence validation unavailable in script.'}
            }
        } catch {New-GdiagIntegrationEvidence 'agent.configuration' 'collection_error' @{path=$path} @{type=$_.Exception.GetType().FullName;hresult=$_.Exception.HResult}}
    }
    if ($Options.codexExecutable) { Get-GdiagCodexEffective -Context $Context -Options $Options }
    if ($Options.codexSkillDiscovery) { Get-GdiagCodexSkills -Context $Context -Options $Options }
    New-GdiagIntegrationEvidence 'agent.host-acceptance' 'host_verification_pending' 'File inventory and any native discovery results do not establish actual skill invocation, command permissions or MCP readiness.'
}

function Get-GdiagCodexSkills {
    param([hashtable]$Context,[hashtable]$Options)
    # The installed host supplies discovery, enabled state and scope. No model turn,
    # configuration write or discovered skill command is sent to the app-server.
    if ($Context.executorSid -ne $Context.affectedSid) {
        New-GdiagIntegrationEvidence 'agent.codex.skills' 'unavailable' @{reason='Selected affected user differs from native host executor.'};return
    }
    $exe=[string]$Options.codexExecutable
    if (-not [IO.Path]::IsPathRooted($exe) -or [IO.Path]::GetExtension($exe) -ne '.exe' -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        New-GdiagIntegrationEvidence 'agent.codex.skills' 'absent' @{next='Select the installed native Codex executable for host discovery.'};return
    }
    if (-not $Options.projectPath -or -not (Test-Path -LiteralPath $Options.projectPath -PathType Container)) {throw 'Native skill discovery requires an existing explicit projectPath.'}
    $project=[IO.Path]::GetFullPath([string]$Options.projectPath)
    $selected=$null
    if ($Options.codexSkillPath) {
        if (-not [IO.Path]::IsPathRooted([string]$Options.codexSkillPath)) {throw 'codexSkillPath must be an absolute selected SKILL.md path.'}
        $selected=[IO.Path]::GetFullPath([string]$Options.codexSkillPath)
    }
    $process=New-Object Diagnostics.Process
    $process.StartInfo.FileName=$exe;$process.StartInfo.Arguments='app-server --stdio'
    $process.StartInfo.WorkingDirectory=$project
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardInput=$true;$process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    $process.StartInfo.StandardOutputEncoding=New-Object Text.UTF8Encoding($false)
    $process.StartInfo.StandardErrorEncoding=New-Object Text.UTF8Encoding($false)
    if ($Options.codexHome) {
        $selectedHome=[IO.Path]::GetFullPath([string]$Options.codexHome)
        if (-not (Test-Path -LiteralPath $selectedHome -PathType Container)) {throw 'Explicit Codex home must already exist.'}
        $process.StartInfo.EnvironmentVariables['CODEX_HOME']=$selectedHome
    }
    $started=$false;$stage='launch';$reply=$null;$pending='';$total=0;$writer=$null
    $deadline=[DateTime]::UtcNow.AddSeconds(25)
    try {
        $started=$process.Start()
        if (-not $started) {throw 'Native host did not start.'}
        # Windows PowerShell's redirected stdin defaults to the system code page.
        # Codex JSON-RPC expects UTF-8, including the selected Unicode project path.
        $writer=New-Object IO.StreamWriter($process.StandardInput.BaseStream,(New-Object Text.UTF8Encoding($false)))
        $outBuffer=New-Object char[] 2048;$errBuffer=New-Object char[] 2048
        $outTask=$process.StandardOutput.ReadAsync($outBuffer,0,2048);$errTask=$process.StandardError.ReadAsync($errBuffer,0,2048)
        $outEnded=$false;$errEnded=$false
        $writer.WriteLine('{"id":1,"method":"initialize","params":{"clientInfo":{"name":"gcaddiag-diagnostics","version":"0.1"}}}')
        $writer.Flush();$stage='initialize'
        while ([DateTime]::UtcNow -lt $deadline -and $null -eq $reply) {
            if (-not $outEnded -and $outTask.IsCompleted) {
                $n=$outTask.Result;$total+=$n
                if (-not $n) {$outEnded=$true} else {$pending+=(-join $outBuffer[0..($n-1)]);$outTask=$process.StandardOutput.ReadAsync($outBuffer,0,2048)}
            }
            if (-not $errEnded -and $errTask.IsCompleted) {
                $n=$errTask.Result;$total+=$n
                if (-not $n) {$errEnded=$true} else {$errTask=$process.StandardError.ReadAsync($errBuffer,0,2048)}
            }
            if ($total -gt 262144) {New-GdiagIntegrationEvidence 'agent.codex.skills' 'truncated' @{stage=$stage;reason='Native host output exceeded 256 Ki characters; no complete discovery claim.'};return}
            while ($pending.Contains("`n")) {
                $index=$pending.IndexOf("`n");$line=$pending.Substring(0,$index);$pending=$pending.Substring($index+1)
                if (-not $line.Trim()) {continue}
                $message=ConvertFrom-Json -InputObject $line -ErrorAction Stop
                if ($message.id -eq 1 -and $stage -eq 'initialize') {
                    if ($message.error -or $null -eq $message.result) {New-GdiagIntegrationEvidence 'agent.codex.skills' 'collection_error' @{stage=$stage;reason='Native host rejected initialization; error text withheld.'};return}
                    $writer.WriteLine('{"method":"initialized"}')
                    $request=@{id=2;method='skills/list';params=@{cwds=@($project);forceReload=$true}} | ConvertTo-Json -Depth 5 -Compress
                    $writer.WriteLine($request);$writer.Flush();$stage='skills/list'
                } elseif ($message.id -eq 2 -and $stage -eq 'skills/list') {
                    if ($message.error -or $null -eq $message.result -or -not $message.result.PSObject.Properties['data']) {New-GdiagIntegrationEvidence 'agent.codex.skills' 'collection_error' @{stage=$stage;reason='Native host lacks supported skills/list or rejected discovery; error text withheld.'};return}
                    $reply=$message.result
                }
            }
            if ($outEnded -and $null -eq $reply) {New-GdiagIntegrationEvidence 'agent.codex.skills' 'collection_error' @{stage=$stage;reason='Native stdout closed before discovery completed.'};return}
            if ($null -eq $reply) {Start-Sleep -Milliseconds 20}
        }
        if ($null -eq $reply) {New-GdiagIntegrationEvidence 'agent.codex.skills' 'timeout' @{stage=$stage;reason='Native discovery exceeded 25 seconds.'};return}
        $entries=@($reply.data | Where-Object {$_.cwd -and [IO.Path]::GetFullPath([string]$_.cwd) -eq $project})
        if ($entries.Count -ne 1 -or -not $entries[0].PSObject.Properties['skills'] -or -not $entries[0].PSObject.Properties['errors']) {throw 'Native discovery did not return the selected project.'}
        $skills=@($entries[0].skills);$errors=@($entries[0].errors)
        foreach ($skill in $skills) {
            if (-not $skill.path -or -not [IO.Path]::IsPathRooted([string]$skill.path) -or $skill.enabled -isnot [bool] -or $skill.scope -notin @('user','repo','system','admin')) {throw 'Native skill metadata shape is unsupported.'}
        }
        New-GdiagIntegrationEvidence 'agent.codex.skills' 'observed' @{skillCount=$skills.Count;enabledCount=@($skills | Where-Object enabled).Count;disabledCount=@($skills | Where-Object {-not $_.enabled}).Count;loadErrorCount=$errors.Count;discovery='native skills/list for selected project';next='Discovery is separate from invocation, permissions and MCP readiness; duplicate names are not a cleanup decision.'}
        if ($selected) {
            $matches=@($skills | Where-Object {[IO.Path]::GetFullPath([string]$_.path) -eq $selected})
            $failed=@($errors | Where-Object {$_.path -and [IO.Path]::IsPathRooted([string]$_.path) -and [IO.Path]::GetFullPath([string]$_.path) -eq $selected})
            if ($matches.Count -eq 1 -and -not $failed.Count) {
                $state=if($matches[0].enabled){'observed'}else{'disabled'}
                New-GdiagIntegrationEvidence 'agent.codex.selected-skill' $state @{path=$selected;enabled=$matches[0].enabled;scope=$matches[0].scope;discovery='exact selected path returned by native host';next='Retain local edits; invocation and original symptom recovery remain separate.'}
            } elseif ($failed.Count) {
                New-GdiagIntegrationEvidence 'agent.codex.selected-skill' 'collection_error' @{path=$selected;reason='Selected skill has a native load error; raw host error/skill contents withheld.';next='Inspect the selected skill frontmatter locally and recheck native discovery after correction.'}
            } elseif ($matches.Count -gt 1) {
                New-GdiagIntegrationEvidence 'agent.codex.selected-skill' 'unknown' @{path=$selected;reason='Native host returned multiple records for selected path; no effective copy inferred.'}
            } else {
                New-GdiagIntegrationEvidence 'agent.codex.selected-skill' 'absent' @{path=$selected;reason='Selected path was not returned by native discovery for this project.';next='Check host discovery location, project trust and policy in this context; absence does not prove the file is missing.'}
            }
        }
    } catch {New-GdiagIntegrationEvidence 'agent.codex.skills' 'collection_error' @{stage=$stage;reason='Native discovery failed or returned an unsupported response; raw descriptions/errors withheld.'} @{type=$_.Exception.GetType().FullName;hresult=$_.Exception.HResult}} finally {
        if ($started) {
            try {if($writer){$writer.Dispose()}else{$process.StandardInput.Close()}}
            catch {New-GdiagIntegrationEvidence 'agent.codex.skills.cleanup' 'unknown' @{reason='Owned host input closure failed; process shutdown will still be attempted.'}}
            try {if (-not $process.WaitForExit(1000)) {$process.Kill();if(-not $process.WaitForExit(1000)){throw 'Owned process still running'}}}
            catch {New-GdiagIntegrationEvidence 'agent.codex.skills.cleanup' 'unknown' @{reason='Owned host shutdown could not be confirmed; inspect its process before retrying.'}}
        }
        $process.Dispose()
    }
}

function Get-GdiagCodexEffective {
    param([hashtable]$Context,[hashtable]$Options)
    # Explicit host inspection, never a launcher discovered in untrusted configuration.
    $exe=[string]$Options.codexExecutable
    if (-not [IO.Path]::IsPathRooted($exe) -or [IO.Path]::GetExtension($exe) -ne '.exe' -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        New-GdiagIntegrationEvidence 'agent.codex.effective' 'absent' @{next='Provide the installed native Codex .exe path; shell shims are not executed.'};return
    }
    $process=New-Object Diagnostics.Process
    $process.StartInfo.FileName=$exe;$process.StartInfo.Arguments='mcp list --json'
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    if ($Options.projectPath) {$process.StartInfo.WorkingDirectory=[string]$Options.projectPath}
    if ($Options.codexHome) {
        $selectedHome=[IO.Path]::GetFullPath([string]$Options.codexHome)
        if (-not (Test-Path -LiteralPath $selectedHome -PathType Container)) {throw 'Explicit Codex home must already exist.'}
        $process.StartInfo.EnvironmentVariables['CODEX_HOME']=$selectedHome
    }
    $started=$false
    try {
        $started=$process.Start()
        $outBuffer=New-Object char[] 2048;$errBuffer=New-Object char[] 2048
        $output=New-Object Text.StringBuilder
        $outTask=$process.StandardOutput.ReadAsync($outBuffer,0,2048);$errTask=$process.StandardError.ReadAsync($errBuffer,0,2048)
        $outEnded=$false;$errEnded=$false;$total=0;$deadline=[DateTime]::UtcNow.AddSeconds(10)
        while ([DateTime]::UtcNow -lt $deadline) {
            if (-not $outEnded -and $outTask.IsCompleted) {
                $n=$outTask.Result;$total+=$n
                if ($n -eq 0) {$outEnded=$true} else {[void]$output.Append($outBuffer,0,$n);$outTask=$process.StandardOutput.ReadAsync($outBuffer,0,2048)}
            }
            if (-not $errEnded -and $errTask.IsCompleted) {
                $n=$errTask.Result;$total+=$n
                if ($n -eq 0) {$errEnded=$true} else {$errTask=$process.StandardError.ReadAsync($errBuffer,0,2048)}
            }
            if ($total -gt 65536) {New-GdiagIntegrationEvidence 'agent.codex.effective' 'truncated' @{reason='native host output exceeded 64K'};return}
            if ($process.HasExited -and $outEnded -and $errEnded) {break}
            Start-Sleep -Milliseconds 20
        }
        if (-not $process.HasExited -or -not $outEnded -or -not $errEnded) {New-GdiagIntegrationEvidence 'agent.codex.effective' 'timeout' @{reason='native host list exceeded ten seconds'};return}
        if ($process.ExitCode -ne 0) {New-GdiagIntegrationEvidence 'agent.codex.effective' 'collection_error' @{reason='native host rejected configuration or command';exitCode=$process.ExitCode;next='Read host diagnostics locally; stderr withheld from agent output.'};return}
        $servers=ConvertFrom-Json -InputObject $output.ToString() -ErrorAction Stop
        foreach ($server in @($servers)) {
            $transport=$server.transport
            $state='observed';$commandState='not_applicable'
            if ($transport.type -eq 'stdio') {
                $command=[string]$transport.command
                if ([IO.Path]::IsPathRooted($command)) {$exists=Test-Path -LiteralPath $command -PathType Leaf} else {$exists=$null -ne (Get-Command $command -ErrorAction SilentlyContinue)}
                $commandState=$(if($exists){'resolved_in_collector_context'}else{'missing_in_collector_context'})
                if (-not $exists) {$state='absent'}
            }
            $summary=@{transport=$transport.type;enabled=$server.enabled;authStatus=$server.auth_status;launcher=$commandState;next='Host configuration listing is not MCP protocol readiness; run authorized handshake in actual host.'}
            New-GdiagIntegrationEvidence 'agent.codex.effective-mcp' $state $summary
        }
        New-GdiagIntegrationEvidence 'agent.codex.effective' 'observed' @{reason='native host parsed effective MCP configuration';serverCount=@($servers).Count;next='Host policy, discovery and protocol acceptance remain separate.'}
    } catch {New-GdiagIntegrationEvidence 'agent.codex.effective' 'collection_error' @{reason='native host inspection failed or returned invalid JSON'} @{type=$_.Exception.GetType().FullName;hresult=$_.Exception.HResult}} finally {
        if ($started -and -not $process.HasExited) {$process.Kill();[void]$process.WaitForExit(1000)}
        $process.Dispose()
    }
}

function Get-GdiagHttpNextStep {
    param([int]$Status)
    switch ($Status) {
        401 {'Use the selected service normal sign-in/credential renewal; no credential was sent by this probe.'}
        403 {'Check service account, organization/model permission and policy; this response alone cannot identify which denied access.'}
        407 {'Use the enterprise proxy authentication mechanism; do not reset global proxy settings.'}
        429 {'Inspect service quota/rate-limit headers locally; avoid speculative retries.'}
        default {'HTTP route responded; account/model authorization and streaming remain unverified.'}
    }
}

function Invoke-GdiagConnectivity {
    param([hashtable]$Context,[string]$Endpoint,[int]$TimeoutSeconds=10,[switch]$DirectStages)
    if (-not $Endpoint) {New-GdiagIntegrationEvidence 'connectivity' 'not_applicable' 'No endpoint selected; routine scan makes no model request.';return}
    $uri=$null
    if (-not [Uri]::TryCreate($Endpoint,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query) {throw 'Endpoint must be HTTPS without credentials or query parameters.'}
    $deadline=[DateTime]::UtcNow.AddSeconds([Math]::Max(1,[Math]::Min(60,$TimeoutSeconds)))
    $route=@{stack='PowerShell/.NET HttpWebRequest';endpoint=($uri.GetLeftPart([UriPartial]::Path));agentRoute='unverified';gcadRoute='unverified';utc=[DateTime]::UtcNow.ToString('o');proxyVariableNames=@('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY' | Where-Object {[Environment]::GetEnvironmentVariable($_)})}
    New-GdiagIntegrationEvidence 'connectivity.context' 'observed' @{route='script only; agent and GCAD route unverified';utc=$route.utc;proxyType=$(if([Net.WebRequest]::DefaultWebProxy){[Net.WebRequest]::DefaultWebProxy.GetType().FullName}else{'none'});next='UTC observed, not verified against trusted time. Effective proxy routing uses .NET policy; environment names do not prove applied proxy.'}
    $addresses=@()
    $dns=$null
    try {
        $dns=[Net.Dns]::BeginGetHostAddresses($uri.DnsSafeHost,$null,$null)
        # Reserve time for an effective proxy route, which may resolve DNS remotely.
        $dnsBudget=[Math]::Min(2000,[Math]::Max(1,[int](($deadline-[DateTime]::UtcNow).TotalMilliseconds/4)))
        if (-not $dns.AsyncWaitHandle.WaitOne($dnsBudget)) {
            New-GdiagIntegrationEvidence 'connectivity.dns' 'timeout' @{route='script direct resolver';next='DNS resolution did not complete within the deadline; a proxy may resolve remotely.'}
        } else {
            $addresses=@([Net.Dns]::EndGetHostAddresses($dns))
            New-GdiagIntegrationEvidence 'connectivity.dns' 'observed' @{route='script direct resolver';addressCount=$addresses.Count}
        }
    } catch {New-GdiagIntegrationEvidence 'connectivity.dns' 'collection_error' @{route='script direct resolver';next='Resolve DNS/network policy; proxy routing remains a separate check.'} @{domain='DNS';code=$_.Exception.GetBaseException().GetType().Name;hresult=$_.Exception.GetBaseException().HResult}} finally {if ($dns) {$dns.AsyncWaitHandle.Close()}}
    if ($DirectStages -and $addresses.Count -and [DateTime]::UtcNow -lt $deadline) {
        $client=New-Object Net.Sockets.TcpClient($addresses[0].AddressFamily)
        $stream=$null;$stage='tcp';$pending=$null
        try {
            $pending=$client.BeginConnect($addresses[0],$uri.Port,$null,$null)
            if (-not $pending.AsyncWaitHandle.WaitOne([Math]::Max(1,[int]($deadline-[DateTime]::UtcNow).TotalMilliseconds))) {throw [TimeoutException]::new('Direct TCP deadline')}
            $client.EndConnect($pending);$pending.AsyncWaitHandle.Close();$pending=$null
            New-GdiagIntegrationEvidence 'connectivity.tcp' 'observed' @{route='explicit direct socket; bypasses configured HTTP proxy';next='Only the first resolved address was tested; effective product/agent/proxy routes remain unverified.'}
            $stage='tls';$stream=New-Object Net.Security.SslStream($client.GetStream(),$false)
            $pending=$stream.BeginAuthenticateAsClient($uri.DnsSafeHost,$null,$null)
            if (-not $pending.AsyncWaitHandle.WaitOne([Math]::Max(1,[int]($deadline-[DateTime]::UtcNow).TotalMilliseconds))) {throw [TimeoutException]::new('Direct TLS deadline')}
            $stream.EndAuthenticateAsClient($pending)
            New-GdiagIntegrationEvidence 'connectivity.tls' 'observed' @{route='explicit direct SslStream; normal OS certificate validation';tlsProtocol=$stream.SslProtocol.ToString();next='Trust succeeded for this direct route only; no global trust setting changed.'}
        } catch {
            $cause=$_.Exception.GetBaseException()
            New-GdiagIntegrationEvidence ('connectivity.'+$stage) $(if($cause -is [TimeoutException]){'timeout'}else{'collection_error'}) @{route='explicit direct socket/SslStream';next='Inspect native failure, system time and enterprise trust/transport policy. Never disable TLS validation.'} @{domain=$stage;code=$cause.GetType().Name;hresult=$cause.HResult}
        } finally {if($stream){$stream.Dispose()};$client.Close();if($pending){$pending.AsyncWaitHandle.Close()}}
    }
    if ([DateTime]::UtcNow -ge $deadline) {New-GdiagIntegrationEvidence 'connectivity.http' 'timeout' @{route='effective .NET proxy route';reason='shared endpoint deadline exhausted before HTTP stage'};return}
    $request=[Net.HttpWebRequest]::Create($uri)
    $request.Method='HEAD';$request.Timeout=[Math]::Max(1,[int]($deadline-[DateTime]::UtcNow).TotalMilliseconds);$request.ReadWriteTimeout=$request.Timeout;$request.AllowAutoRedirect=$false
    $httpPending=$null
    try {
        $httpPending=$request.BeginGetResponse($null,$null)
        if (-not $httpPending.AsyncWaitHandle.WaitOne([Math]::Max(1,[int]($deadline-[DateTime]::UtcNow).TotalMilliseconds))) {
            $request.Abort()
            throw [Net.WebException]::new('HTTP deadline exceeded',[Net.WebExceptionStatus]::Timeout)
        }
        $response=$request.EndGetResponse($httpPending)
        try {New-GdiagIntegrationEvidence 'connectivity.http' 'observed' @{route=$route;httpStatus=[int]$response.StatusCode;authentication='not tested; no credentials sent';streaming='not tested';next=(Get-GdiagHttpNextStep ([int]$response.StatusCode))}} finally {$response.Close()}
    } catch [Net.WebException] {
        $failure=$_.Exception
        if ($failure.Response) {
            try {New-GdiagIntegrationEvidence 'connectivity.http' 'observed' @{route=$route;httpStatus=[int]$failure.Response.StatusCode;authentication='HTTP response alone does not establish account/model access';next=(Get-GdiagHttpNextStep ([int]$failure.Response.StatusCode))} @{domain='WebException';code=$failure.Status.ToString()}} finally {$failure.Response.Close()}
        } else {New-GdiagIntegrationEvidence 'connectivity.transport' $(if($failure.Status -eq 'Timeout'){'timeout'}else{'collection_error'}) $route @{domain='WebException';code=$failure.Status.ToString();hresult=$failure.HResult}}
    } finally {if($httpPending){$httpPending.AsyncWaitHandle.Close()};$request.Abort()}
}

function ConvertTo-GdiagWindowsArgument {
    param([string]$Value)
    # CommandLineToArgvW escaping, including trailing backslashes before the closing quote.
    '"' + ([regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')) + '"'
}

function Invoke-GdiagMcpProbe {
    param([hashtable]$Context,[hashtable]$Options=@{},[int]$TimeoutSeconds=10)
    $mcp=$Options.mcp
    if (-not $mcp -or -not $mcp.command) {New-GdiagIntegrationEvidence 'mcp' 'not_applicable' 'Supply an explicitly authorized stdio launcher in InputFile.mcp; configuration evidence is never executed automatically.';return}
    if ($mcp.transport -and $mcp.transport -ne 'stdio') {New-GdiagIntegrationEvidence 'mcp' 'unavailable' 'Use host protocol diagnostics for remote transports; script probe supports stdio.';return}
    $command=[string]$mcp.command
    if (-not [IO.Path]::IsPathRooted($command) -or -not (Test-Path -LiteralPath $command -PathType Leaf)) {New-GdiagIntegrationEvidence 'mcp.launch' 'absent' @{command=$command;next='Select an absolute executable path in the actual host context.'};return}
    $process=New-Object Diagnostics.Process
    $process.StartInfo.FileName=$command
    $process.StartInfo.Arguments=(@($mcp.args) | ForEach-Object {ConvertTo-GdiagWindowsArgument ([string]$_)}) -join ' '
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardInput=$true;$process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    if ($mcp.cwd) {$process.StartInfo.WorkingDirectory=[string]$mcp.cwd}
    $deadline=[DateTime]::UtcNow.AddSeconds([Math]::Max(1,[Math]::Min(60,$TimeoutSeconds)))
    $stage='launch';$bytes=0;$stderrLines=0;$started=$false
    try {
        $started=$process.Start()
        if (-not $started) {throw 'Process did not start.'}
        $stage='initialize'
        $process.StandardInput.WriteLine('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"gcaddiag","version":"1"}}}')
        $process.StandardInput.Flush()
        $outBuffer=New-Object char[] 2048;$errBuffer=New-Object char[] 2048
        $pending='';$outEnded=$false;$errEnded=$false
        $outTask=$process.StandardOutput.ReadAsync($outBuffer,0,2048);$errTask=$process.StandardError.ReadAsync($errBuffer,0,2048)
        while ([DateTime]::UtcNow -lt $deadline) {
            if (-not $errEnded -and $errTask.IsCompleted) {
                $n=$errTask.Result;$bytes+=$n
                if ($n -eq 0) {$errEnded=$true} else {$stderrLines+=([regex]::Matches((-join $errBuffer[0..($n-1)]),"`n")).Count;$errTask=$process.StandardError.ReadAsync($errBuffer,0,2048)}
            }
            if (-not $outEnded -and $outTask.IsCompleted) {
                $n=$outTask.Result;$bytes+=$n
                if ($n -eq 0) {$outEnded=$true} else {$pending+=(-join $outBuffer[0..($n-1)]);$outTask=$process.StandardOutput.ReadAsync($outBuffer,0,2048)}
            }
            if ($bytes -gt 65536) {New-GdiagIntegrationEvidence 'mcp.protocol' 'truncated' @{stage=$stage;limit=65536};return}
            while ($pending.Contains("`n")) {
                $index=$pending.IndexOf("`n");$line=$pending.Substring(0,$index).TrimEnd("`r");$pending=$pending.Substring($index+1)
                try {$message=ConvertFrom-Json -InputObject $line -ErrorAction Stop} catch {New-GdiagIntegrationEvidence 'mcp.protocol' 'collection_error' @{stage=$stage;reason='non-JSON stdout';stderrLines=$stderrLines};return}
                if($message -isnot [pscustomobject] -or $message.jsonrpc -isnot [string] -or $message.jsonrpc -cne '2.0') {New-GdiagIntegrationEvidence 'mcp.protocol' 'collection_error' @{stage=$stage;reason='invalid JSON-RPC envelope'};return}
                $numericResponseId=($message.id -is [int] -or $message.id -is [long] -or $message.id -is [double] -or $message.id -is [decimal])
                if($message.PSObject.Properties['method']){
                    if($message.method -isnot [string] -or -not $message.method -or $message.PSObject.Properties['result'] -or $message.PSObject.Properties['error'] -or ($message.PSObject.Properties['params'] -and $message.params -isnot [pscustomobject])){New-GdiagIntegrationEvidence 'mcp.protocol' 'collection_error' @{stage=$stage;reason='invalid server request or notification'};return}
                    if($message.PSObject.Properties['id']){
                        if(-not $numericResponseId -and $message.id -isnot [string]){New-GdiagIntegrationEvidence 'mcp.protocol' 'collection_error' @{stage=$stage;reason='invalid server request ID'};return}
                        # Ping is allowed during initialization. Server request IDs are
                        # independent of our request IDs; never interpret one as a response.
                        $reply=if($message.method -ceq 'ping'){@{jsonrpc='2.0';id=$message.id;result=@{}}}else{@{jsonrpc='2.0';id=$message.id;error=@{code=-32601;message='Client method is not supported by this diagnostic probe.'}}}
                        # A peer can emit requests without reading replies. Keep writes
                        # under the same deadline so a full stdin pipe cannot hang diagnosis.
                        foreach($writeStage in @('reply','flush')){
                            $remaining=[int](($deadline-[DateTime]::UtcNow).TotalMilliseconds)
                            if($remaining -le 0){New-GdiagIntegrationEvidence 'mcp.protocol' 'timeout' @{stage=$stage;reason='server reply deadline exceeded'};return}
                            $writeTask=if($writeStage -eq 'reply'){$process.StandardInput.WriteLineAsync(($reply | ConvertTo-Json -Depth 5 -Compress))}else{$process.StandardInput.FlushAsync()}
                            if(-not $writeTask.Wait($remaining)){New-GdiagIntegrationEvidence 'mcp.protocol' 'timeout' @{stage=$stage;reason='server did not consume diagnostic reply'};return}
                        }
                    }
                    # Unknown notifications are data only. No requested tools/code run.
                    continue
                }
                if($message.PSObject.Properties['id'] -and -not $message.PSObject.Properties['method'] -and -not $numericResponseId) {New-GdiagIntegrationEvidence 'mcp.protocol' 'collection_error' @{stage=$stage;reason='response ID does not match numeric request'};return}
                if ($message.id -eq 1 -and $stage -eq 'initialize') {
                    if ($message.PSObject.Properties['error'] -or $message.PSObject.Properties['method'] -or $message.result -isnot [pscustomobject] -or $message.result.protocolVersion -isnot [string] -or $message.result.capabilities -isnot [pscustomobject] -or $message.result.serverInfo -isnot [pscustomobject] -or $message.result.serverInfo.name -isnot [string] -or $message.result.serverInfo.version -isnot [string]) {New-GdiagIntegrationEvidence 'mcp.protocol' 'collection_error' @{stage=$stage;reason='initialization rejected or invalid'};return}
                    # This probe implements the 2024-11-05 lifecycle/tools schema only.
                    # https://modelcontextprotocol.io/specification/2024-11-05/basic/lifecycle
                    if($message.result.protocolVersion -cne '2024-11-05'){New-GdiagIntegrationEvidence 'mcp.protocol' 'unavailable' @{stage=$stage;reason='server negotiated an unsupported protocol version'};return}
                    if($message.result.capabilities.tools -isnot [pscustomobject]){New-GdiagIntegrationEvidence 'mcp.protocol' 'unavailable' @{stage=$stage;initialize='succeeded';discovery='not_applicable';reason='server did not declare the tools capability'};return}
                    $process.StandardInput.WriteLine('{"jsonrpc":"2.0","method":"notifications/initialized"}')
                    $process.StandardInput.WriteLine('{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}');$process.StandardInput.Flush();$stage='tools/list'
                } elseif ($message.id -eq 2 -and $stage -eq 'tools/list') {
                    if ($message.PSObject.Properties['error'] -or $message.PSObject.Properties['method'] -or $message.result -isnot [pscustomobject] -or $message.result.tools -isnot [array]) {New-GdiagIntegrationEvidence 'mcp.protocol' 'collection_error' @{stage=$stage;reason='discovery rejected or invalid'};return}
                    # Required Tool fields from the negotiated version; descriptions/schema contents stay private.
                    $invalidTool=@($message.result.tools|Where-Object {$_ -isnot [pscustomobject] -or $_.name -isnot [string] -or $_.inputSchema -isnot [pscustomobject] -or $_.inputSchema.type -isnot [string] -or $_.inputSchema.type -cne 'object' -or ($_.PSObject.Properties['description'] -and $_.description -isnot [string]) -or ($_.inputSchema.PSObject.Properties['properties'] -and $_.inputSchema.properties -isnot [pscustomobject]) -or ($_.inputSchema.PSObject.Properties['required'] -and ($_.inputSchema.required -isnot [array] -or @($_.inputSchema.required|Where-Object {$_ -isnot [string]}).Count))})
                    if($invalidTool.Count -or ($message.result.PSObject.Properties['nextCursor'] -and $message.result.nextCursor -isnot [string])){New-GdiagIntegrationEvidence 'mcp.protocol' 'collection_error' @{stage=$stage;reason='invalid tools discovery schema'};return}
                    $discovery=if($message.result.PSObject.Properties['nextCursor']){'first_page_succeeded'}else{'succeeded'}
                    New-GdiagIntegrationEvidence 'mcp.protocol' 'observed' @{initialize='succeeded';discovery=$discovery;toolCount=$message.result.tools.Count;stderrLines=$stderrLines;route='explicit script launcher; actual host environment unverified'};return
                }
            }
            if ($outEnded) {
                $exited=$process.WaitForExit(100)
                New-GdiagIntegrationEvidence 'mcp.protocol' 'collection_error' @{stage=$stage;reason='stdout closed before protocol completed';stderrLines=$stderrLines;exitCode=$(if($exited){$process.ExitCode}else{$null});next='Inspect the selected launcher exit status and its local startup diagnostics; a closed stream is not a successful protocol handshake.'}
                return
            }
            Start-Sleep -Milliseconds 20
        }
        New-GdiagIntegrationEvidence 'mcp.protocol' 'timeout' @{stage=$stage;stderrLines=$stderrLines}
    } catch {New-GdiagIntegrationEvidence 'mcp.launch' 'collection_error' @{stage=$stage} @{type=$_.Exception.GetType().FullName;hresult=$_.Exception.HResult}} finally {
        if ($started -and -not $process.HasExited) {$process.Kill();[void]$process.WaitForExit(1000)}
        $process.Dispose()
    }
}
