$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/modules/Integration.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/modules/Lifecycle.ps1')
function Assert($condition,$message) {if (-not $condition) {throw $message}}
$root=Join-Path $env:TEMP ('gcaddiag-integration-'+[Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $root)
try {
    $skills=Join-Path $root '.agents/skills/broken'
    [void](New-Item -ItemType Directory -Path $skills -Force)
    [IO.File]::WriteAllText((Join-Path $skills 'SKILL.md'),"---`nname: broken`ndescription: Test`n---`n[missing](references/no.md)")
    $config=Join-Path $root 'bad.json';[IO.File]::WriteAllText($config,'{"invalid":')
    $context=@{profilePath=$root;executorSid='test';affectedSid='test'}
    $result=@(Get-GdiagAgentEvidence -Context $context -Options @{configPaths=@($config)})
    Assert (@($result | Where-Object {$_.source -eq 'agent.skills' -and $_.status -eq 'incomplete'}).Count -eq 1) 'Missing skill resource not detected'
    Assert (@($result | Where-Object {$_.source -eq 'agent.configuration' -and $_.status -eq 'collection_error'}).Count -eq 1) 'Malformed config not detected'
    $largeSkill=Join-Path $root '.agents/skills/oversized';New-Item -ItemType Directory -Path $largeSkill|Out-Null
    $largePath=Join-Path $largeSkill 'SKILL.md';$largeStream=[IO.File]::Create($largePath)
    try{$largeStream.SetLength(1048577)}finally{$largeStream.Dispose()}
    $boundedSkills=@(Get-GdiagAgentEvidence -Context $context)
    Assert (@($boundedSkills|Where-Object {$_.source -eq 'agent.skills' -and $_.observed.path -eq $largePath -and $_.status -eq 'truncated'}).Count -eq 1) 'Oversized skill was read instead of rejected at the byte bound'
    [IO.File]::WriteAllText($largePath,('x'*262145))
    $boundedSkills=@(Get-GdiagAgentEvidence -Context $context)
    Assert (@($boundedSkills|Where-Object {$_.source -eq 'agent.skills' -and $_.observed.path -eq $largePath -and $_.status -eq 'truncated'}).Count -eq 1) 'Decoded skill content exceeded its character bound'
    $denied=@(Get-GdiagAgentEvidence -Context @{executorSid='sandbox';affectedSid='user'} -Options @{})
    Assert ($denied[0].status -eq 'unavailable') 'Wrong identity accepted'
    $missing=@(Invoke-GdiagMcpProbe -Context $context -Options @{mcp=@{command=(Join-Path $root 'missing.exe')}})
    Assert ($missing[0].status -eq 'absent') 'Missing launcher not detected'
    $server=@'
$a=[Console]::ReadLine()
[Console]::WriteLine('{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}')
$b=[Console]::ReadLine()
$c=[Console]::ReadLine()
[Console]::WriteLine('{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}')
Start-Sleep -Seconds 20
'@
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($server))
    $launcher=(Get-Command powershell.exe).Source
    $exited=@(Invoke-GdiagMcpProbe -Context $context -Options @{mcp=@{command=$launcher;args=@('-NoProfile','-Command','exit 23')}} -TimeoutSeconds 8)
    Assert ($exited[-1].status -eq 'collection_error' -and $exited[-1].observed.exitCode -eq 23 -and $exited[-1].publicSummary -match 'exitCode=23') 'MCP early process exit lost native exit status'
    $good=@(Invoke-GdiagMcpProbe -Context $context -Options @{mcp=@{command=$launcher;args=@('-NoProfile','-EncodedCommand',$encoded)}} -TimeoutSeconds 8)
    Assert ($good[-1].status -eq 'observed' -and $good[-1].observed.discovery -eq 'succeeded') 'Protocol discovery failed'
    $serverRequest=@'
[Console]::WriteLine('{"jsonrpc":"2.0","id":REQUEST_ID,"method":"REQUEST_METHOD"}')
$reply=[Console]::ReadLine()|ConvertFrom-Json
if($reply.id -cne REQUEST_ID -or $reply.jsonrpc -cne '2.0'){exit 31}
if('REQUEST_METHOD' -eq 'ping'){if($reply.result -isnot [pscustomobject] -or @($reply.result.PSObject.Properties).Count -ne 0 -or $reply.error){exit 32}}
else{if($reply.error.code -ne -32601 -or $reply.PSObject.Properties['result']){exit 33}}
'@
    foreach($request in @(@{id=1;method='ping'},@{id='server-ping';method='ping'},@{id=1;method='tools/call'})){
        $requestScript=$serverRequest.Replace('REQUEST_ID',(ConvertTo-Json -InputObject $request.id -Compress)).Replace('REQUEST_METHOD',$request.method)
        $requestServer=$server.Replace('$a=[Console]::ReadLine()',('$a=[Console]::ReadLine()'+"`n"+$requestScript))
        $requestEncoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($requestServer))
        $handled=@(Invoke-GdiagMcpProbe -Context $context -Options @{mcp=@{command=$launcher;args=@('-NoProfile','-EncodedCommand',$requestEncoded)}} -TimeoutSeconds 8)
        Assert ($handled[-1].status -eq 'observed' -and $handled[-1].observed.discovery -eq 'succeeded') ('Server request interfered with response handling: '+$request.method)
    }
    foreach($invalid in @(
        @{name='unsupported version';script=$server.Replace('2024-11-05','2099-01-01');status='unavailable'},
        @{name='array protocol version';script=$server.Replace('"protocolVersion":"2024-11-05"','"protocolVersion":["2024-11-05"]');status='collection_error'},
        @{name='missing tools capability';script=$server.Replace('"tools":{}','"resources":{}');status='unavailable'},
        @{name='invalid JSON-RPC version';script=$server.Replace('"jsonrpc":"2.0"','"jsonrpc":"1.0"');status='collection_error'},
        @{name='numeric JSON-RPC version';script=$server.Replace('"jsonrpc":"2.0"','"jsonrpc":2.0');status='collection_error'},
        @{name='string response ID';script=$server.Replace('"id":1','"id":"1"');status='collection_error'},
        @{name='array response ID';script=$server.Replace('"id":1','"id":[1]');status='collection_error'},
        @{name='null tools';script=$server.Replace('"tools":[]','"tools":null');status='collection_error'},
        @{name='object tools';script=$server.Replace('"tools":[]','"tools":{}');status='collection_error'},
        @{name='missing tool schema';script=$server.Replace('"tools":[]','"tools":[{"name":"broken"}]');status='collection_error'},
        @{name='array tool schema type';script=$server.Replace('"tools":[]','"tools":[{"name":"broken","inputSchema":{"type":["object"]}}]');status='collection_error'},
        @{name='invalid required schema';script=$server.Replace('"tools":[]','"tools":[{"name":"broken","inputSchema":{"type":"object","required":"argument"}}]');status='collection_error'}
    )){
        $badEncoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($invalid.script))
        $bad=@(Invoke-GdiagMcpProbe -Context $context -Options @{mcp=@{command=$launcher;args=@('-NoProfile','-EncodedCommand',$badEncoded)}} -TimeoutSeconds 8)
        Assert ($bad[-1].status -eq $invalid.status -and $bad[-1].observed.discovery -ne 'succeeded') ('Invalid protocol response accepted: '+$invalid.name)
    }
    $pagedScript=$server.Replace('"tools":[]','"tools":[{"name":"fixture","inputSchema":{"type":"object","properties":{},"required":[]}}],"nextCursor":"private-cursor"')
    $pagedEncoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($pagedScript))
    $paged=@(Invoke-GdiagMcpProbe -Context $context -Options @{mcp=@{command=$launcher;args=@('-NoProfile','-EncodedCommand',$pagedEncoded)}} -TimeoutSeconds 8)
    Assert ($paged[-1].status -eq 'observed' -and $paged[-1].observed.discovery -eq 'first_page_succeeded' -and $paged[-1].observed.toolCount -eq 1 -and $paged[-1].publicSummary -notmatch 'private-cursor') 'Valid paginated discovery was rejected or presented as complete'
    $sleep=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 20'))
    $timeout=@(Invoke-GdiagMcpProbe -Context $context -Options @{mcp=@{command=$launcher;args=@('-NoProfile','-EncodedCommand',$sleep)}} -TimeoutSeconds 1)
    Assert ($timeout[-1].status -eq 'timeout') 'Owned hung launcher did not time out'
    $flood=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('[Console]::Write(("x" * 70000)); Start-Sleep -Seconds 20'))
    $bounded=@(Invoke-GdiagMcpProbe -Context $context -Options @{mcp=@{command=$launcher;args=@('-NoProfile','-EncodedCommand',$flood)}} -TimeoutSeconds 8)
    Assert ($bounded[-1].status -eq 'truncated') 'Non-newline MCP output exceeded bounded capture'
    $pingFloodServer=@'
$request='{"jsonrpc":"2.0","id":"'+('x'*256)+'","method":"ping"}'
for($i=0;$i -lt 1000;$i++){[Console]::WriteLine($request)}
Start-Sleep -Seconds 20
'@
    $pingFlood=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($pingFloodServer))
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $blockedReply=@(Invoke-GdiagMcpProbe -Context $context -Options @{mcp=@{command=$launcher;args=@('-NoProfile','-EncodedCommand',$pingFlood)}} -TimeoutSeconds 2)
    $watch.Stop()
    Assert ($blockedReply[-1].status -in @('timeout','truncated') -and $watch.Elapsed.TotalSeconds -lt 6) 'Peer refusing replies bypassed the MCP deadline'
    $network=@(Invoke-GdiagConnectivity -Context $context -Endpoint 'https://127.0.0.1:1/' -TimeoutSeconds 1)
    Assert ($network[-1].source -eq 'connectivity.transport') 'Transport failure conflated with HTTP'
    Assert ($network[-1].observed.gcadRoute -eq 'unverified') 'Generic route claimed product readiness'
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $direct=@(Invoke-GdiagConnectivity -Context $context -Endpoint 'https://127.0.0.1:1/' -TimeoutSeconds 2 -DirectStages)
    $watch.Stop()
    Assert (@($direct | Where-Object {$_.source -eq 'connectivity.dns'}).Count -eq 1) 'DNS stage missing'
    Assert (@($direct | Where-Object {$_.source -eq 'connectivity.tcp' -and $_.status -ne 'observed'}).Count -eq 1) 'Refused direct socket failure missing'
    Assert ($watch.Elapsed.TotalSeconds -lt 6) 'Network operation exceeded bounded deadline'
    # Diagnose and repair a selected WorkBuddy code-project installation without
    # touching personal host configuration or claiming live host discovery.
    $project=Join-Path $root 'selected project'
    $source=Join-Path $root 'trusted package'
    [void](New-Item -ItemType Directory -Path (Join-Path $source 'references') -Force)
    [IO.File]::WriteAllText((Join-Path $source 'SKILL.md'),"---`nname: fixture-gcad`ndescription: fixture`n---`n[operation](references/operation.md)")
    [IO.File]::WriteAllText((Join-Path $source 'references/operation.md'),'fixture resource')
    $casePath=Join-Path $root 'integration case';[void](New-Item -ItemType Directory -Path $casePath)
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $live=@{caseId='isolated-project-integration';casePath=$casePath;machine=[Environment]::MachineName;executorSid=$sid;affectedSid=$sid;profilePath=$root}
    $target=[pscustomobject]@{id='project-skill';path=(Join-Path $project '.codebuddy/skills/fixture-gcad');family='Skill'}
    Write-GdiagLifeJson (Join-Path $casePath 'case.json') @{formatVersion=1;caseId=$live.caseId;context=$live;targets=@($target)}
    $package=@{recipe='skill-package';sourcePath=$source;expectedPackageHash=(Get-GdiagTreeHash @(Get-GdiagTree $source))}
    $planPath=Join-Path $casePath 'plan.json'
    Write-GdiagLifeJson $planPath (New-GdiagPlan $live $target Setup $package)
    Assert ((Invoke-GdiagPlan $planPath Apply).status -eq 'applied') 'Project integration setup failed'
    $userSkill=Join-Path $root '.codebuddy/skills/fixture-gcad';[void](New-Item -ItemType Directory -Path $userSkill -Force)
    Copy-Item -LiteralPath (Join-Path $source 'SKILL.md') -Destination (Join-Path $userSkill 'SKILL.md')
    $setting=Join-Path $project '.codebuddy/settings.json';[IO.File]::WriteAllText($setting,'{"customSetting":"keep"}')
    $beforeSetting=Get-GdiagFileHash $setting
    $resource=Join-Path $target.path 'references/operation.md';Remove-Item -LiteralPath $resource
    $hostOptions=@{host='WorkBuddyProject';projectPath=$project}
    $broken=@(Get-GdiagAgentEvidence -Context $live -Options $hostOptions)
    Assert (@($broken | Where-Object {$_.source -eq 'agent.skills' -and $_.observed.path -eq (Join-Path $target.path 'SKILL.md') -and $_.status -eq 'incomplete'}).Count -eq 1) 'Broken selected project skill was not attributed'
    $scope=@($broken | Where-Object {$_.source -eq 'agent.workbuddy.project-precedence' -and $_.observed.name -eq 'fixture-gcad'})
    Assert ($scope.Count -eq 1 -and $scope[0].observed.expectedEffectivePath -eq (Join-Path $target.path 'SKILL.md')) 'WorkBuddy project-over-user selection unresolved'
    Write-GdiagLifeJson $planPath (New-GdiagPlan $live $target Repair $package)
    Assert ((Invoke-GdiagPlan $planPath Apply).status -eq 'applied') 'Selected missing-resource repair failed'
    Assert ((Invoke-GdiagPlan $planPath Verify).status -eq 'verified') 'Project integration file verification failed'
    $fixed=@(Get-GdiagAgentEvidence -Context $live -Options $hostOptions)
    Assert (@($fixed | Where-Object {$_.source -eq 'agent.skills' -and $_.observed.path -eq (Join-Path $target.path 'SKILL.md') -and $_.status -eq 'observed'}).Count -eq 1) 'Reinspection still reports incomplete project skill'
    Assert ((Get-GdiagFileHash $setting) -eq $beforeSetting) 'Unrelated project settings changed'
    'PASS integration: incomplete skill, malformed config, identity gap, missing launcher, real MCP discovery, owned timeout, transport distinction'
} finally {
    $resolved=[IO.Path]::GetFullPath($root)
    $temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
    if (-not $resolved.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)) {throw 'Unexpected test directory'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
