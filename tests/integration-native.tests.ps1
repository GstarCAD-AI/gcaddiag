param([Parameter(Mandatory=$true)][string]$CodexExecutable)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Integration.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path $PSScriptRoot ('.tmp-codex-native-'+[guid]::NewGuid().ToString('N'))
$homePath=Join-Path $root 'isolated-home';$project=Join-Path $root 'selected-project'
[void](New-Item -ItemType Directory -Path $homePath -Force)
[void](New-Item -ItemType Directory -Path $project)
$configPath=Join-Path $homePath 'config.toml'
[IO.File]::WriteAllText($configPath,"[mcp_servers.fixture]`ncommand = 'C:\missing-gcaddiag-fixture.exe'`n")
$options=@{codexExecutable=$CodexExecutable;codexHome=$homePath;projectPath=$project}
$broken=@(Get-GdiagCodexEffective -Context @{} -Options $options)
Assert (@($broken | Where-Object {$_.source -eq 'agent.codex.effective-mcp' -and $_.status -eq 'absent'}).Count -eq 1) 'Native Codex did not diagnose missing configured launcher'
$server=@'
[void][Console]::ReadLine()
[Console]::WriteLine('{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}')
[void][Console]::ReadLine()
[void][Console]::ReadLine()
[Console]::WriteLine('{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}')
Start-Sleep -Seconds 20
'@
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($server))
$launcher=(Get-Command powershell.exe).Source
$arguments=@('-NoProfile','-EncodedCommand',$encoded)
$launcherJson=ConvertTo-Json -InputObject $launcher -Compress
$argsJson=ConvertTo-Json -InputObject $arguments -Compress
[IO.File]::WriteAllText($configPath,"[mcp_servers.fixture]`ncommand = $launcherJson`nargs = $argsJson`n")
$corrected=@(Get-GdiagCodexEffective -Context @{} -Options $options)
Assert (@($corrected | Where-Object {$_.source -eq 'agent.codex.effective-mcp' -and $_.status -eq 'observed' -and $_.observed.launcher -eq 'resolved_in_collector_context'}).Count -eq 1) 'Native Codex failed to resolve corrected launcher'
$handshake=@(Invoke-GdiagMcpProbe -Context @{} -Options @{mcp=@{command=$launcher;args=$arguments;cwd=$project}} -TimeoutSeconds 8)
Assert ($handshake[-1].status -eq 'observed' -and $handshake[-1].observed.discovery -eq 'succeeded') 'Corrected fixture failed script protocol discovery'
$evidence=@($broken)+@($corrected)+@($handshake) | Select-Object source,status,publicSummary
[IO.File]::WriteAllText((Join-Path $root 'acceptance.json'),(ConvertTo-Json -InputObject $evidence -Depth 5))
Write-Output ('PASS native Codex effective config broken/corrected; script MCP initialize/discovery; actual host skill invocation pending: '+$root)
