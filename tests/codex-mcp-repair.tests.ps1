param([Parameter(Mandatory=$true)][string]$CodexExecutable)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/CodexMcpRepair.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path $PSScriptRoot ('.tmp-codex-mcp-repair-'+[guid]::NewGuid())
$homeDirectory=Join-Path $root ('isolated home '+[char]0x4E2D)
$project=Join-Path $root 'selected project';$casePath=Join-Path $root 'case'
New-Item -ItemType Directory -Path $homeDirectory,$project,$casePath|Out-Null
$config=Join-Path $homeDirectory 'config.toml';$utf8=New-Object Text.UTF8Encoding($false)
$original=@'
# Keep original comments and unrelated preferences.
model = "gpt-6"
approval_policy = "never"
[mcp_servers.selected]
command = 'C:\missing-fixture-launcher.exe'
args = ['--old']
enabled = false
cwd = 'C:\fixture-working-directory'
env_vars = ['GCAD_API_KEY']
[mcp_servers.selected.env]
PRIVATE_TEST_TOKEN = 'sk-fixture-private-do-not-emit'
[mcp_servers.other]
command = 'C:\leave-this-server.exe'
args = ['--keep']
'@
[IO.File]::WriteAllText($config,$original,$utf8)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$context=@{caseId=[guid]::NewGuid().ToString();casePath=$casePath;machine=[Environment]::MachineName;executorSid=$sid;affectedSid=$sid}
$target=[pscustomobject]@{id='config-1';family='AgentConfig';path=$config}
Write-GdiagLifeJson (Join-Path $casePath 'case.json') @{formatVersion=1;kind='local';caseId=$context.caseId;context=$context;targets=@($target)}
$launcher=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$marker=Join-Path $root 'server-was-launched.txt'
$script="Set-Content -LiteralPath '"+$marker.Replace("'","''")+"' -Value unsafe"
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
$options=@{recipe='codex-mcp-stdio';serverName='selected';codexExecutable=[IO.Path]::GetFullPath($CodexExecutable);expectedCodexHash=(Get-GdiagFileHash $CodexExecutable);codexHome=$homeDirectory;projectPath=$project;expectedConfigHash=(Get-GdiagFileHash $config);commandPath=$launcher;expectedCommandHash=(Get-GdiagFileHash $launcher);arguments=@('-NoProfile','-EncodedCommand',$encoded)}
$options.serverName='SELECTED';$caseMismatchRefused=$false
try{$null=New-GdiagCodexMcpPlan $context $target $options}catch{$caseMismatchRefused=$_.Exception.Message -match 'exact case-sensitive'}
Assert ($caseMismatchRefused -and (Get-GdiagFileHash $config) -eq $options.expectedConfigHash) 'Differently cased TOML server name was accepted for mutation'
$options.serverName='selected'
$plan=New-GdiagCodexMcpPlan $context $target $options
Assert (@($plan.changes[0].keys).Count -eq 2 -and $plan.changes[0].keys[0] -eq 'mcp_servers.selected.command' -and $plan.changes[0].keys[1] -eq 'mcp_servers.selected.args') 'Plan does not preview two exact MCP fields'
Write-GdiagLifeJson (Join-Path $casePath 'plan.json') $plan
$planText=$plan|ConvertTo-Json -Depth 30
Assert ($planText -notmatch 'sk-fixture-private|EncodedCommand|leave-this-server') 'Private original/argument data leaked into plan'
Assert ((Get-GdiagFileHash $config) -eq $options.expectedConfigHash) 'Planning changed configuration'
[IO.File]::AppendAllText($config,"`n# user edit before apply`n",$utf8)
$stale=Invoke-GdiagCodexMcpPlan $plan Apply $casePath
Assert ($stale.status -eq 'failed') 'Stale config accepted'
Assert (-not(Test-Path -LiteralPath (Join-Path $casePath ($plan.planId+'.state.json')))) 'Stale plan started a write'
[IO.File]::WriteAllText($config,$original,$utf8)
$applied=Invoke-GdiagCodexMcpPlan $plan Apply $casePath
Assert ($applied.status -eq 'applied') ('Native MCP repair failed: '+$applied.error)
$after=[IO.File]::ReadAllText($config)
Assert ($after.Contains('PRIVATE_TEST_TOKEN') -and $after.Contains('sk-fixture-private-do-not-emit') -and $after.Contains('leave-this-server.exe') -and $after.Contains('# Keep original comments')) 'Unrelated TOML content was lost'
Assert (-not(Test-Path -LiteralPath $marker)) 'MCP server was launched by configuration repair'
$verified=Invoke-GdiagCodexMcpPlan $plan Verify $casePath
Assert ($verified.status -eq 'verified') ('Native effective configuration verification failed: '+$verified.error)
[IO.File]::AppendAllText($config,"`n# user edit after apply`n",$utf8)
$changed=Get-GdiagFileHash $config
$protected=Invoke-GdiagCodexMcpPlan $plan Undo $casePath
Assert ($protected.status -eq 'failed' -and (Get-GdiagFileHash $config) -eq $changed) 'Undo overwrote intervening user edit'
[IO.File]::WriteAllText($config,$after,$utf8)
$undone=Invoke-GdiagCodexMcpPlan $plan Undo $casePath
Assert ($undone.status -eq 'undone' -and (Get-GdiagFileHash $config) -eq $options.expectedConfigHash) 'Exact original bytes were not restored'
# A trusted project overlay must prevent a user-file repair of shadowed fields;
# native batchWrite currently rejects project writes, so refuse them at Plan.
$projectConfigDirectory=Join-Path $project '.codex';New-Item -ItemType Directory -Path $projectConfigDirectory|Out-Null
$projectConfig=Join-Path $projectConfigDirectory 'config.toml'
[IO.File]::WriteAllText($projectConfig,"[mcp_servers.selected]`ncommand = 'C:\missing-project-launcher.exe'`nargs = ['--project-old']`n",$utf8)
$projectToml=ConvertTo-Json -InputObject $project -Compress
[IO.File]::AppendAllText($config,("`n[projects."+$projectToml+"]`ntrust_level = 'trusted'`n"),$utf8)
$options.expectedConfigHash=Get-GdiagFileHash $config
$shadowed=$false
try{$null=New-GdiagCodexMcpPlan $context $target $options}catch{$shadowed=$_.Exception.Message -match 'another configuration layer'}
Assert $shadowed 'Shadowed user launch fields were accepted for repair'
$projectTarget=[pscustomobject]@{id='config-project';family='AgentConfig';path=$projectConfig}
Write-GdiagLifeJson (Join-Path $casePath 'case.json') @{formatVersion=1;kind='local';caseId=$context.caseId;context=$context;targets=@($target,$projectTarget)}
$options.expectedConfigHash=Get-GdiagFileHash $projectConfig;$options.arguments=@('--stdio')
$projectRefused=$false
try{$null=New-GdiagCodexMcpPlan $context $projectTarget $options}catch{$projectRefused=$_.Exception.Message -match 'only the selected Codex home user'}
Assert ($projectRefused -and (Get-GdiagFileHash $projectConfig) -eq $options.expectedConfigHash) 'Unsupported project config write was not refused during planning'
$receipt=@{status='native-codex-config-repair-verified';root=$root;modelRequest=$false;serverLaunched=(Test-Path -LiteralPath $marker);personalConfigurationChanged=$false;applied=$applied.status;verified=$verified.status;undo=$undone.status;staleRefused=$true;interveningEditPreserved=$true;shadowedUserRefused=$true;projectWriteUnsupported=$true}
Write-GdiagLifeJson (Join-Path $root 'acceptance.json') $receipt
'PASS native Codex MCP repair: typed command/args edit, effective native reread, env/cwd/other server/comments preserved, exact Undo, stale/current-edit refusal, no server/model call. Artifacts: '+$root
