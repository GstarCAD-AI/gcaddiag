param([Parameter(Mandatory=$true)][string]$CodexExecutable,[ValidateRange(30,180)][int]$TimeoutSeconds=120,[switch]$UseAutoReview)
# Explicit acceptance only: this starts one real Codex model turn using existing host sign-in.
# No credentials are copied. User config is ignored for this isolated turn; managed controls/rules remain.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
$root=Join-Path $PSScriptRoot ('.tmp-host-invocation-'+[guid]::NewGuid())
$project=Join-Path $root 'selected-project';$skillRoot=Join-Path $project '.agents/skills'
New-Item -ItemType Directory -Path $skillRoot -Force | Out-Null
$package=Join-Path $root 'skill.zip'
& (Join-Path $PSScriptRoot '../packaging/package.ps1') -Output $package | Out-Null
Expand-Archive -LiteralPath $package -DestinationPath $skillRoot
$entry=Join-Path $skillRoot 'gcaddiag/scripts/gcaddiag.ps1'
$casePath=Join-Path $project 'case';$finalPath=Join-Path $root 'last-message.md'
$prompt=@'
Use $gcaddiag from this project's .agents/skills/gcaddiag/SKILL.md for one native Windows acceptance scan. Run the installed script at '{entry}' with -Action Scan -Profile Windows -Output '{case}'. Use Windows PowerShell -NoProfile. Explain execution identity and collection gaps from sanitized stdout/report only; do not read raw case.json into model context. The affected customer user is unconfirmed; never assume a sandbox executor is the customer. Do not launch CAD, install or repair anything, invoke MCP tools, change policies, or modify files outside this selected project. Finish with a short truthful result. This is a bounded skill test, not a request for additional implementation or delegation.
'@
$prompt=$prompt.Replace('{entry}',$entry).Replace('{case}',$casePath)
$logPath=(Join-Path $root 'logs').Replace('\','/');$statePath=(Join-Path $root 'state').Replace('\','/')
# Native CLI documents --ephemeral/--ignore-user-config; OpenAI configuration reference
# documents log_dir/sqlite_home. Existing auth uses the existing CODEX_HOME, never a copied token.
$reviewArguments=if($UseAutoReview){@('--approve-for-me')}else{@('--sandbox','workspace-write')}
$arguments=@('exec','--ephemeral','--ignore-user-config','--strict-config','--skip-git-repo-check')+$reviewArguments+@(
    '--json','--color','never','-C',$project,'--output-last-message',$finalPath,
    '-c',("log_dir='"+$logPath+"'"),'-c',("sqlite_home='"+$statePath+"'"),$prompt)
$run=Invoke-GdiagLifeProcess $CodexExecutable $arguments $root $TimeoutSeconds
$produced=Test-Path -LiteralPath (Join-Path $casePath 'case.json')
$executedCollector=$false
foreach($line in ([string]$run.output -split "`r?`n")){
    try{$event=$line | ConvertFrom-Json -ErrorAction Stop}catch{continue}
    if($event.item.type -eq 'command_execution' -and $event.item.exit_code -eq 0 -and $event.item.command -match 'gcaddiag\.ps1' -and $event.item.command -match '-Action\s+[''"'']?Scan'){$executedCollector=$true}
}
$caseValid=$false
if($produced){$saved=Read-GdiagJson (Join-Path $casePath 'case.json');$caseValid=($saved.formatVersion -eq 1 -and $saved.kind -eq 'local' -and @($saved.observations).Count -gt 0 -and (Test-Path -LiteralPath (Join-Path $casePath 'report.md')))}
$verified=($caseValid -and $executedCollector)
$turnCompleted=($run.status -eq 'completed' -and $run.exitCode -eq 0)
$receipt=[ordered]@{host='Codex native exec';status=$(if($verified){'collector-invocation-verified'}else{'host-verification-pending'});
    commandStatus=$run.status;exitCode=$run.exitCode;caseProduced=$produced;collectorCommandVerified=$executedCollector;
    personalSkillInstalled=$false;credentialCopied=$false;productMaintenanceRequested=$false;ephemeral=$true;automaticApprovalReview=[bool]$UseAutoReview;approvalOrSandboxBypassed=$false;modelTurnCompleted=$turnCompleted;
    stdout=$run.stdout;stderr=$run.stderr;terminationGap=$run.terminationGap;nextAction=$(if($verified){'Review the sanitized case report.'}else{'Inspect bounded local host logs for auth, policy, network or model failure; do not broaden permissions or blindly rerun.'})}
Write-GdiagLifeJson (Join-Path $root 'acceptance.json') $receipt
if($verified){'PASS real Codex collector invocation: packaged Scan/report verified; full model turn completed='+$turnCompleted+'. Artifacts: '+$root}
else{'PENDING real Codex skill invocation: '+$run.status+' exit='+$run.exitCode+'; local receipt: '+(Join-Path $root 'acceptance.json')}
