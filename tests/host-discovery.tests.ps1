param([Parameter(Mandatory=$true)][string]$CodexExecutable)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Integration.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path $PSScriptRoot ('.tmp-host-discovery-'+[guid]::NewGuid())
$homeDirectory=Join-Path $root 'isolated-home';$project=Join-Path $root 'selected-project'
$skillRoot=Join-Path $project '.agents/skills'
New-Item -ItemType Directory -Path $homeDirectory,$skillRoot -Force | Out-Null
$package=Join-Path $root 'skill.zip'
& (Join-Path $PSScriptRoot '../packaging/package.ps1') -Output $package | Out-Null
Expand-Archive -LiteralPath $package -DestinationPath $skillRoot
$process=New-Object Diagnostics.Process
$process.StartInfo.FileName=$CodexExecutable;$process.StartInfo.Arguments='app-server --stdio'
$process.StartInfo.WorkingDirectory=$project
$process.StartInfo.EnvironmentVariables['CODEX_HOME']=$homeDirectory
$process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
$process.StartInfo.RedirectStandardInput=$true;$process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
$process.StartInfo.StandardOutputEncoding=New-Object Text.UTF8Encoding($false)
$process.StartInfo.StandardErrorEncoding=New-Object Text.UTF8Encoding($false)
$reply=$null;$started=$false;$total=0;$pending='';$stage='launch';$deadline=[datetime]::UtcNow.AddSeconds(30)
try {
    $started=$process.Start();Assert $started 'Native app-server failed to start'
    $outBuffer=New-Object char[] 2048;$errBuffer=New-Object char[] 2048
    $outTask=$process.StandardOutput.ReadAsync($outBuffer,0,$outBuffer.Length)
    $errTask=$process.StandardError.ReadAsync($errBuffer,0,$errBuffer.Length)
    $outEnded=$false;$errEnded=$false
    $process.StandardInput.WriteLine('{"id":1,"method":"initialize","params":{"clientInfo":{"name":"gcaddiag-acceptance","version":"0.1"}}}')
    $process.StandardInput.Flush();$stage='initialize'
    while([datetime]::UtcNow -lt $deadline -and -not $reply) {
        if(-not $outEnded -and $outTask.IsCompleted){
            $n=$outTask.Result;$total+=$n
            if(-not $n){$outEnded=$true}else{$pending+=(-join $outBuffer[0..($n-1)]);$outTask=$process.StandardOutput.ReadAsync($outBuffer,0,$outBuffer.Length)}
        }
        if(-not $errEnded -and $errTask.IsCompleted){
            $n=$errTask.Result;$total+=$n
            if(-not $n){$errEnded=$true}else{$errTask=$process.StandardError.ReadAsync($errBuffer,0,$errBuffer.Length)}
        }
        Assert ($total -le 262144) 'Native app-server output exceeded 256 Ki character acceptance bound'
        while($pending.Contains("`n")){
            $index=$pending.IndexOf("`n");$line=$pending.Substring(0,$index);$pending=$pending.Substring($index+1)
            if(-not $line.Trim()){continue}
            $message=$line | ConvertFrom-Json
            if($message.id -eq 1){
                Assert (-not $message.error) 'Native app-server rejected initialization'
                $process.StandardInput.WriteLine('{"method":"initialized"}')
                $request=@{id=2;method='skills/list';params=@{cwds=@($project);forceReload=$true}} | ConvertTo-Json -Depth 8 -Compress
                $process.StandardInput.WriteLine($request);$process.StandardInput.Flush();$stage='skills/list'
            }elseif($message.id -eq 2){Assert (-not $message.error) 'Native skills/list failed';$reply=$message.result}
        }
        if($outEnded -and -not $reply){throw 'Native app-server closed before skills discovery'}
        Start-Sleep -Milliseconds 20
    }
    Assert ($null -ne $reply) "Native host discovery deadline reached at $stage; no model request was made"
    $skills=@($reply.data | ForEach-Object {$_.skills} | Where-Object name -eq gcaddiag)
    Assert ($skills.Count -eq 1) 'Native host did not discover exactly one gcaddiag skill'
    $discovered=$skills[0]
    Assert ($discovered.path -eq (Join-Path $skillRoot 'gcaddiag/SKILL.md')) 'Native discovery selected another skill copy'
    $receipt=@{status='native_discovery_verified';host='Codex app-server';skillName=$discovered.name;skillPath=$discovered.path;scope=$discovered.scope;
        invocation='pending';modelRequest=$false;personalConfigurationChanged=$false;casePath=$root}
    [IO.File]::WriteAllText((Join-Path $root 'acceptance.json'),($receipt | ConvertTo-Json -Depth 5))
    'PASS native Codex skills/list: packaged skill discovered in isolated project; invocation remains pending. Artifacts: '+$root
} finally {
    if($started){$process.StandardInput.Close();if(-not $process.WaitForExit(1000)){$process.Kill();[void]$process.WaitForExit(1000)}}
    $process.Dispose()
}
