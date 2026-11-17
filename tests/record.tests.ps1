$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Evidence.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Integration.ps1')
function Assert($Condition,$Message) {if(-not $Condition){throw $Message}}
$root=Join-Path (Split-Path -Parent $PSScriptRoot) ('.tmp/record-'+[guid]::NewGuid())
$case=Join-Path $root 'case';New-Item -ItemType Directory -Path $case -Force | Out-Null
$context=Get-GdiagContext '' $case
Write-GdiagJson (Join-Path $case 'case.json') @{formatVersion=1;kind='local';caseId=$context.caseId;context=$context;targets=@();observations=@();findings=@()}
$entry=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../scripts/gcaddiag.ps1'))
$arguments=@('-NoProfile','-File',$entry,'-Action','Record','-Case',$case,'-TimeoutSeconds','60')
$quoted=($arguments | ForEach-Object {ConvertTo-GdiagWindowsArgument $_}) -join ' '
$process=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $quoted -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $root 'stdout.txt') -RedirectStandardError (Join-Path $root 'stderr.txt')
$null=$process.Handle
try {
    $deadline=[datetime]::UtcNow.AddSeconds(30);$baseline=$null
    while([datetime]::UtcNow -lt $deadline -and -not $process.HasExited) {
        try {$baseline=Read-GdiagJson (Join-Path $case 'case.json')} catch {$baseline=$null}
        if($baseline.capture -and $baseline.capture.state -eq 'recording'){break}
        Start-Sleep -Milliseconds 100
    }
    Assert ($baseline.capture.state -eq 'recording') 'Record did not persist baseline before waiting'
    Assert (@($baseline.observations | Where-Object phase -eq baseline).Count -gt 0) 'Interrupted capture has no baseline evidence'
    $process.Kill();[void]$process.WaitForExit(3000)
    $output=& (Join-Path $PSHOME 'powershell.exe') -NoProfile -File $entry -Action Report -Case $case
    Assert ($LASTEXITCODE -eq 0) "Interrupted case report failed: $output"
    $reported=$output | ConvertFrom-Json
    Assert ($reported.capture.state -match '^interrupted_') 'Report failed to distinguish missing original recording process'
    'PASS Record: persisted native baseline, owned recording interruption, verified missing process, useful report. Artifacts: '+$root
} finally {
    if(-not $process.HasExited){$process.Kill()};$process.Dispose()
}
