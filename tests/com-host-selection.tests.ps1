$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Windows.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path $PSScriptRoot ('.tmp-com-selection-'+[guid]::NewGuid())
New-Item -ItemType Directory -Path $root|Out-Null
$executable=Join-Path $root 'GdiagComSelectionFixture.exe'
$typeName='GdiagComSelectionFixture'+[guid]::NewGuid().ToString('N')
Add-Type -TypeDefinition ('using System; using System.Threading; public static class '+$typeName+' {public static void Main(){Thread.Sleep(60000);}}') -OutputAssembly $executable -OutputType ConsoleApplication
$context=@{sessionId=(Get-Process -Id $PID).SessionId}
$target=[pscustomobject]@{id='host-fixture';family='GstarCAD';path=$executable;file=@{path=$executable};progId='Gdiag.Fixture.Application'}
$owned=@()
try{
    $none=Get-GdiagComHostSelection $executable $context
    Assert ($none.status -eq 'host_verification_pending') 'Absent host did not remain pending'
    $one=New-Object Diagnostics.Process
    $one.StartInfo.FileName=$executable;$one.StartInfo.UseShellExecute=$false;$one.StartInfo.CreateNoWindow=$true
    Assert ($one.Start()) 'Could not start owned fixture';$owned+=@($one)
    $single=Get-GdiagComHostSelection $executable $context
    Assert ($single.status -eq 'singleton_verified' -and $single.selected.pid -eq $one.Id) 'Unique exact-image/current-session host not identified'
    $copied=@{};foreach($property in $single.selected.PSObject.Properties){$copied[$property.Name]=$property.Value}
    Assert ((Test-GdiagComHostIdentity $single.selected $copied).matches) 'Native process identity failed its own comparison'
    $copied.creationUtc=[datetime]::UtcNow.AddDays(-1).ToString('o')
    $reused=Test-GdiagComHostIdentity $single.selected $copied
    Assert (-not $reused.matches -and $reused.reasons -contains 'process_start_changed') 'Reused PID accepted as original host'
    $stale=Get-GdiagComHostSelection $executable @{sessionId=($context.sessionId+1)}
    Assert ($stale.status -eq 'host_selection_unresolved' -and $stale.reason -match 'session_changed') 'Saved executor session mismatch accepted'
    # An actual owned child reaches only a missing fixture ROT ProgID, never a CAD instance.
    $failedAttach=@(Invoke-GdiagProbe $context $target 'Attach' 15 | Where-Object source -eq 'com_attach')
    Assert ($failedAttach.Count -eq 1 -and $failedAttach[0].status -eq 'host_selection_unresolved') 'Missing fixture COM object was mistaken for a successful attach'
    Assert ($failedAttach[0].summary.stage -eq 'get_active_object' -and $null -ne $failedAttach[0].summary.nativeErrorCode) 'COM stage/native HRESULT lost'
    Assert ($failedAttach[0].summary.nativeErrorCode -ne -2146233087) 'PowerShell wrapper HRESULT replaced the native COM error'
    $failedAttach[0].summary|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root 'native-attach-error.json') -Encoding UTF8
    $two=New-Object Diagnostics.Process
    $two.StartInfo.FileName=$executable;$two.StartInfo.UseShellExecute=$false;$two.StartInfo.CreateNoWindow=$true
    Assert ($two.Start()) 'Could not start second owned fixture';$owned+=@($two)
    $multiple=Get-GdiagComHostSelection $executable $context
    Assert ($multiple.status -eq 'host_selection_unresolved' -and $multiple.candidates.Count -eq 2) 'Two same-image instances were silently selected'
    $original=${function:Invoke-GdiagOwnedProcess}
    try{
        function Invoke-GdiagOwnedProcess {throw 'Active COM child must not be launched for ambiguous hosts.'}
        $ambiguous=@(Invoke-GdiagProbe $context $target 'Attach' 15 | Where-Object source -eq 'com_attach')
        Assert ($ambiguous[0].status -eq 'host_selection_unresolved' -and $ambiguous[0].summary.candidateCount -eq 2) 'Ambiguous attach did not stop before active COM call'
    }finally{Set-Item -Path Function:Invoke-GdiagOwnedProcess -Value $original}
    'PASS COM selection: native absent/unique/two owned instances, stale session/reused PID refusal, bounded child HRESULT, no CAD registration/document/create/Quit. Artifacts: '+$root
}finally{
    foreach($process in $owned){if(-not $process.HasExited){$process.Kill();[void]$process.WaitForExit(1000)};$process.Dispose()}
}
