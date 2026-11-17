$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Windows.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
# A directory opened as a Windows file produces a real PowerShell method wrapper
# around UnauthorizedAccessException without changing ACLs or product state.
$failure=$null;$stream=$null
try{$stream=[IO.File]::Open($PSScriptRoot,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}catch{$failure=$_}finally{if($stream){$stream.Dispose()}}
Assert ($failure -and $failure.Exception -is [Management.Automation.MethodInvocationException]) 'Native fixture did not exercise a PowerShell method wrapper'
$native=Get-GdiagNativeError $failure
Assert ((Get-GdiagErrorStatus $failure) -eq 'access_denied' -and $native.domain -eq 'HRESULT' -and $native.code -eq -2147024891) 'Wrapped native access error lost classification or E_ACCESSDENIED'
$identity=Get-GdiagFileIdentity $PSScriptRoot
Assert ($identity.status -eq 'access_denied' -and $identity.error.code -eq -2147024891) 'File collector retained the generic PowerShell wrapper error'
$observation=New-GdiagNativeObservation 'fixture' (Get-GdiagErrorStatus $failure) @{} $failure $null
Assert ($observation.summary.nativeErrorDomain -eq 'HRESULT' -and $observation.summary.nativeErrorCode -eq -2147024891) 'Public observation lost the native access error'
# Reflection/property wrappers can be nested, and Win32 errors have their own
# error domain rather than the generic Win32Exception HRESULT.
$nested=[Reflection.TargetInvocationException]::new([Management.Automation.MethodInvocationException]::new('wrapper',[ComponentModel.Win32Exception]::new(5)))
$native=Get-GdiagNativeError $nested
Assert ((Get-GdiagErrorStatus $nested) -eq 'access_denied' -and $native.domain -eq 'Win32' -and $native.code -eq 5) 'Nested Win32 access error was flattened'
$other=[Management.Automation.MethodInvocationException]::new('wrapper',[IO.IOException]::new('fixture'))
Assert ((Get-GdiagErrorStatus $other) -eq 'collection_error') 'Unrelated I/O error was misclassified as access denied'
'PASS native errors: real PowerShell method wrapper, access classification, original HRESULT/Win32 domain, nested wrappers, collector summary; no product mutation.'
