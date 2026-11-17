param([Parameter(Mandatory=$true)][string]$WebViewCorePath,[Parameter(Mandatory=$true)][string]$WebViewLoaderPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Integration.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Windows.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Components.ps1')
$root=Join-Path (Split-Path -Parent $PSScriptRoot) ('.tmp/webview-native-'+[guid]::NewGuid());New-Item -ItemType Directory -Path $root -Force|Out-Null
$result=Invoke-GdiagComponentProbe @{casePath=$root} @{id='selected-webview'} WebViewCreate @{webViewCorePath=$WebViewCorePath;webViewLoaderPath=$WebViewLoaderPath} 10
Write-GdiagLifeJson (Join-Path $root 'acceptance.json') $result
if($result.status -eq 'observed' -and $result.summary.controllerCreated){'PASS native WebView environment and controller using owned profile: '+$root}
elseif($result.status -eq 'unavailable' -and $result.summary.reason){'PENDING native WebView policy boundary: '+$result.summary.reason+'; evidence='+$root}
elseif($result.summary.nativeErrorDomain -and $null -ne $result.summary.nativeErrorCode){'PENDING native WebView creation: stage='+$result.summary.stage+'; code='+$result.summary.nativeErrorCode+'; environmentCreated='+$result.summary.environmentCreated+'; evidence='+$root}
else{throw ('Component probe did not preserve a useful native stage/result: '+($result|ConvertTo-Json -Depth 8 -Compress))}
