# Optional component probes; independent of target Python, COM server and WebView.
function Invoke-GdiagComponentProbe {
 param($Context,$Target,[ValidateSet('WebViewCreate','StorageStatus')][string]$Probe,[hashtable]$Options=@{},[int]$TimeoutSeconds=10)
 $result=[ordered]@{source=('component.'+$Probe);targetId=$Target.id;status='unavailable';summary=@{scope='selected_component_only';hostRecovery='unverified'};observed=$null}
 $ownedRoot=$null;$inputStream=$null
 try{
  if($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 60){throw 'Component timeout must be 1..60 seconds.'}
  if($Probe -eq 'StorageStatus'){
   if(-not $Options.storagePath){$result.summary.nextAction='Select the exact database path; no database is inferred from folder names.';return [pscustomobject]$result}
   $path=[IO.Path]::GetFullPath($Options.storagePath)
   if($Options.storageSnapshot -ne $true){$result.summary.nextAction='Explicit storageSnapshot=true permits a temporary local offline snapshot; original database/WAL are never opened by SQLite.';return [pscustomobject]$result}
   $ownedRoot=Join-Path (Assert-GdiagPlainPath $Context.casePath) ('component-'+[guid]::NewGuid())
   New-Item -ItemType Directory -Path $ownedRoot | Out-Null
   $snapshot=Join-Path $ownedRoot 'snapshot.db'
   $schema=-1
   if($Options.ContainsKey('expectedSchemaVersion')){$schema=[int]$Options.expectedSchemaVersion;if($schema -lt 0 -or $Options.storageContract -ne 'GstarAssistantSession'){throw 'Expected schema needs a nonnegative version and explicitly matched storageContract=GstarAssistantSession; no product schema is inferred.'}}
   $result.summary.ownership='explicit_user_selected_file; product_ownership_and_effective_state_root_unverified'
   $result.summary.compatibility='offline_selected_schema_expectation_only; installed_product_compatibility_unverified'
   $args=@('-NoProfile','-NonInteractive','-STA','-File',(Join-Path $PSScriptRoot 'ComponentChild.ps1'),'-Mode',$Probe,'-SourcePath',$path,'-SnapshotPath',$snapshot,'-ExpectedSchemaVersion',[string]$schema)
  }else{
   if(-not $Options.webViewCorePath -or -not $Options.webViewLoaderPath){$result.summary.nextAction='Supply matching trusted Microsoft.Web.WebView2.Core.dll and WebView2Loader.dll from the selected product/SDK; registry presence cannot prove creation.';return [pscustomobject]$result}
   $core=Assert-GdiagPlainPath $Options.webViewCorePath;$loader=Assert-GdiagPlainPath $Options.webViewLoaderPath
   foreach($file in @($core,$loader)){if(-not(Test-Path -LiteralPath $file -PathType Leaf)){throw 'Selected WebView SDK resource is missing.'}}
   $ownedRoot=Join-Path (Assert-GdiagPlainPath $Context.casePath) ('component-'+[guid]::NewGuid());New-Item -ItemType Directory -Path $ownedRoot|Out-Null
   $args=@('-NoProfile','-NonInteractive','-STA','-File',(Join-Path $PSScriptRoot 'ComponentChild.ps1'),'-Mode',$Probe,'-CorePath',$core,'-LoaderPath',$loader,'-ProfilePath',(Join-Path $ownedRoot 'profile'),'-TimeoutSeconds',[string]$TimeoutSeconds)
   if($Options.webViewRuntimePath){$args+=@('-RuntimePath',(Assert-GdiagPlainPath $Options.webViewRuntimePath))}
  }
  $commandLine=($args|ForEach-Object {ConvertTo-GdiagWindowsArgument ([string]$_)}) -join ' '
  $shell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell/v1.0/powershell.exe'
  $result.summary.executor='owned_WindowsPowerShell_5.1_child'
  $probeResult=Invoke-GdiagOwnedProcess $shell $commandLine ($TimeoutSeconds+2)
  $result.observed=$probeResult;$result.status=$probeResult.status
  $records=@();foreach($line in ($probeResult.stdout -split "`r?`n")){if($line.Trim()){try{$records+=($line|ConvertFrom-Json)}catch{}}}
  if($records.Count){$last=$records[-1];$result.summary.stage=$last.stage;$result.summary.componentStatus=$last.status;$result.summary.nativeErrorDomain=$last.nativeErrorDomain;$result.summary.nativeErrorCode=$last.nativeErrorCode;if($last.reason){$result.summary.reason=$last.reason};if($last.nextAction){$result.summary.nextAction=$last.nextAction};if($Probe -eq 'WebViewCreate'){$result.summary.environmentCreated=$last.environmentCreated;$result.summary.controllerCreated=$last.controllerCreated};if($Probe -eq 'StorageStatus'){$result.summary.schemaMatched=$last.schemaMatched;$result.summary.liveHostHealth='unverified'};if($probeResult.status -notin @('timeout','truncated') -and $last.status){$result.status=$last.status}}
  if($Probe -eq 'WebViewCreate'){
   # The external browser process tree is not job-contained; never delete a possibly live profile.
   $result.summary.profileCleanup='retained_until_owned_browser_exit_verified';$result.summary.profilePath=$ownedRoot
  }else{
   $resolved=[IO.Path]::GetFullPath($ownedRoot);$caseRoot=[IO.Path]::GetFullPath($Context.casePath).TrimEnd('\')+'\'
   if($probeResult.termination -eq 'owned_process_exited_descendants_not_verified' -and $resolved.StartsWith($caseRoot,[StringComparison]::OrdinalIgnoreCase)){
    $resolved=Assert-GdiagPlainPath $resolved
    $files=@(Get-ChildItem -LiteralPath $resolved -Force)
    $unknown=@($files|Where-Object {$_.PSIsContainer -or $_.Name -notin @('snapshot.db','snapshot.db-wal','snapshot.db-shm','snapshot.db-journal') -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)})
    if($unknown.Count){$result.summary.snapshotCleanup='retained_unknown_or_reparse_content';$result.summary.retainedLocalEvidence=$ownedRoot}
    else{foreach($file in $files){Remove-Item -LiteralPath $file.FullName -Force};Remove-Item -LiteralPath $resolved -Force;$ownedRoot=$null;$result.summary.snapshotCleanup='removed'}
   }else{$result.summary.snapshotCleanup='retained_due_to_process_uncertainty'}
  }
 }catch{
  $failure=$_.Exception;while($failure.InnerException){$failure=$failure.InnerException}
  $code=$failure.HResult -band 65535
  $result.status=if($code -in @(32,33)){'busy'}elseif($code -eq 5){'access_denied'}else{'collection_error'}
  $result.summary.nativeErrorDomain='HRESULT';$result.summary.nativeErrorCode=$failure.HResult
  if($ownedRoot){$result.summary.retainedLocalEvidence=$ownedRoot;$result.summary.cleanup='inspect_owned_child_state_before_removing_sensitive_snapshot'}
 }finally{if($inputStream){$inputStream.Dispose()}}
 [pscustomobject]$result
}
