param([Parameter(Mandatory=$true)][ValidateSet('StorageStatus','WebViewCreate')][string]$Mode,[string]$SourcePath,[string]$SnapshotPath,[int]$ExpectedSchemaVersion=-1,[string]$CorePath,[string]$LoaderPath,[string]$RuntimePath,[string]$ProfilePath,[int]$TimeoutSeconds=10)
# Executed only in an owned bounded subprocess. No target database is opened here.
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$stage='bootstrap';$environmentCreated=$false
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
try {
if($Mode -eq 'StorageStatus'){
 $stage='offline_snapshot'
 $cursor=[IO.Path]::GetFullPath($SourcePath)
 while($cursor){if(Test-Path -LiteralPath $cursor){if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Source reparse path refused'}};$parent=Split-Path -Parent $cursor;if($parent -eq $cursor){break};$cursor=$parent}
 if([IO.Path]::GetFullPath($SourcePath) -eq [IO.Path]::GetFullPath($SnapshotPath)){throw 'Snapshot must be separate from source'}
 $source=[IO.File]::Open($SourcePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  foreach($suffix in @('-wal','-shm','-journal')){if(Test-Path -LiteralPath ($SourcePath+$suffix)){@{status='busy';stage=$stage;reason='journal_or_wal_present';scope='original_not_opened_by_sqlite'}|ConvertTo-Json -Compress;exit 24}}
  if($source.Length -gt 268435456){@{status='truncated';stage=$stage;reason='snapshot_256MiB_limit'}|ConvertTo-Json -Compress;exit 24}
  $destination=[IO.File]::Create($SnapshotPath);try{$source.CopyTo($destination)}finally{$destination.Dispose()}
  foreach($suffix in @('-wal','-shm','-journal')){if(Test-Path -LiteralPath ($SourcePath+$suffix)){throw 'Journal appeared during offline snapshot'}}
 }finally{$source.Dispose()}
 $stage='system_sqlite_load'
 Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
[assembly:DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
public static class GdiagSqlite {
 [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] public static extern int sqlite3_open_v2(byte[] file,out IntPtr db,int flags,IntPtr vfs);
 [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] public static extern int sqlite3_close(IntPtr db);
 [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] public static extern int sqlite3_prepare_v2(IntPtr db,byte[] sql,int bytes,out IntPtr stmt,IntPtr tail);
 [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] public static extern int sqlite3_step(IntPtr stmt);
 [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] public static extern IntPtr sqlite3_column_text(IntPtr stmt,int col);
 [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] public static extern int sqlite3_column_bytes(IntPtr stmt,int col);
 [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)] public static extern int sqlite3_finalize(IntPtr stmt);
 public static string Scalar(IntPtr db,string sql,out int rc) {
   IntPtr stmt; rc=sqlite3_prepare_v2(db,Encoding.UTF8.GetBytes(sql+"\0"),-1,out stmt,IntPtr.Zero);
   if(rc!=0)return null;
   try {rc=sqlite3_step(stmt); if(rc!=100)return null; int n=Math.Min(sqlite3_column_bytes(stmt,0),64);byte[] bytes=new byte[n];Marshal.Copy(sqlite3_column_text(stmt,0),bytes,0,n);return Encoding.UTF8.GetString(bytes);}
   finally {sqlite3_finalize(stmt);}
 }
}
'@
 $db=[IntPtr]::Zero
 try{
  $stage='snapshot_sqlite_open';$rc=[GdiagSqlite]::sqlite3_open_v2([Text.Encoding]::UTF8.GetBytes($SnapshotPath+[char]0),[ref]$db,1,[IntPtr]::Zero)
  if($rc -ne 0){@{status='io_error';stage=$stage;nativeErrorDomain='SQLite';nativeErrorCode=$rc}|ConvertTo-Json -Compress;exit 21}
  $stage='snapshot_quick_check';$rc=0;$check=[GdiagSqlite]::Scalar($db,'PRAGMA quick_check(1)',[ref]$rc)
  if($rc -ne 100 -or $check -ne 'ok'){
   $status=switch($rc -band 255){5{'busy'} 6{'busy'} 11{'corrupt'} 26{'corrupt'} 3{'access_denied'} 23{'access_denied'} default{if($check -and $check -ne 'ok'){'corrupt'}else{'io_error'}}}
   @{status=$status;stage=$stage;nativeErrorDomain='SQLite';nativeErrorCode=$rc;scope='offline_snapshot_only'}|ConvertTo-Json -Compress;exit 22
  }
  $stage='snapshot_schema';$schema=$null;if($ExpectedSchemaVersion -ge 0){$schema=[GdiagSqlite]::Scalar($db,'SELECT version FROM schema_version LIMIT 1',[ref]$rc)}
  $status=if($ExpectedSchemaVersion -lt 0){'generic_integrity_only'}elseif($rc -eq 100 -and $schema -eq [string]$ExpectedSchemaVersion){'schema_match'}elseif($rc -in @(1,100,101)){'schema_mismatch'}else{'io_error'}
  @{status=$status;stage=$stage;nativeErrorDomain='SQLite';nativeErrorCode=$rc;scope='offline_snapshot_only';schemaMatched=($status -eq 'schema_match');compatibility='caller_selected_expectation_not_installed_product_attestation';liveHostHealth='unverified';contentCollected=$false}|ConvertTo-Json -Compress
 }finally{if($db -ne [IntPtr]::Zero){[void][GdiagSqlite]::sqlite3_close($db)}}
}else{
 $stage='webview_assembly_load'
 # Microsoft managed SDK wraps the official COM callbacks; no homegrown COM vtable.
 # https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2environment.createcorewebview2controllerasync
 Add-Type -AssemblyName System.Windows.Forms
 Add-Type -TypeDefinition 'using System;using System.Text;using System.Runtime.InteropServices;public static class GdiagWebLoader{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern IntPtr LoadLibraryEx(string path,IntPtr file,uint flags);[DllImport("kernel32.dll",CharSet=CharSet.Unicode)]public static extern int GetCurrentApplicationUserModelId(ref uint count,StringBuilder value);[DllImport("shell32.dll")]public static extern int GetCurrentProcessExplicitAppUserModelID(out IntPtr value);}'
 $stage='webview_profile_policy_preflight'
 # SDK profile overrides: AppUserModelID, process code name, then wildcard.
 # https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/webview2-idl
 $policyNames=@('*',[IO.Path]::GetFileName([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName))
 [uint32]$length=0;$appResult=[GdiagWebLoader]::GetCurrentApplicationUserModelId([ref]$length,$null)
 if($appResult -eq 122){$name=New-Object Text.StringBuilder([int]$length);$appResult=[GdiagWebLoader]::GetCurrentApplicationUserModelId([ref]$length,$name);if($appResult -ne 0){throw 'Cannot establish policy AppUserModelID'};$policyNames+=$name.ToString()}
 elseif($appResult -ne 15703){throw 'Cannot establish current application identity for WebView policy'}
 $explicit=[IntPtr]::Zero
 if([GdiagWebLoader]::GetCurrentProcessExplicitAppUserModelID([ref]$explicit) -eq 0){try{$policyNames+=[Runtime.InteropServices.Marshal]::PtrToStringUni($explicit)}finally{[Runtime.InteropServices.Marshal]::FreeCoTaskMem($explicit)}}
 foreach($hive in @('CurrentUser','LocalMachine')){foreach($view in @('Registry64','Registry32')){
  $base=$null;$key=$null
  try{
   $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$hive,[Microsoft.Win32.RegistryView]::$view)
   $key=$base.OpenSubKey('Software\Policies\Microsoft\Edge\WebView2\UserDataFolder')
   if($key){foreach($name in $key.GetValueNames()){if($name -in $policyNames){@{status='unavailable';stage=$stage;reason='applicable_profile_policy_override';hive=$hive;view=$view;environmentCreated=$false;nextAction='Use an approved independent test application without an affected profile override; policy is preserved.'}|ConvertTo-Json -Compress;exit 25}}}
  }finally{if($key){$key.Dispose()};if($base){$base.Dispose()}}
 }}
 $native=[GdiagWebLoader]::LoadLibraryEx($LoaderPath,[IntPtr]::Zero,0x1100)
 if($native -eq [IntPtr]::Zero){@{status='probe_failed';stage='WebView2Loader_load';nativeErrorDomain='Win32';nativeErrorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error()}|ConvertTo-Json -Compress;exit 23}
 [void][Reflection.Assembly]::LoadFrom($CorePath)
 $window=New-Object Windows.Forms.Form;$handle=$window.Handle
 $controller=$null;$environment=$null
 try{
  # Inherited debug/runtime/profile overrides must not redirect the owned profile.
  foreach($name in @('WEBVIEW2_USER_DATA_FOLDER','WEBVIEW2_BROWSER_EXECUTABLE_FOLDER','WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS','WEBVIEW2_RELEASE_CHANNEL_PREFERENCE','WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER')){[Environment]::SetEnvironmentVariable($name,$null,'Process')}
  $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  $stage='webview_environment_create'
  $task=[Microsoft.Web.WebView2.Core.CoreWebView2Environment]::CreateAsync($RuntimePath,$ProfilePath,$null)
  while(-not $task.IsCompleted -and [DateTime]::UtcNow -lt $deadline){[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 10}
  if(-not $task.IsCompleted){throw (New-Object TimeoutException('WebView environment deadline'))}
  $environment=$task.GetAwaiter().GetResult();$environmentCreated=$true;$stage='webview_environment_profile_scope'
  if(-not $environment.PSObject.Properties['UserDataFolder'] -or [IO.Path]::GetFullPath($environment.UserDataFolder).TrimEnd('\') -ne [IO.Path]::GetFullPath($ProfilePath).TrimEnd('\')){throw 'Effective WebView profile differs from owned temporary profile or cannot be verified'}
  $stage='webview_controller_create'
  $task=$environment.CreateCoreWebView2ControllerAsync($handle)
  while(-not $task.IsCompleted -and [DateTime]::UtcNow -lt $deadline){[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 10}
  if(-not $task.IsCompleted){throw (New-Object TimeoutException('WebView controller deadline'))}
  $controller=$task.GetAwaiter().GetResult();$controller.IsVisible=$false
  @{status='observed';stage=$stage;environmentCreated=$true;controllerCreated=$true;browserVersion=$environment.BrowserVersionString;scope='owned_temporary_profile';hostRecovery='unverified'}|ConvertTo-Json -Compress
 }finally{if($controller){$controller.Close()};$controller=$null;$environment=$null;$window.Dispose();[GC]::Collect();[GC]::WaitForPendingFinalizers()}
}
}catch{$failure=$_.Exception;while($failure.InnerException){$failure=$failure.InnerException};$code=$failure.HResult -band 65535;$status=if($failure -is [TimeoutException]){'timeout'}elseif($code -in @(32,33)){'busy'}elseif($code -eq 5){'access_denied'}elseif($code -in @(2,3)){'absent'}else{'probe_failed'};@{status=$status;stage=$stage;nativeErrorDomain='HRESULT';nativeErrorCode=$failure.HResult;message=$failure.Message;environmentCreated=$environmentCreated}|ConvertTo-Json -Compress;exit 20}
