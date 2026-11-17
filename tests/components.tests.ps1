$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Integration.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Windows.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Components.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path (Split-Path -Parent $PSScriptRoot) ('.tmp/components-'+[guid]::NewGuid());New-Item -ItemType Directory -Path $root -Force|Out-Null
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
[assembly:DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
public static class GdiagStorageFixture {
 [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl,CharSet=CharSet.Unicode)]static extern int sqlite3_open16(string file,out IntPtr db);
 [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)]static extern int sqlite3_exec(IntPtr db,string sql,IntPtr cb,IntPtr arg,IntPtr error);
 [DllImport("winsqlite3.dll",CallingConvention=CallingConvention.Cdecl)]static extern int sqlite3_close(IntPtr db);
 public static void Create(string file){IntPtr db;int rc=sqlite3_open16(file,out db);if(rc!=0)throw new Exception("fixture open");try{if(sqlite3_exec(db,"CREATE TABLE schema_version(version INTEGER);INSERT INTO schema_version VALUES(12);",IntPtr.Zero,IntPtr.Zero,IntPtr.Zero)!=0)throw new Exception("fixture SQL");}finally{sqlite3_close(db);}}
 public static void LongSchema(string file){IntPtr db;int rc=sqlite3_open16(file,out db);if(rc!=0)throw new Exception("fixture open");try{if(sqlite3_exec(db,"UPDATE schema_version SET version=replace(hex(zeroblob(100)),'0','X')",IntPtr.Zero,IntPtr.Zero,IntPtr.Zero)!=0)throw new Exception("fixture SQL");}finally{sqlite3_close(db);}}
}
'@
$database=Join-Path $root ('offline '+[char]0x4E2D+[char]0x6587+'.db');[GdiagStorageFixture]::Create($database)
$context=@{casePath=$root};$target=@{id='fixture-1'}
$hash=(Get-FileHash -LiteralPath $database).Hash
$options=@{storagePath=$database;storageSnapshot=$true;storageContract='GstarAssistantSession';expectedSchemaVersion=12}
$result=Invoke-GdiagComponentProbe $context $target StorageStatus $options 10
Assert ($result.status -eq 'schema_match') ('Offline schema failed: '+($result|ConvertTo-Json -Depth 8 -Compress))
Assert ($result.summary.snapshotCleanup -eq 'removed') 'Snapshot not removed'
Assert ((Get-FileHash -LiteralPath $database).Hash -eq $hash) 'Source database changed'
Assert (-not(Test-Path ($database+'-shm')) -and -not(Test-Path ($database+'-wal'))) 'Source sidecar was created'
$options.expectedSchemaVersion=13;$result=Invoke-GdiagComponentProbe $context $target StorageStatus $options 10
Assert ($result.status -eq 'schema_mismatch') 'Wrong schema called compatible'
[IO.File]::WriteAllText(($database+'-wal'),'fixture')
$result=Invoke-GdiagComponentProbe $context $target StorageStatus $options 10
Assert ($result.status -eq 'busy') 'WAL state ignored'
Remove-Item -LiteralPath ($database+'-wal')
$lock=[IO.File]::Open($database,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
try{$result=Invoke-GdiagComponentProbe $context $target StorageStatus $options 10;Assert ($result.status -eq 'busy') 'Existing writer not refused'}finally{$lock.Dispose()}
$broken=Join-Path $root 'broken.db';[IO.File]::WriteAllText($broken,'This is not a SQLite database');$options.storagePath=$broken
$result=Invoke-GdiagComponentProbe $context $target StorageStatus $options 10
Assert ($result.summary.componentStatus -eq 'corrupt') 'Invalid SQLite not diagnosed'
$long=Join-Path $root 'long-schema.db';[GdiagStorageFixture]::Create($long);[GdiagStorageFixture]::LongSchema($long);$options.storagePath=$long
$result=Invoke-GdiagComponentProbe $context $target StorageStatus $options 10
Assert ($result.status -eq 'schema_mismatch') 'Long untrusted scalar turned schema mismatch into generic startup failure'
Assert ($result.observed.stdout -notmatch 'XXXX') 'Private scalar value leaked into output'
$result=Invoke-GdiagComponentProbe $context $target WebViewCreate @{} 10
Assert ($result.status -eq 'unavailable') 'Missing WebView SDK called healthy'
'PASS component snapshots: real built-in SQLite, source bytes/sidecars preserved, selected-schema match/mismatch/corrupt/busy distinctions, bounded private scalar, WebView dependency gap. Artifacts: '+$root
