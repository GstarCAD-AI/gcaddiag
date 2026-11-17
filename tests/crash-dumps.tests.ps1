$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/modules/Evidence.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Lifecycle.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Integration.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/Windows.ps1')
. (Join-Path $PSScriptRoot '../scripts/modules/CrashDumps.ps1')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
$root=Join-Path (Split-Path -Parent $PSScriptRoot) ('.tmp/dump-native-'+[guid]::NewGuid())
New-Item -ItemType Directory -Path $root | Out-Null
$exe=Join-Path $root 'OwnedDump.exe';$dump=Join-Path $root ('owned '+[char]0x4e2d+[char]0x6587+'.dmp')
Add-Type -TypeDefinition @'
using System;using System.Diagnostics;using System.Runtime.InteropServices;using System.IO;
public class OwnedDumpFixture {
 [DllImport("kernel32.dll")]static extern void RaiseException(uint code,uint flags,uint count,IntPtr args);
 [DllImport("kernel32.dll")]static extern uint GetCurrentThreadId();
 [DllImport("dbghelp.dll",SetLastError=true)]static extern bool MiniDumpWriteDump(IntPtr process,uint pid,IntPtr file,uint type,ref ExceptionInfo info,IntPtr stream,IntPtr callback);
 [StructLayout(LayoutKind.Sequential,Pack=4)]struct ExceptionInfo {public uint thread;public IntPtr pointers;public int client;}
 static string file;
 static bool Filter(){IntPtr pointers=Marshal.GetExceptionPointers();if(pointers==IntPtr.Zero)throw new Exception("No exception pointers");using(FileStream s=File.Create(file)){ExceptionInfo info=new ExceptionInfo{thread=GetCurrentThreadId(),pointers=pointers,client=0};if(!MiniDumpWriteDump(Process.GetCurrentProcess().Handle,(uint)Process.GetCurrentProcess().Id,s.SafeFileHandle.DangerousGetHandle(),0x40|0x1000,ref info,IntPtr.Zero,IntPtr.Zero))throw new System.ComponentModel.Win32Exception();}return true;}
 static void Inner(){RaiseException(0xe0424242,0,0,IntPtr.Zero);}
 public static int Main(string[] args){file=args[0];try{Inner();}catch(Exception){Filter();return 0;}return 1;}
}
'@ -OutputAssembly $exe -OutputType ConsoleApplication
$fixture=Invoke-GdiagOwnedProcess $exe (ConvertTo-GdiagWindowsArgument $dump) 20
Assert ($fixture.exitCode -eq 0 -and (Test-Path -LiteralPath $dump)) ('Owned handled-exception dump failed: '+$fixture.stderr)
$hash=(Get-FileHash -LiteralPath $dump).Hash
$context=@{casePath=$root};$target=@{id='owned-fixture'}
$result=Invoke-GdiagDumpAnalysis $context $target @{dumpPath=$dump;imagePath=$root;maxFrames=16} 30
Write-GdiagJson (Join-Path $root 'acceptance.json') (ConvertTo-GdiagPublic $result)
Assert ($result.summary.exceptionCode -eq '0xE0424242') 'Actual exception stream not recovered'
Assert ($result.summary.contextSource -eq 'exception_stream') ('Exception context selection failed: '+($result.summary|ConvertTo-Json -Compress))
Assert ($result.stackFrames.Count -ge 1) ('No genuine frames recovered: '+($result.summary|ConvertTo-Json -Compress))
Assert ($result.stackFrames[0].instruction -match '^0x[0-9A-F]{16}$') 'Stack frame instruction address missing'
Assert ($result.stackFrames[0].instruction -eq $result.summary.exceptionAddress) 'Returned stack did not start at the captured exception instruction'
Assert ((Get-FileHash -LiteralPath $dump).Hash -eq $hash) 'Dump analysis altered original bytes'
Assert ($result.summary.cause -eq 'unresolved') 'Fault stack inferred a root cause'
$writer=[IO.File]::Open($dump,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
try{$busy=Invoke-GdiagDumpAnalysis $context $target @{dumpPath=$dump} 15;Assert ($busy.status -eq 'busy') 'Active dump writer was not distinguished from an analyzable immutable dump'}finally{$writer.Dispose()}
$copy=Join-Path $root 'no-exception.dmp';$bytes=[IO.File]::ReadAllBytes($dump)
$directory=[BitConverter]::ToUInt32($bytes,12);$streams=[BitConverter]::ToUInt32($bytes,8)
for($i=0;$i -lt $streams;$i++){$offset=$directory+$i*12;if([BitConverter]::ToUInt32($bytes,$offset) -eq 6){[Array]::Copy([BitConverter]::GetBytes([uint32]0),0,$bytes,$offset,4)}}
[IO.File]::WriteAllBytes($copy,$bytes)
$noException=Invoke-GdiagDumpAnalysis $context $target @{dumpPath=$copy} 15
Assert ($noException.status -eq 'no_exception_context' -and $noException.stackFrames.Count -eq 0) 'Dump without exception stream was presented as a crash-thread stack'
$bad=Join-Path $root 'bad.dmp';[IO.File]::WriteAllText($bad,'invalid')
$invalid=Invoke-GdiagDumpAnalysis $context $target @{dumpPath=$bad} 15
Assert ($invalid.status -eq 'invalid_dump' -and $invalid.stackFrames.Count -eq 0) 'Invalid dump produced invented frames'
$refused=$false;try{Invoke-GdiagDumpAnalysis $context $target @{dumpPath=$dump;symbolPath='srv*https://msdl.microsoft.com/download/symbols'} 10|Out-Null}catch{$refused=$true}
Assert $refused 'Online symbol source was enabled implicitly'
'PASS native dump: owned handled exception, exception-thread unwind, bounded frames, immutable Unicode dump, invalid input and network symbol refusal. Artifacts: '+$root
