param([Parameter(Mandatory=$true)][string]$DllPath,[switch]$PythonInitialize)
# Runs only in an owned bounded child. Never dot-source into the collector.
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$ProgressPreference='SilentlyContinue'
$stage='compile_native_probe'
try {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class GdiagDll {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetProcAddress(IntPtr module, string name);
 [DllImport("kernel32.dll")] public static extern bool FreeLibrary(IntPtr module);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate void HomeFn(IntPtr home);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate void InitFn(int signals);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int RunFn([MarshalAs(UnmanagedType.LPStr)] string code);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int FinalizeFn();
 public static Delegate Function(IntPtr dll, string name, Type type) {
   IntPtr fn=GetProcAddress(dll,name); if(fn==IntPtr.Zero) throw new EntryPointNotFoundException(name);
   return Marshal.GetDelegateForFunctionPointer(fn,type);
 }
}
"@
$stage='LoadLibraryEx'
$dll=[GdiagDll]::LoadLibraryEx($DllPath,[IntPtr]::Zero,0x1100)
if($dll -eq [IntPtr]::Zero){@{stage=$stage;nativeErrorDomain='Win32';nativeErrorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error()} | ConvertTo-Json -Compress;exit 21}
@{stage=$stage;loaded=$true;hostBinding='not_tested'} | ConvertTo-Json -Compress
if($PythonInitialize){
 $stage='python_isolated_flags'
 foreach($flag in @('Py_IsolatedFlag','Py_NoSiteFlag','Py_IgnoreEnvironmentFlag','Py_DontWriteBytecodeFlag')){
   $address=[GdiagDll]::GetProcAddress($dll,$flag)
   if($address -eq [IntPtr]::Zero){throw "Missing Python export $flag"}
   [Runtime.InteropServices.Marshal]::WriteInt32($address,1)
 }
 $pythonHomePointer=[Runtime.InteropServices.Marshal]::StringToHGlobalUni([IO.Path]::GetDirectoryName($DllPath))
 $setHome=[GdiagDll]::Function($dll,'Py_SetPythonHome',[GdiagDll+HomeFn]);$setHome.Invoke($pythonHomePointer)
 $stage='Py_InitializeEx'; @{stage=$stage} | ConvertTo-Json -Compress
 $initialize=[GdiagDll]::Function($dll,'Py_InitializeEx',[GdiagDll+InitFn]);$initialize.Invoke(0)
 $stage='python_stdlib_import'
 $run=[GdiagDll]::Function($dll,'PyRun_SimpleString',[GdiagDll+RunFn])
 $rc=$run.Invoke("import sys,json,sqlite3,ssl; print(json.dumps(dict(stage='python_stdlib_import',version=sys.version,stdlib=True,hostBinding='not_tested')),flush=True)")
 $stage='Py_FinalizeEx';$finalize=[GdiagDll]::Function($dll,'Py_FinalizeEx',[GdiagDll+FinalizeFn]);$final=$finalize.Invoke()
 [Runtime.InteropServices.Marshal]::FreeHGlobal($pythonHomePointer)
 if($rc -ne 0 -or $final -ne 0){@{stage=$stage;pythonResult=$rc;finalizeResult=$final} | ConvertTo-Json -Compress;exit 22}
}else{[void][GdiagDll]::FreeLibrary($dll)}
}catch{@{stage=$stage;nativeErrorDomain='HRESULT';nativeErrorCode=$_.Exception.HResult;message=$_.Exception.Message} | ConvertTo-Json -Compress;exit 20}
