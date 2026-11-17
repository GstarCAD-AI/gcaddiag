param([Parameter(Mandatory=$true)][string]$InputFile)
# Owned subprocess only. SDK DbgEng.h COM ABI; no debugger commands from dump/log data.
$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
try {
$options=Get-Content -LiteralPath $InputFile -Raw -Encoding UTF8 | ConvertFrom-Json
Add-Type -TypeDefinition @'
using System;using System.IO;using System.Text;using System.Collections.Generic;using System.Runtime.InteropServices;
[assembly:DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
public static class GdiagDump {
 [DllImport("dbgeng.dll",CallingConvention=CallingConvention.StdCall)]static extern int DebugCreate(ref Guid iid,out IntPtr client);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int Query(IntPtr self,ref Guid iid,out IntPtr value);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int TextCall(IntPtr self,[MarshalAs(UnmanagedType.LPStr)]string text);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int WideDumpCall(IntPtr self,[MarshalAs(UnmanagedType.LPWStr)]string text,ulong handle);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int FlagsCall(IntPtr self,uint flags);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int WaitCall(IntPtr self,uint flags,uint timeout);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int ExecuteCall(IntPtr self,uint output,[MarshalAs(UnmanagedType.LPStr)]string text,uint flags);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int StackCall(IntPtr self,ulong frame,ulong stack,ulong ip,[Out]Frame[] frames,uint count,out uint filled);
 [UnmanagedFunctionPointer(CallingConvention.StdCall)]delegate int NameCall(IntPtr self,ulong address,StringBuilder text,uint length,out uint needed,out ulong displacement);
 [StructLayout(LayoutKind.Sequential)]public struct Frame {public ulong ip,ret,frame,stack,table;[MarshalAs(UnmanagedType.ByValArray,SizeConst=4)]public ulong[] parameters;[MarshalAs(UnmanagedType.ByValArray,SizeConst=6)]public ulong[] reserved;public int virt;public uint number;}
 public class Module {public string name;public ulong imageBase;public uint size,timestamp;}
 public class StackFrame {public int index;public string instruction,returnAddress,stackAddress,module,symbol,displacement,symbolStatus;}
 public class Result {public string status="invalid_dump",stage="header",architecture="unknown",exceptionCode,exceptionAddress,dumpTimestampUtc,accessOperation,accessAddress,stackStatus="unavailable",contextSource="none",engine="Windows system DbgEng";public uint exceptionThreadId;public int nativeErrorCode;public List<Module> modules=new List<Module>();public List<StackFrame> stackFrames=new List<StackFrame>();}
 static T Method<T>(IntPtr obj,int slot) where T:class {return Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(Marshal.ReadIntPtr(obj),slot*IntPtr.Size),typeof(T)) as T;}
 static void Check(int hr){if(hr<0)Marshal.ThrowExceptionForHR(hr);}
 static void Bound(Stream s,long pos,long size){if(pos<0||size<0||pos>s.Length||size>s.Length-pos)throw new InvalidDataException("Minidump RVA outside file");s.Position=pos;}
 static string Name(BinaryReader r,uint rva){Bound(r.BaseStream,rva,4);uint n=r.ReadUInt32();if(n>4096||(n&1)!=0)throw new InvalidDataException("Invalid minidump string");Bound(r.BaseStream,(long)rva+4,n);return Path.GetFileName(Encoding.Unicode.GetString(r.ReadBytes((int)n)));}
 public static Result Analyze(string path,string symbols,string images,int maximum){
  Result result=new Result();IntPtr client=IntPtr.Zero,control=IntPtr.Zero,sym=IntPtr.Zero;
  try{
   using(FileStream stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))using(BinaryReader r=new BinaryReader(stream)){
    Bound(stream,0,32);if(r.ReadUInt32()!=0x504d444d)throw new InvalidDataException("Not a Windows minidump");uint version=r.ReadUInt32();if((version&0xffff)!=0xa793)throw new InvalidDataException("Unsupported minidump version");uint count=r.ReadUInt32(),directory=r.ReadUInt32();if(count>256)throw new InvalidDataException("Stream count exceeds bound");Bound(stream,20,4);uint stamp=r.ReadUInt32();if(stamp!=0)result.dumpTimestampUtc=new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds(stamp).ToString("o");
    for(uint i=0;i<count;i++){
     Bound(stream,(long)directory+i*12L,12);uint type=r.ReadUInt32(),size=r.ReadUInt32(),rva=r.ReadUInt32();Bound(stream,rva,size);
     if(type==6){if(size<168)throw new InvalidDataException("Short exception stream");result.exceptionThreadId=r.ReadUInt32();r.ReadUInt32();result.exceptionCode="0x"+r.ReadUInt32().ToString("X8");Bound(stream,(long)rva+24,8);result.exceptionAddress="0x"+r.ReadUInt64().ToString("X16");uint parameters=r.ReadUInt32();if(parameters>15)throw new InvalidDataException("Invalid exception parameter count");if(result.exceptionCode=="0xC0000005"&&parameters>=2){Bound(stream,(long)rva+40,16);ulong operation=r.ReadUInt64();result.accessOperation=operation==0?"read":operation==1?"write":operation==8?"execute":"unknown";result.accessAddress="0x"+r.ReadUInt64().ToString("X16");}}
     if(type==7){if(size<2)throw new InvalidDataException("Short system info");ushort a=r.ReadUInt16();result.architecture=a==9?"x64":a==0?"x86":a==12?"arm64":"unknown";}
     if(type==4){uint n=r.ReadUInt32();if(n>2048||4+(long)n*108>size)throw new InvalidDataException("Module list exceeds bounds");for(uint j=0;j<n;j++){Bound(stream,(long)rva+4+j*108L,108);Module m=new Module();m.imageBase=r.ReadUInt64();m.size=r.ReadUInt32();r.ReadUInt32();m.timestamp=r.ReadUInt32();uint name=r.ReadUInt32();m.name=Name(r,name);result.modules.Add(m);}}
    }
   }
   result.status="no_exception_context";result.stage="exception_context";if(result.exceptionThreadId==0)return result;
   result.stage="debug_engine_create";Guid iid=new Guid("ca83c3de-5089-4cf8-93c8-d892387f2a5e");Check(DebugCreate(ref iid,out client));
   Guid cid=new Guid("5182e668-105e-416e-ad92-24ef800424ba");Check(Method<Query>(client,0)(client,ref cid,out control));Guid sid=new Guid("8c31e98c-983a-48a5-9016-6fe5d667a950");Check(Method<Query>(client,0)(client,ref sid,out sym));
   // Disallow network paths, shell commands, managed helpers, execution and telemetry.
   Check(Method<FlagsCall>(control,56)(control,0x8|0x1000|0x4000|0x10000|0x80000));
   // Exact symbols, no prompts, ignore embedded CodeView paths/environment paths; never enable srcsrv.
   Check(Method<FlagsCall>(sym,6)(sym,0x4|0x80|0x200|0x400|0x1000|0x80000|0x02000000));
   Check(Method<TextCall>(sym,41)(sym,symbols));Check(Method<TextCall>(sym,44)(sym,images));
   result.stage="open_dump";Check(Method<WideDumpCall>(client,60)(client,path,0));result.stage="wait_for_dump";Check(Method<WaitCall>(control,93)(control,0,10000));
   result.stage="exception_context";Check(Method<ExecuteCall>(control,66)(control,3,".ecxr",1|4));result.contextSource="exception_stream";
   result.stage="stack_unwind";Frame[] frames=new Frame[maximum];uint filled;Check(Method<StackCall>(control,31)(control,0,0,0,frames,(uint)maximum,out filled));
   for(int i=0;i<filled;i++){
    StackFrame f=new StackFrame();f.index=i;f.instruction="0x"+frames[i].ip.ToString("X16");f.returnAddress="0x"+frames[i].ret.ToString("X16");f.stackAddress="0x"+frames[i].stack.ToString("X16");f.symbolStatus="unresolved";f.symbol="";f.module="unknown";f.displacement="";
    foreach(Module m in result.modules)if(frames[i].ip>=m.imageBase&&frames[i].ip-m.imageBase<m.size){f.module=m.name;break;}
    StringBuilder text=new StringBuilder(1024);uint needed;ulong offset;int hr=Method<NameCall>(sym,7)(sym,frames[i].ip,text,1024,out needed,out offset);
    if(hr>=0&&needed<=1024){f.symbol=text.ToString();f.displacement="0x"+offset.ToString("X");f.symbolStatus=f.symbol.IndexOf('!')>=0?"resolved_name_not_source_line_attestation":"module_offset_only";}
    result.stackFrames.Add(f);
   }
   result.stackStatus=filled==0?"unavailable":filled>=maximum?"frame_limit_reached":"unwound_available_frames";
   if(filled>0&&result.stackFrames[0].instruction!=result.exceptionAddress){result.stackFrames.Clear();result.status="exception_context_unverified";result.stackStatus="unavailable";result.contextSource="exception_ip_mismatch";return result;}
   result.status=filled==0?"partial_stack":"stack_available";foreach(StackFrame f in result.stackFrames)if(f.symbolStatus!="resolved_name_not_source_line_attestation")result.status="partial_stack";
  }catch(Exception e){result.nativeErrorCode=e.HResult;if(result.stage=="header")result.status="invalid_dump";else result.status="analysis_failed";}
  finally{if(client!=IntPtr.Zero){try{Method<FlagsCall>(client,26)(client,0);}catch{}}if(sym!=IntPtr.Zero)Marshal.Release(sym);if(control!=IntPtr.Zero)Marshal.Release(control);if(client!=IntPtr.Zero)Marshal.Release(client);}
  return result;
 }
}
'@
$stage='dump_open';$dumpReadLock=[IO.File]::Open([string]$options.dumpPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try{
$analysis=[GdiagDump]::Analyze([string]$options.dumpPath,[string]$options.symbolPath,[string]$options.imagePath,[int]$options.maxFrames)
$file=Get-Item -LiteralPath $options.dumpPath
$hash=$null;if($file.Length -le 536870912){$hash=(Get-FileHash -LiteralPath $options.dumpPath -Algorithm SHA256).Hash}
$result=@{analysis=$analysis;dumpMetadata=@{fileName=$file.Name;length=$file.Length;lastWriteUtc=$file.LastWriteTimeUtc.ToString('o');sha256=$hash}}
$enginePath=Join-Path ([Environment]::GetFolderPath('System')) 'dbgeng.dll'
$result.debuggerMetadata=@{engine='Windows system DbgEng';version=$(if(Test-Path -LiteralPath $enginePath){[Diagnostics.FileVersionInfo]::GetVersionInfo($enginePath).FileVersion}else{$null});abiSource='Microsoft Windows SDK DbgEng.h IDebugClient4/IDebugControl/IDebugSymbols';symbolNetwork='disabled';sourceServerExecution='disabled';managedExtensions='disabled'}
[IO.File]::WriteAllText([string]$options.analysisPath,($result|ConvertTo-Json -Depth 15 -Compress),(New-Object Text.UTF8Encoding($false)))
@{status='analysis_written';stage=$analysis.stage}|ConvertTo-Json -Compress
}finally{$dumpReadLock.Dispose()}
}catch{$failure=$_.Exception;while($failure.InnerException){$failure=$failure.InnerException};$code=$failure.HResult -band 65535;$status=switch($code){2{'absent'}3{'absent'}5{'access_denied'}32{'busy'}33{'busy'}default{'unavailable'}};@{status=$status;stage=$stage;nativeErrorCode=$failure.HResult;stackFrames=@();stackStatus='unavailable'}|ConvertTo-Json -Compress;exit 2}
