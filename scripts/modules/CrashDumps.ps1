function Invoke-GdiagDumpAnalysis {
 param($Context,$Target,[hashtable]$Options=@{},[int]$TimeoutSeconds=20)
 $observation=[ordered]@{source='crash.dump_analysis';status='unavailable';targetId=$Target.id;summary=@{stackStatus='unavailable';cause='unresolved';association='unverified';symbols='offline_explicit_only'};stackFrames=@();dumpMetadata=$null;observed=$null}
 if(-not $Options.dumpPath){$observation.summary.nextAction='Select an existing local minidump explicitly; no dump is captured or uploaded by default.';return [pscustomobject]$observation}
 if($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 60){throw 'Dump analysis timeout must be 1..60 seconds.'}
 $paths=@{}
 foreach($key in @('symbolPath','imagePath')){
  $parts=@();foreach($part in @(([string]$Options[$key]) -split ';' | Where-Object {$_})){
   if(-not [IO.Path]::IsPathRooted($part) -or $part.StartsWith('\\') -or $part -match '[*\r\n]'){throw 'Use explicit local symbol/image directories only; symbol servers and source scripts are not enabled.'}
   $parts+=Assert-GdiagPlainPath $part
  };$paths[$key]=$parts -join ';'
 }
 $maximum=32;if($Options.ContainsKey('maxFrames')){$maximum=[int]$Options.maxFrames};if($maximum -lt 1 -or $maximum -gt 64){throw 'Select 1..64 stack frames.'}
 if(-not [IO.Path]::IsPathRooted($Options.dumpPath)){throw 'Select an absolute local analyst dump path; customer paths are never replayed.'}
 $path=[IO.Path]::GetFullPath($Options.dumpPath)
 $request=Join-Path (Assert-GdiagPlainPath $Context.casePath) ('dump-request-'+[guid]::NewGuid()+'.json')
 $analysisPath=$request+'.analysis.json'
 Write-GdiagJson $request @{dumpPath=$path;symbolPath=$paths.symbolPath;imagePath=$paths.imagePath;maxFrames=$maximum;analysisPath=$analysisPath}
 try{
  $arguments=@('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'DumpChild.ps1'),'-InputFile',$request)
  $command=($arguments | ForEach-Object {ConvertTo-GdiagWindowsArgument ([string]$_)}) -join ' '
  $probe=Invoke-GdiagOwnedProcess (Get-GdiagWindowsPowerShellPath) $command $TimeoutSeconds
  $observation.observed=@{probe=$probe;selectedDumpPath=$path;analysisPath=$analysisPath};$observation.status=$probe.status
  $observation.summary.nextAction='No reliable callstack was produced; inspect the local debugger stage/error and provide matching release images/PDBs if needed.'
  if($probe.status -eq 'probe_failed'){
   try{$failure=$probe.stdout|ConvertFrom-Json -ErrorAction Stop;if($failure.status){$observation.status=$failure.status;$observation.summary.stage=$failure.stage;$observation.summary.nativeErrorCode=$failure.nativeErrorCode}}catch{}
  }
  if($probe.status -eq 'observed'){
   try{
    if((Get-Item -LiteralPath (Assert-GdiagPlainPath $analysisPath)).Length -gt 2097152){throw 'Dump analysis output exceeded 2 MiB'}
    $saved=Read-GdiagJson $analysisPath;$analysis=$saved.analysis
    $observation.dumpMetadata=@{fileName=$(if($saved.dumpMetadata.sha256){'dump-'+$saved.dumpMetadata.sha256.Substring(0,12)+'.dmp'}else{'selected-dump.dmp'});length=$saved.dumpMetadata.length;sha256=$saved.dumpMetadata.sha256;lastWriteUtc=$saved.dumpMetadata.lastWriteUtc}
   }catch{$observation.status='collection_error';$observation.summary.stage='decode_analysis';return [pscustomobject]$observation}
   $observation.status=$analysis.status;$observation.observed=@{probe=$probe;analysis=$analysis;selectedDumpPath=$path;analysisPath=$analysisPath;debuggerMetadata=$saved.debuggerMetadata}
   foreach($key in @('stage','exceptionThreadId','exceptionCode','exceptionAddress','dumpTimestampUtc','accessOperation','accessAddress','architecture','stackStatus','contextSource','nativeErrorCode')){$observation.summary[$key]=$analysis.$key}
   $observation.stackFrames=@($analysis.stackFrames | Where-Object {$_});$observation.summary.frameCount=$observation.stackFrames.Count
   $observation.summary.debugger='Windows system DbgEng';$observation.summary.symbolLimit='Resolved names may be exports or PDB symbols; source-line/private-symbol completeness is not attested.'
   $observation.summary.debuggerVersion=$saved.debuggerMetadata.version
   $observation.summary.nativeErrorDomain='HRESULT'
   $observation.summary.confidence='captured_exception_context_debug_engine_unwind; root_cause_unresolved'
   $observation.summary.unwindLimit='Missing dump memory, exact release images, private PDBs or managed symbols can leave the stack partial; argument and memory values are excluded.'
   $usedModules=@($observation.stackFrames | ForEach-Object {$_.module} | Select-Object -Unique)
   $observation.summary.moduleIdentities=@($analysis.modules | Where-Object {$_.name -in $usedModules} | Select-Object name,imageBase,size,timestamp)
   if($Target.file.path){$expected=[IO.Path]::GetFileName($Target.file.path);if(@($analysis.modules|Where-Object name -eq $expected).Count){$observation.summary.association='module_name_match_only_path_release_unverified'}}
   $observation.summary.nextAction=if($analysis.status -eq 'no_exception_context'){'This dump lacks a captured exception stream. Obtain a crash-time dump for the exception-thread callstack; a hang snapshot requires separately scoped thread analysis.'}elseif($observation.stackFrames.Count){'Correlate the exception stack with incident logs and exact matching release images/PDBs. A faulting frame alone is not root cause.'}else{'Inspect dump completeness/debugger errors and supply matching local release images/PDBs where needed; no callstack is fabricated.'}
  }
 }finally{Remove-Item -LiteralPath (Assert-GdiagPlainPath $request) -Force}
 [pscustomobject]$observation
}
