# Read-only prerequisite/distribution metadata. Dot-source Windows.ps1 first.
function New-GdiagPrerequisiteObservation($Source,$Status,$Summary,$Observed,$TargetId) {
    [pscustomobject]@{source=$Source;status=$Status;summary=$Summary;observed=$Observed;targetId=$TargetId;timeUtc=[datetime]::UtcNow.ToString('o')}
}
function Get-GdiagPrerequisiteEvidence {
    param([hashtable]$Context,$Targets)
    $catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../catalog/products.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $policy=$catalog.prerequisites.visualCppX64
    foreach($gap in @($Context.additionalInventoryGaps | Where-Object {$_})){$gap}
    foreach($view in @('Registry64','Registry32')) {
        $record=Get-GdiagRegistryRecord 'LocalMachine' $view (([string]$policy.registrySubkey).Replace('/','\')) $null
        $installed=Get-GdiagRegValue $record @($policy.installedValue)
        $build=Get-GdiagRegValue $record @($policy.buildValue)
        $version=Get-GdiagRegValue $record @('Version')
        $safeVersion='invalid_or_absent';$parsedVersion=$null
        if($version -and [Version]::TryParse(([string]$version).TrimStart('v','V'),[ref]$parsedVersion)){$safeVersion=$parsedVersion.ToString()}
        $baseline='unresolved';$buildNumber=0
        if($record.status -eq 'observed') {
            $typed=@($record.values | Where-Object {$_.name -in @($policy.installedValue,$policy.buildValue) -and $_.type -ne 'DWord'})
            if($typed.Count){$baseline='invalid_registration_type'}
            elseif($installed -ne 1){$baseline='not_registered_installed'}
            elseif([int]::TryParse([string]$build,[ref]$buildNumber)) {
                $baseline=if($buildNumber -ge [int]$policy.reviewedDefaultMinimumBuild){'meets_reviewed_generator_default'}else{'below_reviewed_generator_default'}
            }
        }
        New-GdiagPrerequisiteObservation 'prerequisite.visual-cpp-x64' $record.status @{hive='LocalMachine';view=$view;registeredVersion=$safeVersion;registeredBuild=$(if($buildNumber -gt 0){$buildNumber}else{$null});registrationAssessment=$baseline;requiredBuild='selected_package_metadata_required';runtimeLoading='not_tested';policySource=$policy.source;nativeErrorDomain=$record.error.domain;nativeErrorCode=$record.error.code;nextAction='Use the selected package redist version and failed load probe; do not equate registration with usable runtime.'} @{registry=$record;policy=$policy} $null
    }
    # The shared WebView collector preserves affected-user and registry-view provenance.
    Get-GdiagWebViewEvidence -Context $Context -Target $null
    foreach($target in @($Targets)) {
        if($target.family -eq 'gcad-cli') {
            New-GdiagPrerequisiteObservation 'distribution.gcad-cli' 'observed' @{resourceStatus=$target.resources.status;missingResourceCount=@($target.resources.missing).Count;versionIdentity=$target.release;runtimeLoading='not_tested'} @{target=$target} $target.id
        } elseif($target.family -in @('AutomationEnvironment','PythonInterpreter')) {
            New-GdiagPrerequisiteObservation 'automation.metadata' $target.file.status @{interpreterArchitecture=$target.file.architecture;interpreterVersion=$target.file.fileVersion;environmentMarker=$target.environmentMarker;packageMetadataCount=@($target.packageMetadata).Count;packageImport='not_tested';hostAttachment='not_tested';declaredRequirement=$catalog.automation.declaredRequirement} @{target=$target} $target.id
        }
    }
}
function Get-GdiagCliResources($Executable,$Descriptor) {
    $root=[IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $Executable) $Descriptor.resourceRelativeToExecutableDirectory))
    $missing=@();$errors=@()
    foreach($relative in $Descriptor.requiredResourceFiles) {
        $path=Join-Path $root $relative
        try{$item=Get-Item -LiteralPath $path -ErrorAction Stop;if($item.PSIsContainer){$errors+=@{relative=$relative;status='invalid_type';expected='file'}}}catch{
            if($_.CategoryInfo.Category -eq 'ObjectNotFound'){$missing+=$relative}else{$native=Get-GdiagNativeError $_;$errors+=@{relative=$relative;nativeErrorDomain=$native.domain;nativeErrorCode=$native.code;status=(Get-GdiagErrorStatus $_)}}
        }
    }
    @{root=$root;status=$(if($errors.Count){'collection_error'}elseif($missing.Count){'incomplete'}else{'metadata_present'});missing=$missing;errors=$errors;source=$Descriptor.source;runtimeLoading='not_tested'}
}
function Get-GdiagAdditionalTargets {
    param([hashtable]$Context,[hashtable]$Options=@{})
    $catalog=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../catalog/products.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $Context.additionalInventoryGaps=@()
    if(@($Options.cliPaths).Count -gt 32 -or (@($Options.automationPaths).Count+@($Options.pythonPaths).Count) -gt 16){throw 'Select at most 32 CLI paths and 16 automation/interpreter paths per case.'}
    $candidates=New-Object Collections.Generic.List[object]
    foreach($root in @($Options.cliPaths | Where-Object {$_})) {
        if(-not [IO.Path]::IsPathRooted([string]$root)){throw 'cliPaths must contain absolute paths.'}
        if([IO.Path]::GetExtension([string]$root) -eq '.exe'){$candidates.Add(@{path=[string]$root;source=@{kind='explicit';context='selected-user-input'}})}
        else{
            $found=$false
            foreach($name in $catalog.cliDistribution.executables){foreach($relative in @("bin/$name",$name)){
                $path=Join-Path $root $relative
                if([IO.File]::Exists($path)){$found=$true;$candidates.Add(@{path=$path;source=@{kind='explicit-distribution';context='selected-user-input'}})}
            }}
            if(-not $found){$candidates.Add(@{path=(Join-Path $root ('bin/'+$catalog.cliDistribution.executables[0]));source=@{kind='explicit-missing-distribution';context='selected-user-input'}})}
        }
    }
    foreach($name in $catalog.cliDistribution.executables) {
        foreach($command in @(Get-Command $name -All -ErrorAction SilentlyContinue | Where-Object CommandType -eq Application)){
            $candidates.Add(@{path=$command.Path;source=@{kind='executor-command-resolution';userSid=$Context.executorSid;affectedUserEnvironment='not_inferred'}})
        }
    }
    foreach($process in @(Get-Process | Where-Object ProcessName -in @('gcad-cli','gcad-tui','gcad-batch','gcadcli'))) {
        try{$candidates.Add(@{path=$process.Path;source=@{kind='running-image';pid=$process.Id;startUtc=$process.StartTime.ToUniversalTime().ToString('o');userIdentity='unverified'}})}catch{
            $native=Get-GdiagNativeError $_
            $Context.additionalInventoryGaps+=New-GdiagPrerequisiteObservation 'inventory.process-image' (Get-GdiagErrorStatus $_) @{pid=$process.Id;nativeErrorDomain=$native.domain;nativeErrorCode=$native.code;userIdentity='unverified'} $null $null
        }
    }
    foreach($view in @('Registry64','Registry32')){foreach($location in @(@{hive='LocalMachine';prefix='SOFTWARE';sid=$null},@{hive='Users';prefix="$($Context.affectedSid)\Software";sid=$Context.affectedSid})){
        $key="$($location.prefix)\Microsoft\Windows\CurrentVersion\Uninstall"
        $root=Get-GdiagRegistryRecord $location.hive $view $key $location.sid
        if($root.status -ne 'observed'){$Context.additionalInventoryGaps+=New-GdiagPrerequisiteObservation 'inventory.uninstall-discovery' $root.status @{hive=$location.hive;view=$view;nativeErrorDomain=$root.error.domain;nativeErrorCode=$root.error.code} @{registry=$root} $null}
        if(@($root.subkeys).Count -gt 1024){$Context.additionalInventoryGaps+=New-GdiagPrerequisiteObservation 'inventory.uninstall-discovery' 'truncated' @{hive=$location.hive;view=$view;entryLimit=1024} $null $null}
        foreach($child in @($root.subkeys | Select-Object -First 1024)){
            $record=Get-GdiagRegistryRecord $location.hive $view "$key\$child" $location.sid
            if($record.status -notin @('observed','absent')){$Context.additionalInventoryGaps+=New-GdiagPrerequisiteObservation 'inventory.uninstall-entry' $record.status @{hive=$location.hive;view=$view;nativeErrorDomain=$record.error.domain;nativeErrorCode=$record.error.code} @{registry=$record} $null}
            $display=Get-GdiagRegValue $record @('DisplayName')
            if($display -notmatch '^gcad-(cli|tui|batch)(\s|$)'){continue}
            $install=Get-GdiagRegValue $record @('InstallLocation')
            if(-not $install -or -not [IO.Path]::IsPathRooted([string]$install)){continue}
            foreach($name in $catalog.cliDistribution.executables){foreach($relative in @("bin/$name",$name)){
                $path=Join-Path $install $relative
                if([IO.File]::Exists($path)){$candidates.Add(@{path=$path;source=@{kind='uninstall-registration';record=$record}})}
            }}
        }
    }}
    # Exact executable identity deduplication retains each registry view/source separately.
    $targets=@{}
    foreach($candidate in $candidates){
        if(-not $candidate.path){continue}
        $path=[IO.Path]::GetFullPath($candidate.path)
        if(-not $targets.ContainsKey($path)){
            $targets[$path]=[pscustomobject]@{family='gcad-cli';release='unknown';path=$path;file=(Get-GdiagFileIdentity $path);sources=@();resources=(Get-GdiagCliResources $path $catalog.cliDistribution);expectationStatus='source_layout_only_unknown_release';hostVerification='pending'}
        }
        $targets[$path].sources+=@($candidate.source)
    }
    foreach($entry in $targets.Values){$entry}
    foreach($inputPath in @($Options.automationPaths | Where-Object {$_})+@($Options.pythonPaths | Where-Object {$_})) {
        if(-not [IO.Path]::IsPathRooted([string]$inputPath)){throw 'Automation/interpreter paths must be absolute.'}
        $path=[IO.Path]::GetFullPath([string]$inputPath)
        $isInterpreter=([IO.Path]::GetExtension($path) -eq '.exe')
        $python=if($isInterpreter){$path}else{Join-Path $path $catalog.automation.venvInterpreterRelativePath}
        $marker=if($isInterpreter){$null}else{Join-Path $path $catalog.automation.venvMarker}
        $markerState='not_inferred_from_executable';$metadataStatus='not_tested';$metadataError=$null
        if($marker){try{$markerItem=Get-Item -LiteralPath $marker -ErrorAction Stop;$markerState=if($markerItem.PSIsContainer){'invalid_type'}else{'present'}}catch{$markerState=if($_.CategoryInfo.Category -eq 'ObjectNotFound'){'absent'}else{Get-GdiagErrorStatus $_}}}
        $packageMetadata=@()
        if(-not $isInterpreter){
            $site=Join-Path $path 'Lib/site-packages'
            try{
                $siteItem=Get-Item -LiteralPath $site -ErrorAction Stop
                if(-not $siteItem.PSIsContainer){throw 'Selected site-packages is not a directory.'}
                $metadataStatus='observed'
                foreach($directory in @(Get-ChildItem -LiteralPath $site -Directory -Filter 'pygcadwin-*.dist-info' -ErrorAction Stop | Select-Object -First 16)){
                    $metadata=Join-Path $directory.FullName 'METADATA'
                    if([IO.File]::Exists($metadata) -and (Get-Item -LiteralPath $metadata).Length -le 1048576){
                        $body=Get-Content -LiteralPath $metadata -Raw -Encoding UTF8
                        $version=[regex]::Match($body,'(?m)^Version:\s*([^\r\n]+)').Groups[1].Value
                        if($version -notmatch '^[A-Za-z0-9.!+_-]{1,128}$'){$version='invalid_or_absent'}
                        $packageMetadata+=@{path=$metadata;declaredVersion=$version;import='not_tested';compatibility='not_inferred_from_requirement_lower_bound'}
                    }
                }
            }catch{$metadataStatus=if($_.CategoryInfo.Category -eq 'ObjectNotFound'){'absent'}else{Get-GdiagErrorStatus $_};$metadataError=Get-GdiagNativeError $_}
        }
        [pscustomobject]@{family=$(if($isInterpreter){'PythonInterpreter'}else{'AutomationEnvironment'});release='unknown';path=$path;pythonPath=$python;file=(Get-GdiagFileIdentity $python);environmentMarker=$markerState;packageMetadata=$packageMetadata;packageMetadataStatus=$metadataStatus;error=$metadataError;selection='explicit';hostVerification='pending'}
    }
}
function Invoke-GdiagAutomationReadiness {
    param([hashtable]$Context,$Target,[hashtable]$Options=@{},[int]$TimeoutSeconds=15)
    if($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 60){throw 'AutomationReadiness timeout must be 1..60 seconds.'}
    $python=$Target.pythonPath
    if(-not $python -and $Target.family -eq 'PythonInterpreter'){$python=$Target.path}
    if(-not $python -or -not [IO.Path]::IsPathRooted($python)){throw 'AutomationReadiness requires an exact absolute selected pythonPath.'}
    if(@($Options.wheelPaths).Count -gt 16){throw 'Select at most 16 wheels per readiness check.'}
    $wheelJson=ConvertTo-Json -InputObject @($Options.wheelPaths | Where-Object {$_}) -Compress
    $wheelData=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($wheelJson))
    $code=@'
import sys,sysconfig,os,json,struct,importlib,importlib.metadata as md,re,zipfile,base64
r={'interpreter':sys.executable,'prefix':sys.prefix,'basePrefix':sys.base_prefix,'pythonVersion':'.'.join(map(str,sys.version_info[:3])),'pointerBits':struct.calcsize('P')*8,'expectedPipTarget':sysconfig.get_path('purelib'),'dedicatedEnvironment':sys.prefix!=sys.base_prefix,'hostAttachment':'not_tested','packages':[],'wheels':[]}
def safe(v):
 return v if isinstance(v,str) and re.fullmatch(r'[A-Za-z0-9.!+_*,<>=~ -]{1,160}',v) else 'invalid_or_absent'
def inside(p,root):
 try:return os.path.commonpath([os.path.abspath(p),os.path.abspath(root)]).lower()==os.path.abspath(root).lower()
 except ValueError:return False
try:
 import pip
 r['pipVersion']=safe(pip.__version__);r['pipModulePath']=pip.__file__;r['pipInSelectedPrefix']=inside(pip.__file__,sys.prefix)
 from pip._vendor.packaging.specifiers import SpecifierSet
 from pip._vendor.packaging.requirements import Requirement
 from pip._vendor.packaging.tags import sys_tags,parse_tag
 supported=set(sys_tags())
 try:
  from pip._internal.configuration import Configuration
  cfg=Configuration(isolated=True);cfg.load()
  r['isolatedPipRedirectKeys']=sorted(k for k,v in cfg.items() if k in ('global.target','install.target','global.prefix','install.prefix','global.user','install.user') and str(v).lower() not in ('','false','0','no'))
  r['pipRouteAssessment']='redirect_configured' if r['isolatedPipRedirectKeys'] else 'selected_interpreter_default'
 except Exception as e:r['pipRouteAssessment']='unavailable';r['pipConfigErrorType']=type(e).__name__
except Exception as e:
 r['status']='pip_or_compatibility_parser_unavailable';r['errorType']=type(e).__name__;print(json.dumps(r));sys.exit(0)
required=['pygcadwin','pywin32'];compatible=True
for name in required:
 try:
  dist=md.distribution(name);requires=dist.metadata.get('Requires-Python','');version=dist.version
  item={'name':name,'version':safe(version),'requiresPython':safe(requires) if requires else 'not_declared','pythonCompatible':not requires or SpecifierSet(requires).contains(r['pythonVersion'],prereleases=True),'distributionPath':str(dist.locate_file(''))}
  item['inSelectedPrefix']=inside(str(dist.locate_file('')),sys.prefix)
  wheel=dist.read_text('WHEEL') or '';tags=[line[5:].strip() for line in wheel.splitlines() if line.startswith('Tag:')]
  item['wheelTagsCompatible']=any(bool(parse_tag(t)&supported) for t in tags) if tags else None
  if not item['pythonCompatible'] or item['wheelTagsCompatible'] is False or not item['inSelectedPrefix']:compatible=False
  if name=='pygcadwin':
   item['dependencyChecks']=[]
   for raw in (dist.requires or []):
    req=Requirement(raw)
    if req.marker and not req.marker.evaluate({'extra':''}):continue
    try:installed=md.version(req.name);ok=req.specifier.contains(installed,prereleases=True)
    except md.PackageNotFoundError:installed=None;ok=False
    item['dependencyChecks'].append({'name':safe(req.name),'version':safe(installed),'satisfied':ok})
    if not ok:compatible=False
  r['packages'].append(item)
 except md.PackageNotFoundError:r['packages'].append({'name':name,'status':'absent'});compatible=False
 except Exception as e:r['packages'].append({'name':name,'status':'metadata_invalid','errorType':type(e).__name__});compatible=False
for path in json.loads(base64.b64decode('WHEEL_DATA').decode()):
 item={'path':path,'status':'unverified'}
 try:
  if not os.path.isabs(path) or os.path.getsize(path)>134217728:raise ValueError('wheel-bound')
  with zipfile.ZipFile(path) as z:
   entries=[i for i in z.infolist() if i.filename.endswith('.dist-info/WHEEL')]
   metadata=[i for i in z.infolist() if i.filename.endswith('.dist-info/METADATA')]
   if len(entries)!=1 or len(metadata)!=1 or entries[0].file_size>65536 or metadata[0].file_size>1048576:raise ValueError('metadata-bound')
   from email.parser import Parser
   fields=Parser().parsestr(z.read(metadata[0]).decode('utf-8'))
   tags=[line[5:].strip() for line in z.read(entries[0]).decode('utf-8').splitlines() if line.startswith('Tag:')]
   requires=fields.get('Requires-Python','');item.update(name=safe(fields.get('Name')),version=safe(fields.get('Version')),requiresPython=safe(requires) if requires else 'not_declared',pythonCompatible=not requires or SpecifierSet(requires).contains(r['pythonVersion'],prereleases=True),wheelTagsCompatible=any(bool(parse_tag(t)&supported) for t in tags),status='metadata_inspected',authenticity='not_established_by_metadata')
 except Exception as e:item.update(status='metadata_invalid',errorType=type(e).__name__)
 r['wheels'].append(item)
r['status']='package_compatibility_failed'
if compatible:
 try:
  for name in ('pygcadwin','pythoncom','win32com.client','pywintypes'):
   r['importStage']=name;importlib.import_module(name)
  r['status']='imports_verified_host_pending';r['packageModulePath']=sys.modules['pygcadwin'].__file__
 except Exception as e:r['status']='binding_import_failed';r['errorType']=type(e).__name__;r['errorMessageLocal']=str(e)[:2048]
print(json.dumps(r))
'@
    $code=$code.Replace('WHEEL_DATA',$wheelData)
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($code))
    $arguments='-I -B -c "exec(__import__(''base64'').b64decode('''+$encoded+''').decode(''utf-8''))"'
    $result=Invoke-GdiagOwnedProcess $python $arguments $TimeoutSeconds
    $summary=@{probeStatus=$result.status;hostAttachment='not_tested';nativeStage=$result.stage;exitCode=$result.exitCode;termination=$result.termination}
    $detail=$null;$status=$result.status
    if($result.status -eq 'observed'){
        try{
            $detail=ConvertFrom-Json -InputObject $result.stdout -ErrorAction Stop
            $summary.automationReadiness=$detail.status;$summary.dedicatedEnvironment=$detail.dedicatedEnvironment;$summary.pipRouteAssessment=$detail.pipRouteAssessment;$summary.pipInSelectedPrefix=$detail.pipInSelectedPrefix;$summary.pythonVersion=$detail.pythonVersion;$summary.pointerBits=$detail.pointerBits;$summary.importStage=$detail.importStage;$summary.errorType=$detail.errorType
            $summary.interpreter=$detail.interpreter;$summary.expectedPipTarget=$detail.expectedPipTarget;$summary.pipVersion=$detail.pipVersion
            $summary.packages=@($detail.packages | Select-Object name,version,pythonCompatible,wheelTagsCompatible,inSelectedPrefix,status)
        }catch{$status='collection_error';$summary.stage='readiness_json';$summary.errorType=$_.Exception.GetType().Name}
    }
    New-GdiagPrerequisiteObservation 'automation.readiness' $status $summary @{interpreter=$python;result=$result;readiness=$detail;note='No host is created, attached or closed. Import/pip metadata does not prove selected CAD automation.'} $Target.id
}
