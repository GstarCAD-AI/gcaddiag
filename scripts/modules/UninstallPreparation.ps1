# Read-only preparation for the source-backed recursive vendor uninstaller.
function Get-GdiagUninstallPreparation {
    param($Context,$Target)
    if(-not $Target -or $Target.family -ne 'GstarAssistant'){return @{status='unsupported_product';nextAction='Use the selected product vendor workflow; no uninstall handler is verified.'}}
    $root=Assert-GdiagPlainPath $Target.path
    if($root.StartsWith('\\') -or $root -eq [IO.Path]::GetPathRoot($root)){throw 'Select a local installation directory, not a volume or network root.'}
    $files=New-Object Collections.Generic.List[object]
    $gaps=New-Object Collections.Generic.List[string]
    $overlaps=@()
    foreach($other in @($Context.targets)){
        if(-not $other -or $other.id -eq $Target.id -or -not $other.path){continue}
        $otherRoot=[IO.Path]::GetFullPath($other.path).TrimEnd('\')
        if($root.TrimEnd('\') -eq $otherRoot -or $root.StartsWith($otherRoot+'\',[StringComparison]::OrdinalIgnoreCase) -or $otherRoot.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){
            $overlaps+=@{targetId=$other.id;family=$other.family;release=$other.release;path=$otherRoot}
        }
    }
    $manifestRoot=$root;if($Target.payloadRoot){$manifestRoot=Assert-GdiagPlainPath $Target.payloadRoot}
    $listed=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $manifestStatus='absent';$manifestPath=Join-Path $manifestRoot 'payload-manifest.json'
    if(Test-Path -LiteralPath $manifestPath){
        try{
            Assert-GdiagPlainPath $manifestPath | Out-Null
            if((Get-Item -LiteralPath $manifestPath -Force).Length -gt 16777216){throw 'Manifest exceeds input bound.'}
            $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if($manifest.schema_version -ne 2 -or $manifest.product -ne 'GstarAssistant' -or $manifest.layout -ne 'gstarassistant-v1' -or $manifest.files -isnot [pscustomobject]){throw 'Unsupported installed manifest.'}
            $entries=@($manifest.files.PSObject.Properties)
            if($entries.Count -gt 100000){throw 'Manifest entry bound exceeded.'}
            foreach($entry in $entries){
                $relative=$entry.Name.Replace('/','\')
                if([IO.Path]::IsPathRooted($relative) -or $relative -match '[<>:"|?*\x00-\x1f]' -or @($relative -split '\\' | Where-Object {-not $_ -or $_ -in @('.','..') -or $_.EndsWith('.') -or $_.EndsWith(' ')}).Count){throw 'Unsafe installed manifest path.'}
                if($entry.Value -notmatch '^[0-9A-Fa-f]{64}$'){throw 'Invalid installed manifest hash.'}
                [void]$listed.Add([IO.Path]::GetFullPath((Join-Path $manifestRoot $relative)))
            }
            $manifestStatus='installed_manifest_untrusted_membership_only'
        }catch{$listed.Clear();$manifestStatus='unavailable_or_invalid';$gaps.Add('Installed manifest cannot classify package membership.')}
    }
    $clock=[Diagnostics.Stopwatch]::StartNew();$itemCount=0;$bytes=0L;$status='inventory_complete'
    if(-not(Test-Path -LiteralPath $root -PathType Container)){$status='installation_absent';$gaps.Add('Selected installation directory is absent.')}
    else{
        $pending=New-Object 'Collections.Generic.Stack[string]';$pending.Push($root)
        while($pending.Count -and $status -ne 'truncated'){
            $directory=$pending.Pop()
            try{
                foreach($path in [IO.Directory]::EnumerateFileSystemEntries($directory)){
                    if($itemCount -ge 5000 -or $clock.Elapsed.TotalSeconds -ge 10){$status='truncated';$gaps.Add('Inventory reached the 5000-item or 10-second work bound; remaining files are unresolved.');break}
                    $itemCount++
                    $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    $relative=$item.FullName.Substring($root.TrimEnd('\').Length+1)
                    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){$gaps.Add('A reparse entry was not followed.');$files.Add(@{relative=$relative;category='reparse_unresolved';bytes=$null});continue}
                    if($item.PSIsContainer){$pending.Push($item.FullName);continue}
                    $category='unlisted_preserve_review'
                    if($listed.Contains($item.FullName)){$category='manifest_listed_unverified'}
                    if($relative -match '(?i)(^|[\\/])(?:\.env(?:\..*)?|credentials[^\\/]*|licenses?[^\\/]*|id_rsa|id_ed25519)$|\.(?:dwg|dxf|dwt|db|sqlite|sqlite3|pfx|key|pem|lsp|fas|vlx)$|(^|[\\/])(?:configs|skills|plugins|templates)([\\/]|$)'){$category='user_or_configuration_preserve'}
                    $bytes+=$item.Length
                    $files.Add(@{relative=$relative;category=$category;bytes=$item.Length})
                }
            }catch{$gaps.Add('A directory could not be fully enumerated; contents remain unresolved.');$status='collection_incomplete'}
        }
    }
    $registration=@();$registryStatus='unsupported_release'
    if($Target.release -in @('R26','R27')){
        $registryStatus='observed'
        foreach($release in @('R26','R27')){
            foreach($key in @("Software\Gstarsoft\GstarAssistant\$release","Software\Microsoft\Windows\CurrentVersion\Uninstall\GstarAssistant $release")){
                $record=Get-GdiagRegistryRecord Users Registry64 ($Context.affectedSid+'\'+$key) $Context.affectedSid
                $registration+=@{release=$release;key=$key;record=$record}
                if($record.status -notin @('observed','absent')){$registryStatus='incomplete'}
            }
        }
    }
    $matchedReleases=@();$uninstallerRegistration='unverified';$startupRegistration='unverified'
    $uninstaller=Join-Path $root 'uninstall.exe'
    foreach($entry in $registration){
        $location=Get-GdiagRegValue $entry.record @('InstallLocation')
        if($location -and [IO.Path]::IsPathRooted([string]$location) -and [IO.Path]::GetFullPath([string]$location).TrimEnd('\') -eq $root.TrimEnd('\')){
            $matchedReleases+= $entry.release
            if($entry.release -eq $Target.release -and $entry.key -match '\\Uninstall\\'){
                $command=Get-GdiagRegValue $entry.record @('UninstallString')
                $uninstallerRegistration=if($command -eq ('"'+$uninstaller+'"')){'matches_exact_source_command'}else{'mismatch_or_missing'}
            }
            if($entry.release -eq $Target.release -and $entry.key -match '\\Gstarsoft\\'){
                $productRelease=Get-GdiagRegValue $entry.record @('GcadProductRelease')
                $locale=Get-GdiagRegValue $entry.record @('GcadLocale')
                if($productRelease -match '^(R26|R27|B27)$' -and $locale -match '^[A-Za-z0-9_-]+$'){
                    $startupRegistration='recorded_target_requires_current_host_validation'
                    $entry.startupKey="Software\Gstarsoft\GstarCAD\$productRelease\$locale\Applications\GstarAssistant"
                }
            }
        }
    }
    $matchedReleases=@($matchedReleases | Select-Object -Unique)
    if($matchedReleases.Count -gt 1){$gaps.Add('R26 and R27 registration share this root; source uninstaller chooses R27 first. Resolve release ownership before uninstall.')}
    if($Target.release -notin $matchedReleases){$gaps.Add('Selected release registration does not confirm this installation root.')}
    $processUse='not_running_observed'
    try{Assert-GdiagAutomationIdle $root @('gcad','GstarCAD','GstarAssistant','uninstall')}catch{$processUse='running_or_inaccessible';$gaps.Add('Selected process use could not be cleared; close only the affected host through its normal workflow.')}
    $uninstallerStatus='absent'
    if(Test-Path -LiteralPath $uninstaller -PathType Leaf){
        try{Assert-GdiagPlainPath $uninstaller | Out-Null;$uninstallerStatus='present_identity_unverified'}catch{$uninstallerStatus='reparse_unresolved'}
    }
    if($overlaps.Count){$gaps.Add('Another saved target overlaps the recursive removal root.')}
    $counts=[ordered]@{manifestListed=0;unlisted=0;userOrConfiguration=0;reparse=0}
    foreach($item in $files){switch($item.category){'manifest_listed_unverified'{$counts.manifestListed++}'unlisted_preserve_review'{$counts.unlisted++}'user_or_configuration_preserve'{$counts.userOrConfiguration++}'reparse_unresolved'{$counts.reparse++}}}
    @{status=$status;installationPath=$root;recursiveRemoval=$true;entryCount=$itemCount;fileCount=$files.Count;bytes=$bytes;categories=$counts;
      manifestStatus=$manifestStatus;registryStatus=$registryStatus;uninstallerStatus=$uninstallerStatus;uninstallerRegistration=$uninstallerRegistration;startupRegistration=$startupRegistration;
      processUse=$processUse;overlapCount=$overlaps.Count;sharedReleaseRoot=($matchedReleases.Count -gt 1);preservation='required_before_vendor_uninstall';execution='not_supported_pending_isolated_vendor_acceptance';
      nextAction='Review the private plan inventory, preserve custom/configuration files outside the entire removal root, resolve ownership/process gaps, and verify the installed vendor contract. Recollect before any future execution.';
      gaps=$gaps.ToArray();observed=@{files=$files.ToArray();registration=$registration;overlaps=$overlaps;uninstallerPath=$uninstaller;preserved=$false};
      limits=@('Read-only metadata inventory; no file contents copied or hashed and no registry/process changes.','Installed manifest membership does not authenticate files or establish that listed settings are unchanged or disposable.','Uninstaller presence/registration is not trusted package identity or permission to execute.','Nested browser module usage and external state roots need selected product evidence; no lock-free or complete data-backup claim.')}
}
