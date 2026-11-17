# Source: generate_nsis_setup.ps1 uses File /r overlay at INSTDIR and generates
# app_icon.ico/uninstall.exe; /REPAIR is not a separate preservation branch.
# Call only after the existing vendor planner has validated candidate manifest,
# signed installer/hash/release association and current selected host identity.
function Get-GdiagLegacyRecoveryAssessment {
    param($Target,$CandidateManifest,$ExistingTree,[string]$OriginalManifestStatus)
    if($Target.family -ne 'GstarAssistant' -or $Target.release -notin @('R26','R27')){throw 'Legacy recovery assessment requires a selected supported assistant release.'}
    if($OriginalManifestStatus -notin @('absent','invalid')){throw 'Legacy recovery must identify absent or invalid installed metadata.'}
    $root=Assert-GdiagPlainPath $Target.path
    $payloadRoot=$root;if($Target.payloadRoot){$payloadRoot=Assert-GdiagPlainPath $Target.payloadRoot}
    if($payloadRoot -ne $root -and -not $payloadRoot.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Registered legacy payload lies outside selected installation; resolve target ownership first.'}
    $candidate=@($CandidateManifest.files.PSObject.Properties)
    if($CandidateManifest.product -ne 'GstarAssistant' -or $CandidateManifest.layout -ne 'gstarassistant-v1' -or $CandidateManifest.schema_version -ne 2 -or -not $candidate.Count){throw 'Validated candidate manifest is required.'}
    if([string]$CandidateManifest.target_year -ne ('20'+$Target.release.Substring(1))){throw 'Recovery candidate release differs from selected assistant.'}
    # ExistingTree is the already collected exact current file/hash snapshot.
    # Reject aliases before using externally supplied manifest or snapshot paths.
    $existing=@{};$candidatePaths=@{}
    foreach($file in @($ExistingTree)){
        $relative=([string]$file.relative).Replace('/','\')
        $full=[IO.Path]::GetFullPath((Join-Path $root $relative))
        if([IO.Path]::IsPathRooted($relative) -or -not $full.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $file.hash -notmatch '^[A-Fa-f0-9]{64}$' -or $existing.ContainsKey($relative)){throw 'Invalid current installation snapshot.'}
        $existing[$relative]=$file
    }
    foreach($entry in $candidate){
        $relative=$entry.Name.Replace('/','\')
        $full=[IO.Path]::GetFullPath((Join-Path $root $relative))
        if([IO.Path]::IsPathRooted($relative) -or -not $full.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $entry.Value -notmatch '^[A-Fa-f0-9]{64}$' -or $candidatePaths.ContainsKey($relative)){throw 'Invalid candidate inventory.'}
        $candidatePaths[$relative]=$entry.Value
    }
    $details=New-Object 'Collections.Generic.List[object]'
    $matching=0;$missing=0;$collisions=0;$preserveCount=0;$generatedConflicts=0
    foreach($relative in @($candidatePaths.Keys | Sort-Object)){
        $prior=$existing[$relative]
        $state=if(-not $prior){'missing_restore_candidate'}elseif($prior.hash -eq $candidatePaths[$relative]){'matches_candidate'}else{'collision_requires_preservation_and_migration'}
        switch($state){'missing_restore_candidate'{$missing++}'matches_candidate'{$matching++}default{$collisions++}}
        $details.Add([pscustomobject]@{relative=$relative;candidateHash=$candidatePaths[$relative];beforeHash=$(if($prior){$prior.hash}else{$null});assessment=$state})
    }
    foreach($relative in @($existing.Keys | Sort-Object)){
        if($candidatePaths.ContainsKey($relative)){continue}
        $category='unlisted_custom_preserve_in_place'
        if($relative -eq 'payload-manifest.json'){$category='invalid_metadata_preserve_original_before_replacement'}
        elseif($relative -in @('uninstall.exe','app_icon.ico')){$category='generated_file_collision_requires_preservation';$generatedConflicts++}
        $preserveCount++
        $details.Add([pscustomobject]@{relative=$relative;beforeHash=$existing[$relative].hash;candidateHash=$null;assessment=$category})
    }
    $legacyLayout=$payloadRoot -ne $root
    $legacyRemnants=@($existing.Keys | Where-Object {$_ -match '^contents\\(?:modules|configs|skills|python|lib)\\'}).Count -gt 0
    $layoutUnverified=$legacyRemnants -and $Target.modulePathSource -ne 'registered_module_path'
    $gaps=New-Object 'Collections.Generic.List[string]'
    if($legacyLayout){$gaps.Add('Registered payload root differs from installer destination. The reviewed installer does not migrate legacy contents/configuration; resolve mapping before overlay.')}
    if($layoutUnverified){$gaps.Add('Legacy contents files exist without a registered loader establishing the active layout. A catalog-default root cannot authorize migration.')}
    if($collisions){$gaps.Add('Candidate payload would replace differing bytes. Without trusted old metadata, corruption cannot be distinguished from local edits; preserve and resolve each collision.')}
    if($generatedConflicts){$gaps.Add('The installer generates existing app_icon.ico/uninstall.exe outside its validated payload inventory. Their ownership/content requires resolution before overwrite.')}
    $canOverlay=-not $legacyLayout -and -not $layoutUnverified -and $collisions -eq 0 -and $generatedConflicts -eq 0
    [pscustomobject]@{
        mode='recover-installed-manifest';installedManifestStatus=$OriginalManifestStatus;
        installedVersion='unverified_without_valid_installed_manifest';candidateVersion=[string]$CandidateManifest.version;
        candidateRelease=$Target.release;candidateLayout='gstarassistant-v1';layoutMigrationRequired=$legacyLayout;legacyLayoutUnverified=$layoutUnverified;
        status=$(if($canOverlay){'missing_files_overlay_preconditions_met'}else{'preservation_or_migration_required'});
        canOverlay=$canOverlay;matchingCount=$matching;missingCount=$missing;collisionCount=$collisions;preservationCount=$preserveCount;generatedCollisionCount=$generatedConflicts;
        preservation='Shared vendor executor must preserve full exact installation snapshot and typed registration before invocation; unlisted custom files remain in place and are hash-checked afterward.';
        nextAction=$(if($canOverlay){'Use the existing trusted vendor Repair plan with its stale-state checks and full originals. Verify complete candidate payload/registration, then the failed component and selected CAD host.'}else{'Review the private exact-path collision inventory. Preserve originals outside the entire installation root; obtain a version/layout-specific migration or resolve selected collisions before replanning. Do not manufacture an installed manifest or delete old contents.'});
        gaps=$gaps.ToArray();observed=@{installationPath=$root;registeredPayloadRoot=$payloadRoot;files=$details.ToArray()};
        limits=@('Only Repair is eligible. Update across unknown installed metadata/version requires explicit migration planning.','A candidate hash is not installer authenticity; the normal vendor signature, trusted package/manifest association and release/host checks remain required.','This assessment performs no copy, registration change or installer execution. It does not attest vendor recovery, rollback or preserved-backup completion.')
    }
}
