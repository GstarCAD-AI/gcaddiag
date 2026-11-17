# Selected Microsoft VC++ x64 remedy

Use `vc-redist-x64` only for a selected R26/R27 GstarAssistant with a recorded
failed x64 native DLL-load probe. The catalog's prerequisite policy comes from
`GstarAssistant/src/apps/GstarAssistant/nsis/generate_nsis_setup.ps1`
`EnsureVcRedistX64`. The standalone remedy uses Microsoft's documented
[install/repair, logging and restart controls](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170).

The operation is `Repair`; `prerequisiteAction` selects `install` for a missing
or older machine runtime, or `repair` for the exact registered runtime version.
Select an existing Microsoft-signed local v14 x64 Redistributable and its exact
publisher subject, version and trusted SHA256. The package is not bundled or
downloaded by the skill. A newer installed runtime refuses an older package;
obtain the matching current repair package instead. Do not infer package
architecture from the bootstrap executable's PE bitness.

```json
{
  "recipe": "vc-redist-x64",
  "setupContract": "microsoft-vc-v14-x64-v1",
  "failureEvidenceId": "evidence-from-selected-native-probe",
  "prerequisiteAction": "repair",
  "packagePath": "C:\\Support\\vc_redist.x64.exe",
  "expectedPackageHash": "TRUSTED_SHA256",
  "expectedPublisher": "EXACT_MICROSOFT_AUTHENTICODE_SUBJECT",
  "packageVersion": "SELECTED_EXACT_PRODUCT_VERSION"
}
```

The failed observation must belong to this case and target, identify an existing
DLL within its payload and record a `LoadLibraryEx` dependency/initialization
failure (Win32 126, 1114 or 14001). This is a reason to investigate the declared
prerequisite, not proof it caused the error. Architecture mismatch and later
Python startup failures are not accepted as this recipe's evidence. Select the
appropriate probe before planning rather than manufacture an observation.

Planning verifies the package, preserves typed HKLM64 version evidence and
binds the exact failed DLL. Apply rechecks current state, closes no applications,
and refuses a running or inaccessible selected host. It invokes only the
selected vendor executable through normal UAC with fixed `/install` or `/repair`,
`/norestart` and a case-local `/log` destination. The default displays the vendor
UI. `silent:true` adds `/quiet` only when `agreementsAccepted:true` records an
already-authorized silent operation and applicable agreement acceptance. The
collector keeps its affected-user identity and does not run a generic elevated
shell or modify HKCU.

The installer is allowed five minutes. A timeout leaves the elevated vendor
process unresolved; inspect actual process and machine state before recovery.
Cancellation, nonzero exit and missing/mismatched registration remain failed.
Successful registration is checked using the same typed source-policy key, and
the exact original DLL-load probe is repeated in an isolated owned child.
Successful loading still requires verification of the original CAD symptom.

Exit `3010` remains `restart_required`, including later Verify. Complete the
restart normally, recollect evidence and rerun the original probe separately;
the original action receipt is not rewritten to erase its restart requirement.
No automatic restart or shared-runtime Undo is offered. Registry originals are
diagnostic evidence, not a method to roll back an installed runtime. Other
applications share this runtime; do not uninstall it as cleanup or copy DLLs
from another product release.

Local acceptance uses an owned executable/DLL fixture with mocked signature,
registry, UAC and host-idle checks. Actual Microsoft installation, UAC and
registered-machine recovery acceptance remain pending a disposable test machine.
