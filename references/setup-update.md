# Setup and updates

Start with the selected workload: GstarCAD/assistant, standalone CLI, drawing automation, or an external-host skill. Inventory first; a missing optional product is not permission to install all prerequisites.

The skill lifecycle recipe is `skill-package`, for a trusted local skill distribution. It copies the complete selected package into an empty destination, records file hashes, repairs missing recorded resources, and applies a matching package update while rejecting conflicting local edits. It retains extra/custom files. It does not silently install Codex, WorkBuddy, Python or a product-private runtime. Versions absent from package metadata remain unknown.

Supply an options JSON file to `Plan`:

```json
{"recipe":"skill-package","sourcePath":"C:\\Support\\trusted-skill","destinationPath":"C:\\Project\\.agents\\skills\\example","expectedPackageHash":"TREE_SHA256"}
```

Use `Setup` without an existing target to create an intended Skill target. For Repair/Update, select the same case-local Skill target. The SHA256 is the sorted package tree identity (relative paths with `/`, `:`, SHA256 per file, joined with LF, UTF-8); `Get-GdiagTreeHash (Get-GdiagTree <path>)` in `Lifecycle.ps1` measures it. A checksum detects change; it does not establish publisher authenticity. Review source provenance and requested scope before applying. No downloading or package discovery occurs in offline maintenance.

Plan writes case artifacts only. Review exact destination and files, use the host's existing authorization, then Apply and Verify. File integrity verification leaves actual skill discovery and operation `hostVerification=pending`. Reopen/reload the selected host through its supported mechanism and perform a bounded real invocation. A file-copy success is not host readiness.

Existing unmanaged skill installations require explicit reconciliation instead of overwriting: compare custom files, preserve edits, then use an empty selected destination. Repair and Update require gcaddiag's prior package record. Updates preserve removed/extra files for separate ownership review; they never infer disposability from an updated manifest. Updating the currently executing gcaddiag tree is refused; finish the incident and run another copy.

For GstarAssistant, inspect the installed setup version before deriving arguments. Reviewed sources: `GstarAssistant/src/apps/GstarAssistant/nsis/generate_nsis_setup.ps1` and `src/apps/setup_wizard/packages/installer_core/lib/src/lifecycle/installer_impl.dart`. The wrapper passes `/S /TARGET=<year> /TARGETPATH=<host>`; repair adds `/REPAIR`. The generator recognizes target, target path, install directory and log file. Its repair behavior is payload/registration reinstallation. Do not infer a separate cause-specific repair. Silent EULA handling belongs to the wrapper/product, and cannot be silently accepted by this skill.

## Dedicated automation environment

For a standalone CLI distribution, use the source-backed
[CLI package recipe](cli-package.md) with its complete trusted manifest.
For a selected assistant prerequisite load failure, see the narrow
[VC++ prerequisite remedy](prerequisite-repair.md). Both retain their own
component/host verification and reversal limits.

Recipe `automation-venv` creates or recreates a dedicated Python environment with an exact launcher. Select a standalone base Python explicitly; the recipe checks its executable hash and requires `sys.prefix == sys.base_prefix`. It rejects known product-private Python paths and never runs pip in the base environment. Use the installed standalone Python distribution's normal installation/trust checks; an executable checksum alone does not authenticate every standard-library file.

```json
{"recipe":"automation-venv","destinationPath":"C:\\Support\\gcadclaw-env","pythonPath":"C:\\Python311\\python.exe","expectedPythonHash":"BASE_EXE_SHA256","standalonePython":true,"wheels":[{"path":"C:\\Support\\wheels\\pygcadwin-SELECTED-py3-none-any.whl","sha256":"WHEEL_SHA256"}],"dependencies":["pygcadwin==SELECTED_VERSION"],"timeoutSeconds":120}
```

Replace example wheel/version with the actual compatible selected package and all required dependency wheels. Every supplied wheel requires an exact checksum. Package pins must be `name==version`; URLs, ranges and pip options are refused. Pip uses only these supplied wheels with `--isolated --no-index --no-deps --no-cache-dir --disable-pip-version-check`; it does not fetch dependencies or query an index. A missing/incompatible wheel or failed package import remains a failed component check. There is no claim that any arbitrary pygcadwin version fits every CAD release.

Setup requires an absent destination. Repair/Update require a prior `gcaddiag-environment.json` ownership record. Existing environments are preserved whole in a unique adjacent directory before recreation. Custom files remain in that preserved environment; no settings are automatically migrated across Python/dependency changes. Creation happens at the final path because moving a staged Windows venv would leave pip launchers pointing at its old absolute path. The returned `Scripts/python.exe` is the exact launcher for future commands.

Child creation, offline installation and startup are time/output bounded; termination targets only the owned parent and descendants whose creation identities were inspected. A process job does not contain the tree, so timeout/truncation always reports manual attention: confirm no owned descendant remains before recovery. Descendant inspection/termination failures remain explicit gaps. A failed action leaves `started` state; automatic Undo and replay are prohibited. Failure preserves any previous environment. Inspect the exact current/preserved paths before manual recovery. Verify checks stdlib startup and exact pinned distribution versions, and imports `pygcadwin` when selected. An empty dependency list verifies only a stdlib environment. Package import always leaves actual selected CAD attachment pending.

Undo preserves the newly created environment in a separate adjacent directory and restores the previous directory only if neither has changed since the action. It refuses intervening edits. These preserved directories are recovery material, not automatically disposable caches.

## Selected GstarAssistant vendor package

For a damaged installation lacking a valid installed manifest, see
[legacy recovery](legacy-recovery.md). Explicit `recoverMissingManifest: true`
on Repair produces a concrete collision/preservation assessment against the
trusted candidate. Only a same-layout missing-file overlay with no differing
existing bytes can proceed; legacy layout and unresolved edits need migration.

Recipe `vendor-package` supports the reviewed GstarAssistant NSIS generator contract for R26/2026 and R27/2027. B27 remains discovery-only until package applicability is established. Select the actual case-local GstarCAD host by ID; its release, locale, path and executable checksum bind the target. The assistant destination must be separate from the CAD host. A per-release registration pointing to another installation refuses implicit relocation.

```json
{"recipe":"vendor-package","setupContract":"gstarassistant-nsis-v1","packageRelease":"R27","destinationPath":"C:\\Support\\Assistant-R27","hostTargetId":"target-1","expectedHostHash":"CAD_EXE_SHA256","packagePath":"C:\\Support\\GstarAssistant-setup.exe","expectedPackageHash":"INSTALLER_SHA256","expectedPublisher":"EXACT_TRUSTED_AUTHENTICODE_CERTIFICATE_SUBJECT","payloadManifestPath":"C:\\Support\\release\\payload-manifest.json","payloadManifestHash":"MANIFEST_SHA256"}
```

The package must have a valid Authenticode signature matching the explicitly selected trusted publisher, the actual product name from the reviewed generator, and the same declared version as the supplied manifest. The manifest must identify schema 2, `gstarassistant-v1`, `GstarAssistant`, the selected year and the complete catalog payload. `packageRelease` and the installer/manifest checksum association must come from the selected trusted release metadata or verified offline package. The executable signature/product-version fields alone do not attest the embedded target-year payload; do not pair independently found files based only on matching version numbers. Confirm this contract applies to that exact installer version; it is not a generic wrapper for any setup executable. Source files are `GstarAssistant/src/apps/GstarAssistant/nsis/generate_nsis_setup.ps1` and the setup wizard's `installer_impl.dart`.

Manifest input is bounded to 16 MiB and 100000 entries and fails instead of truncating a larger inventory. Entries must have unique canonical Windows file identities; absolute paths, traversal, ADS, device names, invalid characters and ambiguous trailing/empty/dot components are rejected. Every actual source/destination access also rejects reparse ancestry.

Default execution uses the vendor's visible UI and its agreement/licensing flow. Optional `"silent":true,"agreementsAccepted":true` is valid only when the user has explicitly chosen silent execution and accepted the applicable agreements in the surrounding host workflow. These values record that choice; they are not a new approval-token service. Arguments are fixed: `/TARGET=<2026|2027>`, `/TARGETPATH=<selected CAD root>`, `/INSTALLDIR=<selected assistant root>`, `/LOGFILE=<local case log>`, optional `/S`, and `/REPAIR` only for Repair. No arbitrary command or argument input exists.

Plans snapshot the exact installed file inventory and typed HKCU 64-bit installation/uninstall/startup values. Apply rechecks machine/user, host, source signatures/hashes, current registration and files, refuses an affected running process, and preserves local original files and registration in the case. Repair/Update refuse changed installed payload/configuration and collisions with new files until their preservation/migration has been explicitly resolved. Custom files outside the payload remain in place and are checked after installation. This is payload/registration reinstallation, not a cause-specific internal repair.

The plan also names the source-defined generated `app_icon.ico` and `uninstall.exe` files. Their existing bytes are included in the full originals snapshot, and the installer may replace them during a known-manifest repair/update. Missing-manifest recovery still requires explicit resolution of existing generated-file collisions.

Apply checks the complete supplied manifest and the source-defined HKCU64 installation, uninstall and startup relationships after the installer exits; Verify repeats those checks. The release, locale, version, loader paths, startup-key reference and exact quoted uninstaller location must agree with the selected target, registry types must match, and the generated uninstaller file must exist. Missing uninstall registration or stale cross-release metadata prevents verification even when payload files match. Runtime initialization and actual CAD host recovery remain pending until separately tested. Native exit 3010 is `restart_required`, including subsequent Verify. The reviewed NSIS prerequisite helper can internally consume a VC++ installer 3010 and later return 0, so prerequisite reboot readiness remains explicitly unverified even when the outer installer succeeds. The package can run its embedded VC++ installer `/install /quiet /norestart`, potentially requiring vendor UAC; this nonreversible prerequisite behavior is disclosed in the plan.

Automatic Undo is unavailable for vendor installers/prerequisites/migrations. The originals are reviewed recovery material, not a transactional rollback. A timeout or nonzero exit leaves `started` state and requires inspection of actual installation/child processes before recovery. Uninstall remains preparation/guidance only until an isolated supported native vendor-uninstall acceptance is available.

The handler has native process fixture checks, including 0/3010 and coherent fixture updates; those checks mock publisher/registry observations and do not establish actual product installation/recovery. Real vendor-package acceptance remains pending. Other product installers and migrations remain guidance-only. Existing administrator authorization never redirects per-user settings to a different administrator.
