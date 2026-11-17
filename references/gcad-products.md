# Product and automation interpretation

`catalog/products.json` contains the reviewed NSIS payload baseline, R26/R27
metadata, B27 discovery caveat, startup values and state-root rule. The source is
the sibling GstarAssistant installer and app implementation, reviewed 2026-11-17.
This baseline is not a substitute for the selected release's signed package and
complete manifest. An unknown release is inspectable but has no guessed repair.

Compare registered root, file PE architecture/version, expected payload and
process image/modules. Registered, installed and loaded are independent states.
Use RuntimeGrxPath/GrxPath when registered; InstallDir can contain a `contents`
payload directory in installed packages even though the reviewed current NSIS
uses InstallDir/modules. Derive the payload root from a registered modules path,
retain the installation root separately, and compare startup LOADER with the
registered module. Catalog baseline differences are hypotheses until matched to
the actual installed package manifest; they must not force a layout migration.
Process records include PID, creation time, image and session; inaccessible module
lists are gaps. An executor's GCAD_STATE_ROOT does not prove the running CAD's
environment. Resolve effective product state from host evidence before changing it.

Python probes require the exact selected executable or explicit private runtime
DLL. The DLL probe performs isolated initialization and stdlib imports in an owned
child; it does not establish host extension binding. Automation first checks an explicit dedicated interpreter and
pygcadwin import, with no pip installation. Use a dedicated gcadclaw venv for setup,
never product-private or arbitrary global Python. Import success is not COM health.

An Attach probe requires a selected `progId` and `path` in the saved target. It
uses GetActiveObject in an owned PowerShell process, checks the returned FullName
against the selected executable and releases only its COM reference. It never
creates a server, inspects documents or calls Quit. Multiple instances with the
same executable still require session/instance evidence; attachment alone does
not establish the intended document or unique instance. Licensed host acceptance
is pending. With a selected ProgID, passive inspection records user and machine
CLSID/LocalServer32/InprocServer32 registrations in both registry views. Actual
server user/integrity must still be correlated with host evidence. Do not infer
an out-of-process COM mismatch merely from Python bitness, and do not
invent /regserver commands. Use a verified vendor registration mechanism.

Installed payload verification recognizes the reviewed installer schema2
`gstarassistant-v1` manifest, product GstarAssistant, target_year/version and its
filename→SHA256 object. It rejects escaping/reparse paths before reading files,
caps manifest JSON at 2 MiB, examines at most 2000 entries, and hashes up to
256 MiB with a five-second budget checked between files. Unchecked files remain
explicitly unverified/truncated. Unsupported manifest schemas are not guessed.
Reported checks compare local files to the local manifest, which does not itself
prove package authenticity; confirm publisher/package identity before repair.

## Prerequisites and standalone distributions

The catalog also carries the reviewed VC++ registration/build rule, standalone
CLI resource layout, and gcadclaw's declared Python requirement. Scan preserves
both registry views and typed access errors. A registered build meeting the
reviewed installer default does not establish that the selected package's
prerequisite is usable; its bundled redistributable can declare another minimum.

Scan InputFile fields `cliPaths` select absolute executables/distribution roots,
`pythonPaths` select interpreters, and `automationPaths` select dedicated virtual
environments. Accessible process/uninstall/PATH candidates retain their sources.
Missing resources and package metadata remain separate from startup or COM
readiness. `selectedInstallerPath` inventories one explicitly selected file for
a later evidence-backed maintenance plan.

## Component initialization and offline storage

`WebView` reports runtime metadata. `-Probe WebViewCreate` accepts InputFile
`webViewCorePath` and `webViewLoaderPath`, pointing to matching trusted Microsoft
SDK Core assembly/native loader; optional `webViewRuntimePath` selects a fixed
runtime. SDK binaries are not shipped or needed by Scan. The owned Windows
PowerShell STA child checks policy/environment overrides, uses a fresh profile,
verifies its effective location, and attempts environment/controller creation.
The tested executor creates an environment but controller creation returns
`0x8000FFFF`; this does not establish a product fault. The profile remains local
until owned browser-process exit can be verified.

`Storage`/`StorageWrite` inspect a selected directory and optionally create one
DeleteOnClose temporary file. `-Probe StorageStatus` accepts `storagePath` and
`storageSnapshot: true`. All source opening, writer exclusion, sidecar checks,
bounded copying and SQLite work occur in an owned child. SQLite opens only an
owned snapshot. Existing writers or WAL/SHM/journal state yield busy/checkpoint
needed; use the product's normal close/checkpoint workflow. This probe never
resets, removes or checkpoints the original database or its sidecars.

Optional `storageContract: "GstarAssistantSession"` and a verified selected
`expectedSchemaVersion` compare the snapshot's schema table to that expectation.
`schema_match`, `schema_mismatch`, `generic_integrity_only`, busy, denied, corrupt
and I/O results stay distinct. These checks do not attest product ownership,
installed-release compatibility or live host health. Only known snapshot files
are removed after the owned child exits; uncertain cleanup retains the local
snapshot and reports the gap. Snapshots are excluded from exports.
