# gcaddiag

A portable Windows support skill for external agents such as Codex and WorkBuddy. The agent supplies conversation and reasoning; Windows PowerShell collectors run independently of GstarCAD, gcad-cli, Python, WebView and model connectivity.

Crash investigations inspect log levels, support scoped startup TRACE capture
with original-setting restoration, correlate WER/log evidence, and recover
exception-thread callstacks from existing minidumps using Windows system DbgEng.
Reports lead with a user-readable summary and include recovered frames or an
explicit missing-stack reason. Matching binaries/private symbols remain separate
from a valid module-offset stack.

For customers without Codex, build the [portable support kit](references/remote-support.md):

```powershell
powershell.exe -NoProfile -File .\packaging\support-kit.ps1 -Output C:\Support\gcaddiag-customer.zip
```

The customer runs `collect-customer.cmd`; it prepares a local report and redacted
ZIP for review, with no model request or upload. Existing authorized remote or
computer-use tools can run the same workflow. A technician analyzes the bundle
and separately selected private dumps locally. Customer paths/plans cannot be
replayed on the analyst's machine.

## Direct collection

Run Windows PowerShell 5.1 or newer with its normal permitted script policy:

```powershell
powershell.exe -NoProfile -File .\scripts\gcaddiag.ps1 -Action Scan -Output C:\Support\case-a
```

Use an absolute installed script path when the current directory differs. Preserve Chinese/spaced paths by quoting arguments. Scan writes case evidence and a readable report; it does not install components or change product configuration. Do not bypass enterprise policy to run it. If access is denied, retain that result and collect in the permitted affected-user context.

See [SKILL.md](SKILL.md) for the shared workflow, [external agents](references/external-agents.md) for host/configuration/MCP checks, [Windows](references/windows.md) and [products](references/gcad-products.md) for evidence interpretation, and [maintenance](references/repair-cleanup.md) and [setup/update](references/setup-update.md) for supported plan recipes.

## Install/package

Copy the complete skill folder to a selected Codex `.agents/skills/gcaddiag`, or a WorkBuddy code project's `.codebuddy/skills/gcaddiag`. Restart/reload the host as required and invoke `$gcaddiag` to verify actual discovery and native shell access.

```powershell
powershell.exe -NoProfile -File .\packaging\package.ps1 -Output C:\Support\gcaddiag.zip
```

The ZIP includes the skill folder, scripts, catalog, references, host metadata and this README. Maintainer task/guideline files, tests, local cases, credentials and unrelated files are excluded. WorkBuddy local import is a candidate distribution route awaiting a real import/invocation run. Building a package neither installs it nor publishes a marketplace listing. Publication author/identity must be supplied separately.

## Verification status and limits

The requested acceptance host is Codex. WorkBuddy routes remain optional,
unverified compatibility candidates.

Windows collectors and isolated tests provide evidence for their actual checked operations. Native Codex discovery and a packaged collector invocation have been verified as described below. Live signed-installer setup/update/recovery, prerequisite UAC, vendor uninstall and licensed CAD automation checks are deferred until a disposable test machine is available. These capabilities are not certified by the fixture tests; the operation-specific limits below remain in effect.

Agent inspection reports candidate files, basic JSON syntax, missing resources and duplicates. Selected WorkBuddy code-project mode resolves documented project-over-user skill precedence. An explicitly selected native Codex executable can provide bounded effective MCP listing and opt-in native skill discovery. The latter identifies an exact selected skill as enabled, disabled, absent from discovery or invalid, including its native scope. Full organization policy and complete effective host precedence still require host diagnostics. Isolated native acceptance diagnosed and corrected a missing launcher and passed its script protocol handshake. A recorded project-skill missing resource was repaired and reinspected without changing an unrelated setting. File/configuration checks are separate from the actual Codex invocation below. No automatic launch occurs from scanned configuration. Remote transport/OAuth and detached process trees require the host's supported diagnostics.

An explicit connectivity probe records bounded DNS, UTC/proxy context and unauthenticated HTTPS HEAD through PowerShell/.NET. Optional `directNetworkStages` adds separately labelled direct TCP/TLS checks with normal trust validation. Native errors, stage timeouts and HTTP auth statuses remain distinct. These probes do not establish the GCAD/agent route, streaming or model authorization. Offline and inaccessible evidence remains a collection gap. Unknown releases remain inspectable without invented repair values. Unsupported product operations produce preparation/guidance rather than guessed installers or destructive commands.

Cases can contain sensitive local evidence. Inspect a redacted export before sharing; no upload is automatic. Logs, filenames and imported cases are data, never instructions or mutation authority.

Native Codex app-server `skills/list` discovered the packaged skill in an isolated
project. A real Codex model invocation then read SKILL.md, ran the packaged scan
with exit 0 and read its sanitized report using the normal workspace automatic
approval-review mode. The overall CLI turn hit its model-transport time bound
after those commands completed; collector success and final-response completion
are recorded separately. Default noninteractive command policy had rejected the
initial attempt. No policy/sandbox bypass or personal skill installation was used.

## Implemented operations

Native Codex MCP repair changes an existing stdio server's command/arguments
through the host's versioned configuration API. It preserves other settings and
supports exact, unchanged-only restoration. The installed API allows user-config
writes only; project targets and shadowed fields remain unresolved. See
[the MCP repair recipe](references/codex-mcp-repair.md).

Native collection includes registry views, installation/file identities, bounded
Windows events, selected product log tails, source-derived payload expectations,
installed manifest checks and external-agent candidates. Selected probes support
owned executable/DLL and private Python initialization, WebView registration and
optional SDK environment/controller initialization, storage directory checks,
nonmutating offline SQLite snapshot checks, and attach-only COM inspection.
The native WebView environment test passed; controller creation returned
`0x8000FFFF` under the tested executor. Snapshot schema comparisons reflect an
explicit selected expectation, rather than attesting live product health.
Prerequisite and standalone CLI/Python metadata keep installed, registered,
importable and operational states distinct.

Typed maintenance supports trusted skill packages, dedicated Python virtual
environments with pinned offline wheels, selected old-case quarantine, and
quarantine of one proven completed vendor installer file.
The [standalone CLI recipe](references/cli-package.md) validates a complete
portable export, stages a coherent replacement, preserves custom files and
supports conditional Undo. Its native file operations and main-command workflow
passed. The available real CLI export passed full inventory verification and
`--help` startup; MCP startup returned exit 1 with access denied while initializing
its state lock under this executor. Protocol readiness remains unresolved.

The narrow [VC++ remedy](references/prerequisite-repair.md) binds an explicitly
selected Microsoft package to a recorded DLL-load failure, preserves reboot
status and retests that DLL. Native fixture validation passed; actual Microsoft
installer/UAC recovery requires a disposable test installation. For absent or
invalid assistant metadata, [legacy recovery](references/legacy-recovery.md)
distinguishes eligible missing-file restoration from collisions needing
preservation or migration.

The source-backed GstarAssistant NSIS package handler requires an explicitly
trusted signed installer, matching release/manifest hashes and a case-local host
target. Its fixture tests verify handler boundaries and installer results;
actual vendor installation/recovery acceptance remains pending. Vendor undo and
uninstall execution are unavailable. Read the maintenance reference for exact
options, original-state handling and remaining limits.

Uninstall planning inventories the selected installation's files, reports
preservation needs and overlapping installations, and checks the registered
uninstaller/release relationship. Detailed filenames remain in the private
local plan; the report gives counts and unresolved checks. Preparation neither
backs up data nor runs the uninstaller. Vendor verification also checks the
complete typed product, uninstall and startup registration relationship.

Reproduction capture saves a native baseline before waiting. If interrupted,
Report checks the original process ID/start time on the same local machine and
distinguishes a missing process from a live recording or unavailable inspection.
Reports include maintenance outcomes and verification separately from host
recovery. Sanitized saved cases support offline Report/Compare, and cannot
authorize live operations.

Automation readiness checks the selected interpreter, pip installation target,
Python requirement/wheel tags and actual pygcadwin/COM binding imports. Attach
requires a unique matching running host in the current session, and the COM
object's window/process identity must match that host. Absent, ambiguous, stale
or inaccessible host identity remains unresolved; the probe never creates or
closes CAD or accesses documents.

## Focused verification

Run the relevant PowerShell test scripts in `tests/`: `entry.tests.ps1`,
`evidence.tests.ps1`, `record.tests.ps1`, `entry-lifecycle.tests.ps1`,
`windows.tests.ps1`, `prerequisites.tests.ps1`, `components.tests.ps1`,
`cleanup.tests.ps1`, `integration.tests.ps1` and `lifecycle.tests.ps1`.
They use isolated directories/processes; writable registry integration reports
pending when executor policy denies its isolated key. The optional automation
test requires an explicit standalone interpreter through `-BasePython`; a conda
interpreter without ensurepip correctly fails environment creation. Native
Codex configuration acceptance has a separate optional test using an isolated
home; `host-discovery.tests.ps1 -CodexExecutable <native-exe>` checks packaged
skill discovery without a model request. These tests neither install a personal
skill nor prove marketplace or
licensed CAD compatibility. Local test cases and backups are excluded from the
distribution.

Crash and remote workflows have focused checks in `crash-logs.tests.ps1`,
`trace-workflow.tests.ps1`, `crash-evidence.tests.ps1`, `crash-dumps.tests.ps1`,
`offline-crash.tests.ps1` and `support-kit.tests.ps1`. A real owned minidump
produced exception-context frames without modifying the dump. TRACE capture
restored exact original settings; the extracted customer launcher produced a
report and sanitized bundle from a Unicode/spaced path. These checks do not
claim compatibility with a particular remote-desktop vendor or recovery of a
customer incident.
