# Repair, cleanup and reversal

## Completed installer file cleanup

Scan can add one `InstallerPackage` target from InputFile `selectedInstallerPath`.
Plan Cleanup with `recipe: "installer-artifact"` and `completedPlanPath` pointing
to this same case's completed vendor-package plan. The handler rechecks the
signed installer hash/publisher, completed local state/journal, declared restart,
and installed payload/registration. It refuses installation roots, recovery
material, running/locked executables, and reparse paths. The preview identifies
the exact file, ownership receipt, size and reversibility. Sibling files and
unknown extraction/download directories are preserved.

Apply quarantines that one file beside its original path. Verify rechecks the
installed product and quarantine; Undo restores only unchanged quarantine to an
absent original path. Both refuse a running quarantined executable. Shared
identity checks and journaling remain in the lifecycle executor. Unknown
obsolete registry values and duplicate skills without effective discovery stay
guidance-only. Vendor uninstall remains separately selected and execution
acceptance is pending.

Use evidence to choose one selected target and remedy. `Plan` describes exact file changes and hashes, affected machine/SID, process expectations and verification limits. `Apply` checks current machine/SID, originating local case, target tree and source package integrity. Unsupported product recipes and Uninstall produce `guidance_only`; they cannot be applied.

`skill-package` supports Setup, Repair and Update for a complete trusted local skill package. It backs up exact overwritten bytes or records absence before each change, journals started/completed actions in `actions.jsonl`, and writes a per-plan state record. A source path is never a shell command. No arbitrary executable or elevated command runner is exposed.

For a selected native Codex stdio server's stale launcher/arguments, use
[Codex MCP repair](codex-mcp-repair.md). It edits the specific fields through the
installed host's configuration API, preserves other settings and supports
unchanged-only Undo. It does not start the configured server.

`automation-venv` supports Setup/Repair/Update of a specifically selected dedicated environment using a standalone base Python and trusted local wheels. See [setup-update.md](setup-update.md). It preserves prior environments whole instead of deleting or mixing runtime files, returns the exact new launcher, and distinguishes stdlib, package import and pending CAD attachment. Undo preserves both sides and refuses intervening changes. An unsuccessful creation/installation leaves `started` state and local bounded probe logs; inspect actual state before restoring the preserved environment or making another plan.

`vendor-package` executes only the reviewed GstarAssistant R26/R27 NSIS contract with a trusted signed package, matching complete release manifest and selected CAD host. It saves local original files and typed selected registry values, rejects unresolved custom changes before overwrite, and verifies complete installed payload and registration rather than trusting exit 0. The actual vendor/prerequisite/migration operation has no automatic Undo. Native fixture execution is verified; real vendor product acceptance and original host recovery remain pending. See [setup-update.md](setup-update.md) for exact options and UI/agreement/reboot behavior.

After Apply, Verify distinguishes file integrity from actual external-host discovery/operation. Undo checks every written file still matches its post-action hash and every original backup matches its original hash, then restores exact bytes/absence. Any intervening edit refuses the entire undo before writing. Backups remain in the local case and must not be shared. A partial/interrupted action remains `started` with saved originals; inspect actual files and journal, then resolve the interruption before generating a new plan. Do not blindly replay.

Cleanup recipe `old-case` supports only an explicitly selected old gcaddiag case directory. It checks the case identity and allows only known case report/record filenames, refusing drawings and custom files. The current active case, any reparse ancestor, or a reparse point anywhere inside the selected tree is refused. Apply moves the verified tree to a unique same-parent quarantine; Verify checks content and original absence; Undo restores only if the original location is still absent and quarantine content unchanged. Quarantine is reversible and releases no disk space until a separately authorized permanent removal. The caller must choose an old case that is no longer in use. No product registration/cache cleanup is inferred from names or age.

Example Cleanup options: `{"recipe":"old-case"}` with a case-local selected Case target whose `path` identifies the old case. No recursive product deletion is implemented.

Uninstall is separate from cleanup. The reviewed GstarAssistant NSIS uninstaller recursively removes its installation directory. Preserve or resolve drawings, templates, custom plugins, skills and credentials from a custom install location first; verify the other installation is unaffected. Actual vendor-uninstall execution is pending isolated supported-installation acceptance and is not advertised as verified. Use its supported UI/arguments only after installed-version validation. Global registry cleaning, blanket database/cache reset, TLS/security-policy changes and generic `/regserver` guesses are unsupported.

`Plan -Operation Uninstall -Case <local-case> -TargetId <assistant-id>` now
inspects the selected GstarAssistant installation. It saves a private metadata
inventory in `plan.json` and adds preservation counts and unresolved checks to
the report. It distinguishes manifest-listed files, unlisted files and likely
user/configuration data, including custom files inside a legacy `contents`
payload. Installed-manifest membership does not authenticate bytes or make
settings disposable. No contents are copied, backed up or removed by planning.

Preparation checks exact registered `uninstall.exe` association, other-target
overlap and R26/R27 registration sharing a removal root. The source uninstaller
checks R27 before R26 and uses recorded `GcadProductRelease`/`GcadLocale` for the
startup key; the assistant release alone cannot identify that key. Missing or
mismatched registration remains unresolved. Inventory does not follow reparse
entries and stops at 5000 entries or a 10-second work bound. Inaccessible or
truncated contents remain preservation gaps. Preserve reviewed files outside
the entire recursive removal root, confirm the installed vendor contract and
recollect current state before any future uninstall. All such plans remain
`guidance_only`; Apply refuses them.

## WebView profile failures

The reviewed `GstarAssistant/src/apps/GstarAssistant/assistant_app.cpp`
`ResolveGstarAssistantAppDataRoot` uses an absolute `GCAD_STATE_ROOT` override or
`LOCALAPPDATA/GstarAssistant/<release-year>`. The `browserDirectory` construction
near lines 4161–4164 then requests a **new** `webview/gstarcad-<uniqueFileToken>`
directory for each host instance. This source does not reopen a fixed profile
whose reset would provide a cause-specific repair. Confirm the selected installed
package follows this contract before applying that interpretation.

In `assistant/src/assist_webview/webview_impl.cc`, the destructor near lines
258–282 writes `<profile>.browser` with the browser PID and process creation
identity during teardown. Product code removes the profile after that browser
exits; the constructor near lines 143–160 retries previously exited markers.
An orphan marker therefore concerns a prior instance's cleanup. It does not
establish that another running host owns or will reuse that profile. Preserve
browser data while the process is live or its lifetime cannot be verified.

`webview-profile` remains guidance-only. Do not infer mutation authority from a
directory name, caller-asserted root, executor environment or uncorrelated log.
Collect the selected host's effective state root, actual user-data folder,
installed package semantics and browser PID/start identity through supported
diagnostics. A separate owned temporary-profile WebView creation probe can
distinguish runtime startup failure from a selected profile problem. Resetting
an unverified profile may discard cookies/sign-in state and does not establish
host recovery. Confirmed exited-profile disposal is a separate owned cleanup
question; do not manufacture a reusable-profile reset recipe from this source.
