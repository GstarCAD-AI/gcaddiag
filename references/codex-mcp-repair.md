# Repair one Codex stdio MCP launch reference

Use the `codex-mcp-stdio` Repair recipe only for an existing server entry in an
explicitly selected local Codex home user `config.toml`. An `AgentConfig` target identifies
that exact file. This recipe corrects only its `command` and `args` fields using
the installed native host's `config/batchWrite` API. It preserves environment
references/values, working directory, enabled state, other servers, model and
permission/policy settings. It does not start the MCP server or a model turn.

Provide the native Codex `.exe`, its reviewed hash, the affected user's existing
Codex home, an explicit project directory, and the checksum of the config file.
Select a real native launcher `.exe` and checksum plus its exact argument array.
Server names currently accept letters, digits, underscore and hyphen and must
match the existing TOML key's exact case. A differently cased selection is refused
before writing because it would identify a distinct TOML table. The
selected file must be the active native user layer at `<codexHome>/config.toml`; disabled/trust
gaps, managed/profile layers, shadowed launch fields and unavailable field
origins require local reconciliation before a repair can be planned. The tested
native API rejects project-file writes with `configLayerReadonly`; project
targets are therefore refused during planning. Project overrides still inform
effective-field inspection and prevent a misleading user-file repair.

```json
{
  "recipe": "codex-mcp-stdio",
  "serverName": "gcad",
  "codexExecutable": "C:\\Tools\\Codex\\codex.exe",
  "expectedCodexHash": "REVIEWED_CODEX_EXE_SHA256",
  "codexHome": "C:\\Users\\customer\\.codex",
  "projectPath": "C:\\Work\\selected-project",
  "expectedConfigHash": "REVIEWED_CONFIG_SHA256",
  "commandPath": "C:\\Tools\\selected-mcp.exe",
  "expectedCommandHash": "REVIEWED_LAUNCHER_SHA256",
  "arguments": ["--stdio"]
}
```

First supply `selectedAgentConfigPath` with that exact config path in a Scan
InputFile. `Scan -Profile ExternalAgent` records an explicitly selected
`AgentConfig` target. Use its case-local target ID with the repair options above:

```powershell
& "<skill>\scripts\gcaddiag.ps1" -Action Scan -Profile ExternalAgent -InputFile "C:\Support\config-selection.json" -Output "C:\Support\mcp-case"
& "<skill>\scripts\gcaddiag.ps1" -Action Plan -Operation Repair -Case "C:\Support\mcp-case" -TargetId selected-config-id -InputFile "C:\Support\mcp-repair.json"
```

Use the generated plan with the shared Apply/Verify/Undo interface on the
same local case and affected user. The concrete plan names the two changed keys,
launcher and argument count. Exact arguments stay in a private case-local
launcher specification; review that selected input before Apply. Original config
bytes, which can contain secrets, are preserved privately before writing.
Default redacted exports exclude the specification and original backup.

Native `config/read` supplies the selected layer version and effective field
origins. Apply rechecks the config/executable hashes, case identity and native
version, then uses `expectedVersion` and `reloadUserConfig:false`. It rereads
through the native parser and compares all unrelated layer/effective settings.
The write must report `ok`; an overridden write is not successful recovery.
No TOML regex patch or entire-server replacement is used. Existing Codex sessions
may need normal reconnect/restart; permissions and enabled state are retained.

Verify establishes configuration repair only. Explicitly retest MCP
initialization/discovery in the intended host afterward. A launcher file/hash
alone does not establish package trust, dependency readiness or protocol health.

Undo restores exact original bytes only while the written config remains
unchanged and the original backup matches its recorded checksum. Intervening
edits are preserved. A partial/failed/native-timeout write leaves a started
action and private originals for inspection; it is not blindly retried or
automatically reversed. App-server reads/writes are bounded to 25 seconds and
1 Mi characters per call. Native descriptions, configuration values and error
text never enter maintenance results; host cache/log initialization may occur.

The installed app-server schema defines `config/read`, `config/batchWrite`,
per-file versions and exact field edits. `tests/codex-mcp-repair.tests.ps1` uses
isolated host configuration and an explicit native executable. It verifies
preserved unrelated settings/comments, environment/cwd, stale-plan refusal,
effective native reread, exact original restoration and intervening-edit refusal.
The test does not modify personal Codex configuration or invoke a model/server.
