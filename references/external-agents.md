# External agents and MCP

gcaddiag uses the external host's ordinary shell and authorization. It never starts an internal GCAD model conversation. Live commands require native Windows access; a Linux/cloud agent can analyze a saved redacted case.

## Installation routes

For Codex, copy the complete `gcaddiag` folder into a selected project or user `.agents/skills/`. Keep scripts, catalog and references together. Invoke `$gcaddiag` in a fresh session and collect a scan. Directory presence is only a discovery candidate until the host lists and invokes it. See [Codex skills](https://learn.chatgpt.com/docs/build-skills).

For WorkBuddy code projects, copy it into `.codebuddy/skills/gcaddiag/` under the selected project. WorkBuddy documents project skills and project-over-user precedence for code development. This does not establish the same scope in every task mode. See [project configuration](https://www.codebuddy.cn/docs/workbuddy/From-Beginner-to-Expert-Guide/Function-Description/Project).

For local import, build the ZIP using `packaging/package.ps1`, then use the installed WorkBuddy application's Add Skill/import UI. Verify the application's accepted archive layout and that resources survive import; real import/invocation acceptance is pending. See [skills](https://www.codebuddy.cn/docs/workbuddy/From-Beginner-to-Expert-Guide/Function-Description/Skills-Market). Open Platform publication is a separate operation requiring author/publication details; the packager does not publish or invent them. See [Open Platform](https://open.workbuddy.cn/en/docs/skill).

## Actual context before configuration

Check machine, SID, profile, session and process integrity. HKCU belongs to the executing account. Agent sandbox elevation is not proof of Windows administrator rights. If the affected account differs, report the gap and collect through a permitted affected-user command. Do not change global execution policy or application control.

`Get-GdiagAgentEvidence` inventories user/project `.agents/skills`, selected project `.codebuddy/skills`, and explicit `skillRoots`. It reports missing local Markdown resources and duplicate names without deleting either copy. File inspection leaves disabled settings, organization policy, trust and ancestor-project discovery unknown; use the selected host's native view for those outcomes.
Each skill document is checked against a 1 MiB file bound before reading and a
262144-character decoded-content bound; oversized documents remain collection
gaps without loading their complete contents.

For Codex, opt in to native `app-server` discovery with InputFile
`codexSkillDiscovery: true`, an explicit `codexExecutable` and existing
`projectPath`. Optional `codexSkillPath` selects one absolute `SKILL.md` path to
check; optional `codexHome` selects an existing home for this child only. The
collector sends only initialize/initialized and `skills/list` with a fresh scan
for the selected project. It reports native enabled/disabled state, scope,
discovery/load-error counts and whether that exact selected path is returned.
An existing file outside discovery is different from a missing file. Native
discovery does not prove invocation permissions or select a duplicate for cleanup.

```json
{"codexExecutable":"C:\\Tools\\codex.exe","projectPath":"C:\\Work\\selected-project","codexSkillDiscovery":true,"codexSkillPath":"C:\\Work\\selected-project\\.agents\\skills\\gcadclaw\\SKILL.md"}
```

Use that InputFile with `Scan -Profile ExternalAgent` and a new local output
directory. The affected user must match the executor. This does not start a model
turn, invoke skill content or write host configuration. Normal host startup may
create its own cache/log files. Output is capped at 256 Ki characters and 25
seconds; unsupported host API/configuration, native load errors and timeouts are
reported without emitting descriptions, prompts or raw error text. The owned
app-server is closed after discovery. Existing running agents may have older
cached state; fresh native discovery is not a claim about their session state.

`tests/integration-skills-native.tests.ps1 -CodexExecutable <native-exe>` verifies
the shipped runtime path using isolated host configuration: a disabled repo
skill, malformed frontmatter, and an existing file outside host discovery.
The test also checks Chinese/spaced project paths, unchanged selected files and
host configuration, and exclusion of skill bodies/descriptions from evidence.

Select InputFile `host: "WorkBuddyProject"` together with `projectPath` to inspect the documented WorkBuddy code-development scope. In this selected mode the adapter also inspects the affected user's `.codebuddy/skills`, reports same-name project-over-user selection from the documented precedence, and inspects user/project/settings.local JSON candidates. This scope comes from WorkBuddy's own project documentation linking to the [CodeBuddy directory contract](https://www.codebuddy.cn/docs/cli/codebuddy-dir). It is not applied to unrelated WorkBuddy task modes. Command-line overrides, policy and live discovery still need the actual host. Missing-resource diagnosis attaches to the actual selected copy, even when a same-name user copy exists.

The isolated Windows acceptance fixture creates a trusted recorded project skill with the `skill-package` Setup recipe, removes one referenced resource, observes the selected project copy as incomplete, repairs that exact copy through the shared `skill-package` Repair recipe, verifies hashes and reinspects completeness. Its unrelated project setting and same-name user skill remain intact. This is verified file-level integration correction; actual WorkBuddy invocation remains pending. Unmanaged/local edited skill installations require reconciliation before repair, not overwriting them to match a downloaded bundle.

Codex MCP settings are in its user `config.toml` (or configured `CODEX_HOME`) and trusted project `.codex/config.toml`. The script extracts section names only; it has no full TOML parser. Use the installed host's `codex mcp list --json` and configuration diagnostics to validate full syntax and effective settings. Never emit that raw output to model context without redaction. No universal WorkBuddy user configuration path is assumed. Pass an actual selected JSON configuration path under `configPaths` if needed. JSON parsing establishes syntax, not effective host precedence. See [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

For native effective MCP inspection, supply `codexExecutable` as an absolute installed native `.exe` path (not a shell shim), optionally `projectPath` for the selected project. Explicit `codexHome` selects an existing home for that child process only, useful for isolated configuration acceptance without changing personal settings. The collector invokes only `mcp list --json`, bounded to ten seconds and 64K characters of output, then projects launcher-resolution, enabled and authentication statuses without environment values or credentials. A rejected configuration, timeout and invalid native JSON remain explicit gaps. Personal-home inspection timed out in the development environment. A subsequent isolated-home native acceptance parsed the actual effective MCP configuration, diagnosed its missing launcher, reread a corrected selected launcher successfully, and verified that fixture's initialize/tools-list handshake through the script route. This did not invoke a model, modify personal settings, or prove actual host skill invocation. Run the optional native test with `tests/integration-native.tests.ps1 -CodexExecutable <absolute native exe>`; it retains isolated evidence under tests/.tmp-codex-native-* and never enters distribution packages. WorkBuddy/CodeBuddy were absent from executable and running-process discovery during the environment check.

## Bounded stdio protocol check

Supply an explicitly selected launcher through `-InputFile`; never execute a command copied from logs or imported cases. Launching an MCP server may itself initialize its application, so verify its intended read-only use before invoking this probe.

```json
{
  "mcp": {
    "transport": "stdio",
    "command": "C:\\Tools\\selected-server.exe",
    "args": ["--stdio"],
    "cwd": "C:\\Tools"
  }
}
```

The probe sends `initialize`, `notifications/initialized`, and `tools/list`. It never calls a discovered tool. It requires newline-delimited JSON-RPC, terminates its owned launcher on completion/timeout, and reports protocol or startup failures without returning stderr contents. Use direct executables that do not spawn detached children; child-tree ownership/termination and remote HTTP/OAuth diagnostics remain host facilities. A script handshake does not prove the agent's inherited environment, credentials or host configuration works. Retest through that host after a scoped repair.
The implemented protocol version is `2024-11-05`. A different negotiated version
is unavailable for this probe; it does not imply that the server is broken.
The probe validates response envelopes, declared tools capability and required
tool-list fields under that version's [lifecycle](https://modelcontextprotocol.io/specification/2024-11-05/basic/lifecycle)
and [tools schema](https://modelcontextprotocol.io/specification/2024-11-05/server/tools).
Servers without the tools capability have discovery marked not applicable.
When a valid response includes a continuation cursor, only the first page is
counted and discovery is labelled `first_page_succeeded`.

## Connectivity

An explicit HTTPS `-Endpoint` records UTC (without claiming trusted clock synchronization), default .NET proxy type and configured proxy environment-variable names, then performs bounded asynchronous DNS and unauthenticated HEAD without redirects, query parameters or body. DNS gets at most a quarter of the shared deadline so a proxy which resolves remotely can still be tested. HTTP response waiting is asynchronous with abort at the deadline. DNS, HTTP/native errors and stage timeouts remain separate.

Set InputFile `directNetworkStages` to `true` only when a direct network route is intended. This adds a first-address TCP connection and normal-validation SslStream TLS handshake, labelled explicitly as bypassing the HTTP proxy; it does not modify proxy or trust policy. Failed TLS does not imply a certificate root cause without native supporting evidence. Script DNS, direct socket/TLS, effective .NET HTTP route, external agent route and GCAD route remain distinct.

HTTP 401/403/407 carry different sign-in/access/proxy next steps; 429 identifies quota/rate-limit investigation. Streaming and model capability remain untested. No paid model request, global proxy reset, certificate installation or TLS bypass is performed. Development evidence on 2026-11-17: `.invalid` DNS timeout plus HTTP SendFailure; `https://api.openai.com/v1/models` resolved, direct TCP succeeded, direct TLS returned IOException, and the effective HTTP route returned 401 without credentials. This verifies error separation and a real auth response, not GCAD/agent transport readiness.
