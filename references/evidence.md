# Cases, reports and privacy

Diagnostics generate a user-facing `report.md` automatically. Its summary leads
with the observed outcome, main findings, unresolved checks, next steps and
maintenance verification. Crash cases include recovered exception-thread
callstacks or an explicit missing-stack reason; detailed evidence remains below.

Offline `DumpAnalysis` writes a new `kind: analysis` case. Supplied customer
context/target IDs remain intact, while `analystExecution` records the separate
local executor. It cannot authorize live maintenance. The original bundle/dump
is not overwritten; exports include sanitized report/structured stack facts,
never raw dumps, debugger sidecars, startup files or TRACE originals.

The entry point emits sanitized JSON on stdout. Exit 0 means the requested
operation completed, including an explicit unavailable/unsupported result;
exit 2 means command/input/identity/access failure. Inspect evidence statuses
and action verification separately from exit code.
Failure output contains fixed guidance and exception type/category/HResult only.
Parser messages can embed a complete private input, so they are withheld even
when input fails before a case exists; failed reads do not modify imported cases.

`case.json` has formatVersion, collectorVersion, caseId, context, targets,
observations, findings and completeness. Each observation has a case-local ID
and UTC collection time plus its source/status. Sources can report their own
native errors and timestamps. The case stays partial while targeted runtime,
host or access evidence is unavailable. IDs are scoped to one case.

`report.md` and stdout use the same conservative public projection: arbitrary
observed data, raw logs/XML, error details, command arguments, environments and
message bodies are omitted. Obvious credential assignments, headers, URL
credentials, common API tokens, email addresses and user-profile names are
redacted from remaining strings. Machine names, user SIDs and profile names use
consistent pseudonyms. Installation paths outside profiles remain useful support
identifiers; inspect those before sharing if personally identifying. This favors
confidentiality over exhaustive agent-visible diagnosis.
Do not send local case.json or lifecycle backups to a model. A user can inspect
local details and provide a selected sanitized fact when necessary. Restrict
access to the case directory using normal Windows permissions.

Export creates a ZIP containing only public case.json and report.md. It excludes
plans, originals, journals, raw logs and other files even if placed in the case
directory. No upload is performed. Public bundles can be read offline with
Report/Compare, never used as authority for target changes. A new local scan
must establish identity/current state before constructing a live plan.

Compare uses version, architecture, registry scope/view, file/payload and probe
status records. It ignores evidence IDs, collection times, PIDs and user identity;
paths are compared only for the same machine and affected user. It reports
additions/removals without comparing omitted local detail, inferring a cause or
generating mutations. Release differences remain explicit for interpretation.

To request a bounded subset, supply `-Action Report -InputFile query.json`, where
the file contains `{"evidenceIds":["evidence-1","evidence-2"]}`. The complete
sanitized report remains local. Large stdout results return target/finding
summaries and a truncation indicator instead of flooding agent context.
