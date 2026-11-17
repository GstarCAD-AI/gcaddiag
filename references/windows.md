# Windows evidence

The collector uses explicit Registry32/Registry64 views of HKLM and the affected
user's loaded HKEY_USERS hive. A denied/unloaded hive is a collection gap. It does
not load hives, use Win32_Product, inject modules, or diagnose HKCU as another user.
Each target retains its registry values, kinds and raw strings. Other-user paths
containing environment variables remain unresolved rather than expanding under
the executor. Multiple release/locale/view candidates deliberately remain distinct.

Application, System, CodeIntegrity, AppLocker and Defender queries use the case
interval (default 30 minutes, maximum 24 hours), at most 100 records per channel.
Disabled, empty-completed, inaccessible, unavailable and truncated are separate
results. XML fields are evidence, never commands. Publisher PID is not fault PID.
The timeline labels exact target executable matches separately from path/PID/
observed process-lifetime matches, retaining report/activity IDs in local fields.
A PID-only match stays unattributed; events before the observed process's start
cannot match its lifetime. Correlation findings remain hypotheses. Audit records,
common Windows fault modules and missing payload are not proof of enforcement or
root cause. CodeIntegrity 3076/AppLocker 8003/8006 are audit; CodeIntegrity 3077/
AppLocker 8004/8007 are enforcement records, requiring identity association.
Defender detection 1116 does not establish quarantine; 1117 is an action record.

Product logs use the reviewed `BuildAssistantStorageRoots` layout:
state root / users / account / sessions, optionally session subdirectories, and
only `debug.logs` and `webview-bridge.log`. The collector reads at most 20 users,
20 session directories per user and eight files, each a 64 KiB tail. It does not
open drawings/databases, recursively search the profile or follow reparse roots.
An absolute executor GCAD_STATE_ROOT is a candidate only when executor and affected
SID match. Otherwise the affected profile's AppData/Local/GstarAssistant/year is
the default candidate. Neither proves the running host's effective environment.
File modification inside the incident interval is labeled separately from entry
timestamps; outside-interval logs remain baseline and do not prove association.
Raw log tails stay in local case.json and are untrusted data; public/export views
retain only statuses, byte counts and collection/interval scope. Logs can contain
secrets and user messages, so do not share local case.json directly.

Runtime probes run fixed code in an owned child with a 1–60 second limit. The
probe does not launch CAD and only that child is killed on timeout; descendant
termination is not claimed for arbitrary native DLL behavior. Output is capped
at 8192 stdout characters / 4096 stderr characters using concurrent 1024-character
reads, including output without newlines. Overflow stops the owned child and
returns `truncated`; it never accumulates an unlimited output string and clips it
afterward. No probe loads a GRX into the collector. Metadata
and Python startup are separate from host binding.

`Native` loads an explicitly selected nativePath DLL in the owned PowerShell
child using LoadLibraryEx DLL_LOAD_DIR|DEFAULT_DIRS. It returns actual Win32 load
codes; error126 does not identify which transitive dependency is missing. It
refuses GRX loading. `PythonDll` additionally checks Python's exported isolation,
ignore-environment, no-site and no-bytecode flags, supplies an explicit runtime
home, initializes Python, imports sqlite3/ssl, and finalizes. It does not execute
site .pth files or import pygcadwin. Runtime falls back to this isolated private
DLL probe when the selected GstarAssistant runtime has a DLL but no executable.
`NativeChild.ps1` uses built-in .NET Add-Type only inside the owned child; policy
or compiler denial remains a probe failure while basic collection stays useful.
The test startup closure is Windows PowerShell/.NET/kernel32, independent of GCAD.

`WebView` inspects the documented Evergreen pv registration in explicit machine/
affected-user views. A nonzero version is advertised runtime metadata, not browser
controller/environment creation or product profile verification. Fixed Version
runtimes are not inferred absent from Evergreen keys. No independent product
WebView creation helper was found in the reviewed source tree, so creation remains
pending. See [Microsoft distribution detection](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution#detect-if-a-webview2-runtime-is-already-installed).

`Storage` requires explicit storagePath and inspects directory metadata only.
`StorageWrite` is an explicitly selected permission test using one new random
DeleteOnClose file, readback and disposal in that directory; it does not create a
missing state root, inspect or modify a database, or establish another user's
access. Reparse ancestors are rejected. The reviewed product storage_probe.cc
distinguishes compatible/missing/incompatible/busy/permission/corrupt/I/O through
its SQLite API, but no independent callable installed endpoint was found. Those
database outcomes remain unverified rather than inferred from a directory probe.

For reproduction use Record's foreground interval and cancellation; retain gaps
when channels are blocked. Advanced dumps/traces require a concrete unresolved
question and a separately selected collection. No monitoring service is installed.
