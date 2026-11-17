# Standalone CLI distribution

`cli-package` supports a selected trusted **portable** `gcad-cli-v1` export from
the source contract in `IntelliDesign/scripts/products.py::export_runtime` and
`validate_runtime`. The CLI has a private `bin`, `resources` and `python`
distribution; it does not need a GstarCAD installation. This recipe does not
invent installer switches or install the GRX assistant package as a CLI.

```json
{"recipe":"cli-package","destinationPath":"C:\\Support\\gcad-cli","sourcePath":"C:\\Support\\trusted-cli-export","payloadManifestHash":"SHA256_OF_PAYLOAD_MANIFEST"}
```

Use `Plan -Operation Setup` without an existing target for a new dedicated
destination. For Repair/Update, select the saved `gcad-cli` target. A discovered
`bin/gcad-cli.exe`, `bin/gcad-tui.exe` or `bin/gcad-batch.exe` identifies its
strict package root. The plan retains that exact target identity. Setup requires
an absent destination. Source, case, destination and other selected installations
must be separate.

Supply the hash from the trusted release or a reviewed offline export. The
schema2 `payload-manifest.json` must declare `gcad-cli-v1`, product `gcad-cli`
and a reviewed target year, and completely account for the source files. The
source contract requires the headless backend, matching private Python/runtime,
Main Agent resources, automation libraries and architectural rules. No GRX
modules, secret-bearing startup files or unexpected extra source files are
accepted. Every listed file is checked; a hash alone does not authenticate its
publisher. Tree enumeration refuses reparse points and stops at 100000 entries
or 8 GiB rather than authorizing replacement from a partial inventory.

The preview compares recorded installed and candidate versions, identifies the
selected year/configuration and declares the release channel unknown because
the source manifest does not specify one. No newer version or published release
is invented for a versionless checkout. An explicit downgrade requires
`allowDowngrade:true` after the user has selected that downgrade. Cross-year
migrations require a separate destination until compatibility is established.

Repair/Update use the previous `.gcaddiag-cli.json` record. An unmanaged existing
export may instead be selected with `installedManifestHash` from its trusted
original package. Missing owned files can be restored, but changed shipped
configuration, skills or binaries are refused until preservation/migration is
resolved. Unlisted custom files are copied unchanged; collisions with new
package files are refused. The entire old directory is retained beside the new
one. Removed package binaries stay in that recovery directory rather than being
mixed into the updated runtime. Custom empty directories also remain in the
preserved directory.

Apply checks current state, verifies staged payload/custom files, checks that
the selected CLI/runtime is idle, then swaps the complete directory. It never
closes a process, edits PATH/MCP/provider settings, migrates external account
state or launches a model/runtime. Verification proves payload integrity and
custom-file preservation. A separate bounded runtime or MCP probe is required
for readiness, and product recovery remains distinct.

The idle check inspects process image paths and relevant inaccessible process
identities. A separate application may have loaded a private DLL without running
from this directory; a blocked swap remains a failed action requiring inspection,
not proof that the entire dependency tree was idle.

Undo preserves the new tree beside the installation and restores the old tree
only when both match their recorded hashes. It refuses intervening edits. A
failed/partial action retains staging and recovery state for inspection; do not
replay it or call that state a successful rollback. Restoring package bytes does
not prove that an external conversation database can reverse a schema migration.

The handler is validated with isolated native file operations and fixture PE
images that are never executed. Optional `tests/cli-package.tests.ps1
-RealPackagePath <export>` checks a full real local export read-only; it does not
publish or rebuild an SDK and is not a customer readiness claim.
