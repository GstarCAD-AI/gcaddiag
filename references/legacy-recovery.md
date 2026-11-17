# Missing or invalid installed manifest

A damaged installation or older layout can lack the installed manifest while
still containing customer configuration and custom plugins. Do not create a
manifest that pretends those current bytes are a trusted vendor release.

For an explicit same-release `vendor-package` Repair with
`recoverMissingManifest: true`, retain the normal trusted signed installer,
matching candidate-manifest hash, host identity and release checks. The recovery
assessment compares that validated candidate with the exact current snapshot.
It reports missing files, matching files, differing collisions and unlisted
files to preserve. Detailed filenames/hashes remain private in the plan's
`observed` data; agent-visible output contains counts and next steps.

An overlay can proceed through the existing vendor executor only when the
registered payload root equals the installation root and every existing
candidate file already matches the candidate hash. Missing files can then be
restored without replacing unknown edits. The executor still preserves every
existing file and the typed selected registration before the installer runs,
and checks retained custom files afterward. Existing generated `app_icon.ico`
or `uninstall.exe` outside the candidate inventory needs explicit resolution
because the source installer overwrites them separately from payload copying.

Differing configuration, binaries or other collisions produce a concrete
preservation/migration plan, not permission to overwrite. A legacy registered
`contents/modules` layout also needs a version-specific mapping: the reviewed
NSIS generator copies into the installation root and has no legacy data
migration branch. Its `/REPAIR` argument does not provide a distinct preserving
repair. Preserve originals outside the entire installation root, resolve those
specific mappings/collisions, and recollect before replanning.

Unknown installed-version Update remains unresolved until compatible migration
is established. Successful recovery of missing files still needs runtime and
selected-host verification. Native local fixtures demonstrate planning and
boundary behavior; actual signed vendor installation remains unverified without
an isolated test installation.
