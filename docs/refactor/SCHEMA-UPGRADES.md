# Offline schema upgrades

The server no longer opens an older schema for control, check or bootstrap and silently migrates it before backup. Those business entry points first require the compiled `nestlink_storage::SCHEMA_VERSION`. The explicit `schema` command and consistent read-only backup work with supported schemas from 4 through that current version.

Current schema 20 adds durable service usage grants, report highwaters and four lifetime quota scopes. An ordinary forward migration preserves these facts. Restoring an older snapshot instead marks service quota reconciliation required and keeps new grants closed indefinitely, because the snapshot cannot establish later spending. A normal limit update or the temporary publication-recovery delay does not remove that fence. The controlled external-ledger reconciliation/unseal entry point remains implementation work; see [service publication](SERVICE-PUBLICATION.md).

The migration entry point is:

```text
nestlink-server migrate --config <absolute-directory>/server.toml --from-schema <actual-old-schema> --to-schema <this-binary-current-schema> --backup <absolute-private-external-parent>/new-upgrade.nl15 --password-file <existing-private-password-file>
```

Supply an existing private password file containing 12–1024 bytes; no replacement password or deployment/signing identity is generated. Migration currently accepts self-contained deployments with fixed `control.sqlite3`, `vault.key`, `permit.key` and `server.toml`. An external database/key layout requires explicit reviewed relocation before this directory transaction. Backup paths must resolve outside the directory being renamed.

The stable admission and actual control singleton locks live in the checked private parent, outside the directory switch. A running control or concurrent database/key operation prevents migration before any backup or schema write. Control keeps the real deployment lease until its runtime exits. The installation startup gate is handed off to that lease, then released so privileged package maintenance can stop the service without a lock-order deadlock.

The migrator opens the source with SQLite read-only/no-follow flags, verifies application ID, exact deployment/schema and integrity, and uses SQLite's online backup API to include committed WAL. It never uses `Store::open_existing` to capture a pre-upgrade archive. The existing Argon2id/XChaCha20-Poly1305 backup is create-new, flushed, read back, authenticated and compared to the source before staging. All schema writes happen in a new private sibling. The normal restore command still invalidates recovered sessions/recovery codes; the separate migration stage preserves existing authority, consumed recovery states, deployment epoch, keys and quota records.

A private journal binds the transaction UUID, exact active/candidate/previous leaf names, schema/deployment, encrypted archive hash and snapshot/config/key proofs. The original directory is renamed intact to the retained previous leaf; no live WAL is copied and no user directory is recursively removed. Activation failure before admission restores that exact original directory. Candidate, previous and encrypted backup are retained for review.

Crash recovery requires the still-present journal and exact transaction UUID:

```text
nestlink-server recover-migration --directory <absolute-deployment-directory> --transaction <UUID> --complete
nestlink-server recover-migration --directory <absolute-deployment-directory> --transaction <UUID> --rollback
```

Recovery validates actual directory proofs rather than assuming the last phase write preceded a crash. A terminal phase is durably replaced before deleting the journal. If the deletion reappears after power loss, a completed transaction can only complete; a rolled-back transaction can only remain rolled back. The cleanup accepts later same-deployment changes to the database without restoring any old snapshot. This prevents an old journal from reviving consumed recovery codes, revoked grants or spent quotas after business may have resumed. A missing journal refuses recovery; retaining a previous directory is not permission to downgrade an admitted deployment.

The Ubuntu package owner supports forward state compatibility pairs `v15-control-schema<N>-epoch1` and supplies:

```text
lifecycle.py install --role server <fixed-signed-bundle-arguments> --migrate-config /var/lib/nestlink-v15/instances/<active-install-UUID>/server.toml --migration-backup <new-private-external-archive> --migration-password-file <existing-private-file>
```

It executes the hash/signature-verified new migrator as the unprivileged service account, with `--defer-admission`. The schema journal remains closed through binary activation and installation receipt/generation commit. Only then does it finalize the exact transaction and remove the installation fence. A pre-admission activation error rolls schema back before reinstalling the exact old package. If the migration child dies without a receipt or finalization is uncertain, the gate and new migrator are retained; the owner does not blindly downgrade its executable.

For a crash after the package receipt moved forward, retry the exact accepted signed incoming package with `--recover-incomplete --complete-schema-transaction <UUID>`. The UUID is in the private schema journal. This explicitly completes that still-fenced transaction before checking the new deployment and reopening the package. If the schema was already explicitly completed while the package fence remained, exact incomplete-package recovery recognizes the target schema without rerunning migration or replacing the existing archive. Same-sequence changed bytes and changed update pins remain refused.

Different security epochs, reverse schema transitions and unknown user-state formats remain unsupported until a dedicated authenticated migration exists. That restriction does not block the supported forward control-schema path above.

The source includes real Rust fixtures for old-schema read-only capture, authenticated migration, identity/epoch/recovery preservation, runtime exclusion, exact pre-admission rollback, directory-gap recovery and post-admission non-resurrection. Both platforms passed all-target strict Clippy for the affected crates. The first Windows run passed read-only capture/runtime exclusion but exposed SQLite's default path-length limit in four candidate-directory fixtures; that failed attempt is retained. A shared connection helper now uses SQLite's normal locking win32-longpath VFS while retaining read-only/no-follow flags. The latest service-web-host-schema attempts passed both file-path regressions and all six encrypted migration fixtures on Windows and Linux, with stable source inputs and owned scratch removal recorded for each group. Pure package-owner tests also passed within the combined lifecycle run. See [the consolidated check record](SERVICE-HOST-PRODUCER-CHECKS-2026-10-15.md). These checks do not constitute certificate-backed installed-product acceptance.
