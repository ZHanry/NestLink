# Installation generations and retained data

Installed v15 binaries read a public `installation-instance.json` beneath their stable install root while holding shared installation admission. The marker contains a UUID namespace, never a device key or credential. The daemon still creates a random device ID and a new OS-protected private key in the selected private state leaf.

State resolves to `<state-root>/instances/<installation-UUID>`. A normal upgrade or compatible binary rollback preserves the UUID. Uninstall retires it and preserves every old state leaf, installation receipt, quota, backup and pinned update identity. A later install creates a fresh UUID, including an exact reinstall of the latest previously accepted signed bytes. Earlier sequences, changed bytes at the same sequence, and changed update pins are refused. An old explicit instance path cannot reactivate a retained identity.

Windows setup resolves the effective state before entering native maintenance. The maintenance owner keeps its original exact state through Commit, Leave and Abort, including the first installation and uninstall. Shortcut arguments use the stable state root so that stale shortcuts do not select a retired generation. Windows receipt/marker writes retain a create-new recovery record before either replacement; a retry of the signed installer recovers it only after the native exclusive maintenance owner confirms quiescence. Discovery reads are repeated under that owner, and a changed generation stops the transaction.

For an interrupted transaction whose accepted receipt was already committed, an exact retry of the active generation requires the native `installation_recovery` flag from the held exclusive installation gate. The incoming record must equal both the current and maximum accepted record, use the maximum accepted sequence and retain the same active installation UUID. Directory, version, source revision, manifest hash, both signer pins and state compatibility must also match; the retry preserves the previous accepted record. Ordinary active replay, lower sequences, changed bytes/pins and a different or inactive generation do not qualify for this recovery. A later fresh installation after completed uninstall follows the separate retired-generation rule above.

Successful setup Commit or completed uninstall sends `release`, which clears both maintenance journals. Failure or cancellation sends `abandon` through the same original control directory; the owner drops the OS locks and retains the user and installation startup fences plus recovery evidence. A new explicit owner can then acquire the locks immediately, but installed startup remains refused until recovery completes. The Windows helper checks the original controller PID and creation time as well as its typed ready record; a leftover ready file cannot authorize another transaction.

Ubuntu lifecycle retains a similar private recovery record under its installation crash fence. An interrupted operation requires `--recover-incomplete`; recovery restores the prior receipt/marker while exclusive installation admission is held. It does not erase the crash fence. Only a fully successful package transaction removes that fence.

The server service starts `installed-control --state-root /var/lib/nestlink-v15`. It opens only the current generation's `server.toml`; it does not adopt the older `control/` directory. Before starting the service, explicitly initialize the current deployment as the unprivileged service account:

```text
runuser -u nestlink-v15 -- /usr/lib/nestlink-v15/server/current/nestlink-server installed-init --state-root /var/lib/nestlink-v15 --management-origin https://control.example
```

The service's `ExecCondition` skips an uninitialized generation. Initialize a new administrator through the existing `bootstrap` command using the newly created config path and an operator-supplied private password file. Reinstall does not silently restore old users, roles, credentials or node admission.

For explicit account-side unbinding, review old device descriptors with:

```text
nestlink-daemon retained-instances --state-root <absolute-v15-state-root>
```

This reads only bounded private `installation-device.json` descriptors, including a pre-generation leaf if present. It does not open a device seed, authorization, quota or session, and performs no network operation. Use the current authenticated device-management flow to unbind the selected old device deliberately. Retained data is not automatically imported or deleted.

Development binaries outside a marked installed root keep their explicit state directory behavior. No v14 settings or identity are read. For installed state, missing, inactive, linked, writable or inconsistent markers block startup and require installation recovery.

The [2026-10-16 publication and maintenance review](../../artifacts/release-completion-review-20261016/REVIEW-REPORT.md) records exact recovery/replay policy fixtures and actual Windows/Ubuntu maintenance subprocess checks. It includes abandon, persistent startup refusal, immediate recovery ownership and successful fence removal. Genuine signed installation, interruption, rollback, removal and reinstallation acceptance remain required.
