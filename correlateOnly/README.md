# Correlate only mode

## Table of contents

- [Correlate only mode](#correlate-only-mode)
  - [Table of contents](#table-of-contents)
  - [When to use this mode](#when-to-use-this-mode)
  - [Setting up the target system](#setting-up-the-target-system)
  - [What this mode does (and does not) do](#what-this-mode-does-and-does-not-do)
  - [Reconciliation behavior](#reconciliation-behavior)
  - [Revoke sign-in sessions on disable](#revoke-sign-in-sessions-on-disable)
  - [Limitations compared to the full CRUD connector](#limitations-compared-to-the-full-crud-connector)
  - [Adding regular lifecycle scripts (update and enable)](#adding-regular-lifecycle-scripts-update-and-enable)
  - [Keeping read-only fields in sync with a None mapping](#keeping-read-only-fields-in-sync-with-a-none-mapping)

## When to use this mode

Use this mode when accounts in Microsoft Entra ID are already created and maintained elsewhere, for example an on-premises Active Directory synced to Entra ID through Microsoft Entra Connect, AADConnect or DirSync.

HelloID then only needs to:
- Correlate existing Entra ID accounts to persons.
- Import them, so permissions and entitlements can still be managed through HelloID.


Creating, updating or enabling the account itself is not needed in the default correlate only flow. Disabling and deleting are only supported for Reconciliation actions on cloud-only accounts, as described below.

## Setting up the target system

Create a **separate** target system in HelloID and only import the files from this `correlateOnly/` folder:

- `configuration.json`
- `create.ps1`
- `delete.ps1`
- `disable.ps1`
- `fieldMapping.json`
- `import.ps1`

Do not combine these files with the `create.ps1`, `configuration.json`, `fieldMapping.json` or `import.ps1` from the root of the repository, they are not compatible with each other.

The `configuration.json` in this folder only contains the connection settings required to query Microsoft Entra ID (Organization, TenantID, AppID and certificate). Options such as `exchangeOnlineIntegration`, `deleteAccount`, `setManagerOnCreate` and `updateManagerOnUpdate` are not present, as they are not applicable in this mode. The only additional option is `revokeSignInSessionsOnDisable`, see [Revoke sign-in sessions on disable](#revoke-sign-in-sessions-on-disable).

Next, configure the scripts from the [`permissions/`](../permissions/) folder for the entitlements you need, e.g. group memberships. These are the same scripts used for the full CRUD connector, there is no correlate only variant.

## What this mode does (and does not) do

- `create.ps1` does **not** create a new account. It looks up an existing account in Microsoft Entra ID using the configured [correlation configuration](../README.md#correlation-configuration) and correlates it to the person. If no account, or more than one account, is found, the action fails.
- `import.ps1` imports the correlated accounts, so they are visible for entitlement/permission assignment and reconciliation. For accounts with `onPremisesSyncEnabled -eq $true`, the imported `Enabled` state is always reported as `false`, regardless of the actual `accountEnabled` value in Entra ID. This avoids reconciliation actions/errors on AD synced accounts, that insight is already provided by the AD connector.
- `disable.ps1` and `delete.ps1` only disable or delete accounts for actions that originate from Reconciliation. They protect AD synced accounts and only disable or delete cloud-only accounts. When `revokeSignInSessionsOnDisable` is enabled, `disable.ps1` also revokes the sign-in sessions of the account for every origin, see [Revoke sign-in sessions on disable](#revoke-sign-in-sessions-on-disable).
- `fieldMapping.json` only maps `id` (used as the account reference), `employeeId` (used for correlation), `userPrincipalName` and `onPremisesSyncEnabled`. All mappings use the `None` mapping mode, meaning the values are only read from Entra ID and stored in HelloID, they are never written back.
- There is no `update.ps1` or `enable.ps1` in this folder, since regular account lifecycle changes are typically handled by the source that manages the account in Entra ID (e.g. on-premises AD). These regular scripts from the root of the repository are optional and can be added to the same target system when needed, see [Adding regular lifecycle scripts](#adding-regular-lifecycle-scripts-update-and-enable).
- Permission scripts in the [`permissions/`](../permissions/) folder can still be used on top of a correlate only target system, since they only require the account reference produced by `create.ps1`.

## Reconciliation behavior

The `disable.ps1` and `delete.ps1` scripts in this folder are specifically designed for Reconciliation scenarios. Regular provisioning flows are unaffected, because the scripts only execute their action when `$actionContext.Origin -eq 'Reconciliation'`.

During a Reconciliation action, the scripts retrieve the correlated Entra ID account and check the `onPremisesSyncEnabled` property:

- When `onPremisesSyncEnabled` is `true`, the account is synchronized from on-premises Active Directory. The script stops with an error to prevent accidental lifecycle changes to synced accounts.
- When `onPremisesSyncEnabled` is `false` or `null`, the account is treated as cloud-only and the requested Reconciliation action is executed.

This makes the correlate only variant suitable for environments where HelloID manages permissions for AD synced accounts, while still allowing Reconciliation cleanup for cloud-only accounts that should be disabled or deleted.

## Revoke sign-in sessions on disable

When the `revokeSignInSessionsOnDisable` option is enabled in `configuration.json`, `disable.ps1` revokes all active sign-in sessions of the correlated Entra ID account using the Graph API endpoint [`revokeSignInSessions`](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0&tabs=http).

Unlike the disable itself, revoking sessions is **not** limited to Reconciliation and is **not** blocked for AD synced accounts:

- It runs for every origin, including regular enforcement. The user is signed out of Microsoft 365 as soon as HelloID processes the disable, even when the account itself is disabled through the on-premises AD.
- It runs for both AD synced and cloud-only accounts. The revoke is executed before the disable, so it also runs during Reconciliation for an AD synced account, where the disable itself is blocked and the action fails.
- When the option is disabled (default), actions with another origin than Reconciliation are skipped without querying Entra ID.

> [!NOTE]
> This action requires the `User.RevokeSessions.All` (least privileged) or `User.ReadWrite.All` application permission. Revoking sessions can take a few minutes to take effect, and access tokens that were already issued remain valid until they expire (by default about one hour).

## Limitations compared to the full CRUD connector

| Aspect                   | Correlate only                                                                                                              | Full CRUD (root of the repository)                               |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Create account           | ❌ Not supported, the account must already exist                                                                             | ✅ Creates the account in Entra ID (and optionally Exchange Online) |
| Update account           | ⚠️ Optional, not added by default, see [Adding regular lifecycle scripts](#adding-regular-lifecycle-scripts-update-and-enable) | ✅ Supported                                                       |
| Enable account           | ⚠️ Optional, not added by default, see [Adding regular lifecycle scripts](#adding-regular-lifecycle-scripts-update-and-enable) | ✅ Supported                                                       |
| Disable account          | ⚠️ Reconciliation only, and only for cloud-only accounts. Revoking sign-in sessions (optional) is supported for all accounts | ✅ Supported                                                       |
| Delete account           | ⚠️ Reconciliation only, and only for cloud-only accounts                                                                      | ✅ Supported                                                       |
| Exchange Online          | ❌ Not supported                                                                                                             | ✅ Supported (optional)                                            |
| Permissions/entitlements | ✅ Supported                                                                                                                 | ✅ Supported                                                       |
| Import                   | ✅ Supported                                                                                                                 | ✅ Supported                                                       |

## Adding regular lifecycle scripts (update and enable)

The `update.ps1` and `enable.ps1` scripts from the root of the repository work with a correlate only target system: add them to the same target system alongside the scripts from this folder.

This is useful when you need to manage a **cloud-only** attribute that isn't synchronized from your on-premises AD, for example `ageGroup`. This only works for properties that aren't driven by the AD sync, e.g. `employeeHireDate` can **not** be managed this way, since Microsoft Entra Connect will overwrite it again with the value from AD on the next sync. Only map properties in `fieldMapping.json` that are actually cloud-only.

`enable.ps1` also works, but for AD synced accounts, keep in mind that a following Microsoft Entra Connect sync cycle will overwrite `accountEnabled` again with the value from AD.

Do not use the regular root `disable.ps1` or `delete.ps1` for AD synced correlate only accounts. Use the `disable.ps1` and `delete.ps1` scripts from this folder when you need Reconciliation cleanup: they explicitly block AD synced accounts and only process cloud-only accounts. Deleting an AD synced account must be done by removing it in the source AD.

## Keeping read-only fields in sync with a None mapping

Fields mapped with the `None` mapping mode also work when the regular `update.ps1` is added to a correlate only target system, as described above. When `Store in account data` is enabled for that field, HelloID reads the current value from Microsoft Entra ID during an update and stores it, without writing anything back to Entra ID.

This is useful when a field is fully managed outside of HelloID, but you still want its current value visible on the person's **Accounts** tab in HelloID. For example: `userPrincipalName` is changed in AD, which is synced to both Microsoft Entra ID and the source system. Without a None mapping for `userPrincipalName` on the update action, HelloID keeps showing the old UPN in the stored account data. With the None mapping configured, the next time an update action runs for the account, HelloID reads the current UPN from Microsoft Entra ID and updates the stored account data, without writing anything back to Entra ID.

> [!NOTE]
> HelloID is source driven and only executes an update action when it detects a change in the source data for a mapped field. The value is only refreshed when such an update is processed for the account, not in real time when the value changes in Entra ID itself.

