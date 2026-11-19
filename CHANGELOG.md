# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [Unreleased]

### Added
- **permissions/folderPermission**, **permissions/outOfOffice** and **permissions/regionalConfiguration**: ported from the [ExchangeOnline connector](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-ExchangeOnline/tree/feature-out-of-office) to the Exchange Admin API (beta `InvokeCommand`), so no ExchangeOnlineManagement module is needed. Same style as the shared mailbox scripts: retry on 429, 5xx and timeouts within the action deadline, `X-AnchorMailbox` set to `Oid:<account reference>@<tenant id>`, and DryRun support. Behaviour is the same as the source: folderPermission and regionalConfiguration only have a grant script, the outOfOffice grant disables the reply and the revoke enables it with the message from the custom configuration key `OutOfOfficeReply` (see permissions/outOfOffice/README.md).

### Changed
- **permissions/educationalGroups/README.md**: rewritten. Explains how the educational team scripts work (name convention `<prefix>_<code>_<school year>`, school year calculation, static and dynamic permissions, imports, resources with and without activation button), in which situations to use which scripts, that only the resource scripts need an education tenant, the different default prefixes of the resource scripts and `subPermissions.ps1`, and the actual configuration keys.
- **guestInvite/README.md** (new): how the guest create works, the required API permissions and the external collaboration settings of the tenant, with troubleshooting for `Guest invitations not allowed for your company`. Linked from the main README.
- **temporaryAccessPass**: the configuration key `TemporaryAccesPassLifetime` (typo) is renamed to `TemporaryAccessPassLifetime`, with default `4320` minutes (3 days), recommended for onboarding; the maximum lifetime of the tenant policy must be at least this value (see the README). **Action required when updating**: enter the lifetime again in the configuration, otherwise the enable action fails with "TemporaryAccessPassLifetime [] is not a valid positive number".
- **temporaryAccessPass/README.md**: a Troubleshooting section that explains the error `Converged UserCredentialPolicy does not allow creating or updating ...` (the Temporary Access Pass method is disabled in the tenant policy) and the lifetime and one-time use settings of the policy, with links to the Microsoft documentation. The lifetime examples are within the default policy range.
- **README.md**: the main README only lists the permissions of the account scripts. Every permission folder (and `resources/groups`, `resources/teams`) has its own README that explains the permission and lists the API permissions it needs, so an app registration only gets the permissions for the folders that are used. Corrected along the way: `perUserMfaState` needs `Policy.ReadWrite.AuthenticationMethod` (was not documented), and `teamChannels` needs `Channel.ReadBasic.All` instead of `Team.ReadBasic.All`/`TeamMember.ReadWrite.All`.
- **permissions/sharedMailboxes/grantPermission.ps1** and **revokePermission.ps1**: `X-AnchorMailbox` is now `Oid:<shared mailbox object id>@<tenant id>` instead of the system mailbox, so all requests for one shared mailbox are routed to the same Exchange backend server. The import scripts keep the system mailbox anchor.
- **permissions/sharedMailboxes/importPermission.ps1**, **permissions/exchangeGroups/importPermission.ps1** and **permissions/exchangeGroups/permissions.ps1**: large results are now read completely. The list of distribution groups and every `$batch` sub-response (mailbox permissions, recipient permissions, group members) follow `@odata.nextLink` until the last page; before, only the first page was used.
- **permissions/exchangeGroups**: groups are referenced by `ExchangeObjectId` instead of `Guid`, because the `Guid` can change during a tenant relocation (see [ExchangeOnline issue #30](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-ExchangeOnline/issues/30)). Grant and revoke accept both, so existing entitlements keep working. Where `Guid` and `ExchangeObjectId` differ, the permission reference of the group changes in HelloID.
- **permissions/sharedMailboxes/permissions.ps1** and **importPermission.ps1**: `Get-Mailbox` uses `ResultSize Unlimited` (was `500`) with `@odata.nextLink`. A server-side filter with `-RecipientTypeDetails` is not accepted by the v2.0 endpoint (400), so the mailbox type is still filtered in the script.
- **Exchange list and import scripts**: every list request retries on 429, 5xx and timeouts, sends a `client-request-id` and stops on `@adminapi.errors`, so HelloID never receives a partial list.
- **permissions/exchangeGroups/grantPermission.ps1** and **revokePermission.ps1**: the account reference is validated and trimmed like in the shared mailbox scripts, and DryRun is checked with `-ne $true`.

### Fixed
- **resources/educationalGroups/withoutActivationButton/resources.ps1**: the counter of created teams was never raised, so the maximum of 200 teams per run (`$maximumAmountToCreatePerRun`) was not applied and the audit log always said "Created [0]". Found with the lifecycle test.
- **guestInvite/create.ps1**: the audit log "Set Manager on create is enabled, but no manager externalId is found on the person object" was added when `setManagerOnCreate` was *disabled* (the `else` belonged to the wrong `if`). It is now added only when the option is enabled and the person has no manager. Found with a live test.
- **Entra ID scripts**: the fixes of [2.8.1](#281---2026-11-19) are included (merged from main).
- **permissions/sharedMailboxes/importPermission.ps1**: the permissions are retrieved with the `ExternalDirectoryObjectId` of the shared mailbox (like grant and revoke) instead of `Identity`, which is the name of the mailbox. A name that also matches a group or contact failed with status 409 and stopped the import; two shared mailboxes with the same name got each other's permissions. Reported by Remco.
- **Exchange permission scripts**: HelloID blocks the .NET types `System.Threading.Tasks.TaskCanceledException` and `System.TimeoutException` ("Script blocked: .NET type(s) ... are not supported"), so these exceptions are now recognised by their type name (`GetType().FullName`).
- **Exchange import scripts**: with more than 500 accounts on one permission, every chunk is now a separate object; before, all chunks carried the accounts of the last chunk.
- **permissions/sharedMailboxes**: error messages now read `error.details.message`, and the certificate is checked for a private key before signing.

### Known limitations
- **Send As**: when Exchange Online switches backend server between consecutive Send As changes on the same mailbox, the newest changes (of the last seconds) can be overwritten without an error. This was reproduced with the system mailbox anchor (6 of 6,687 changes in one test, all at one server switch). Full Access, Send on Behalf and Exchange group memberships are not affected. Advice: check Send As after large batches (first enforcement, a business rule for a whole department).

## [2.8.1] - 2026-11-19

### Fix
- **permissions/emailAuthenticationMethods/revokePermission.ps1**: `$removeWhenRevokingEntitlement` worked the other way around. With the default (`$false`) the email method was deleted on revoke; it is now kept, and only deleted with `$true`.
- **permissions/phoneAuthenticationMethods/revokePermission.ps1**: the existing method was read from `phone` instead of `phoneNumber`, so it was never found and never deleted, also not with `$removeWhenRevokingEntitlement = $true`.
- **permissions/phoneAuthenticationMethods/grantPermission.ps1**:
  - Every phone type now has its own person field in `$phoneNumberMapping` at the top of the script. Before, `alternateMobile` used the same number as `mobile`, and `office` used the business mobile number. Defaults: `mobile` = `Person.Contact.Personal.Phone.Mobile`, `alternateMobile` = `Person.Contact.Business.Phone.Mobile`, `office` = `Person.Contact.Business.Phone.Fixed`.
  - Dutch landline numbers (`0...`) are converted to `+31...` (were `+0...`).
  - When the person has no number for the type, the grant fails with a clear error instead of a Graph 400.
- **permissions/emailAuthenticationMethods/grantPermission.ps1**: the email address is set in `$email` at the top of the script; an empty address gives a clear error instead of a Graph 400.
- **Sub permission imports** (`groups/subPermissionsImport.ps1`, `educationalGroups/members/importSubPermissions.ps1`, `educationalGroups/owners/importSubPermissions.ps1`, `teamChannels/importPermission.ps1`): with more than 500 accounts on one permission, every chunk is now a separate object. Before, the same object was output for every chunk, so all chunks carried the accounts of the last chunk.
- **Invoke-MSEntraBatchRequest** (all list and import scripts that use `$batch`): a failed sub-request (429/5xx) was only logged as a warning and returned an empty result, which gave an incomplete import or permission list. It is now retried on its own (with `Retry-After`, as the 2.7.0 changelog describes), and any other failure stops the script. A sub-request that returns 404 (object deleted meanwhile) still gives an empty result. The whole batch is also retried on 500, 502 and 503 (was 429 and 504), now with the `Retry-After` of the response when present (otherwise 5, 10, 15 seconds). The `@odata.nextLink` pagination calls are retried on 429/5xx as well (up to 3 times) instead of failing at once.
- **Resolve-MS-Entra-ExoError** and the other error helpers (37 scripts): an error response with an empty or whitespace-only body no longer wipes the original error message. `ConvertFrom-Json` returned `$null` there, so the warning showed `Error: ` without text; the exception message (for example `401 (Unauthorized)`) is now kept.
- **create.ps1**, **update.ps1**: `managerId` is no longer sent in the Graph request bodies (it is not a property of the user resource, and holds the source manager id, not an Entra id). It was always seen as a changed property, so every `UpdateAccountEntra` failed with `Request_ResourceNotFound`. The manager is still set by the manager actions.
- **Resolve-MS-Entra-ExoError** (all scripts): the message of `error.details` was read from `details.message` instead of `error.details.message`, so it was empty.
- **update.ps1**:
  - A change of only the manager no longer adds the audit log "No changes will be made to the account during enforcement". The manager actions now set `Success` themselves.
  - `UpdateAccountExo` is no longer added (and executed) twice when both the mailbox properties and the email addresses changed.
- **enable.ps1**: a missing mailbox no longer stops the action. The Entra ID account is enabled and Exchange Online is skipped with a warning, like in update and disable.
- **create.ps1**, **update.ps1**, **enable.ps1**, **disable.ps1**, **delete.ps1**: an empty `HiddenFromAddressListsEnabled` is skipped instead of failing (`[bool]::Parse` on null or an empty value for Set-Mailbox).
- **create.ps1** and **uniquenessCheck.ps1**: the `givenName` fallback lookup (and the correlation lookup in uniquenessCheck) did not select `id`, so a found account had no id. In create, the retry after creating a mailbox failed with "AccountReference is null"; in uniquenessCheck, the own account was not excluded. Found with a live test.
- **create.ps1**: the fallback lookup on `givenName` is only done with Exchange Online integration. Without it, a match gave the audit log "Retrying account creation" while a new account was created.
- **create.ps1**, **uniquenessCheck.ps1**, **correlateOnly/create.ps1**, **guestInvite/create.ps1**: values in a Graph `$filter` are escaped (`'` becomes `''`) and URL encoded, so values with `'`, `+`, `&` or `#` (for example `o'brien+test@domain.com`) are found correctly instead of giving a 400 or a wrong result.
- **permissions/teamChannels/grantPermission.ps1**: an account that is already a member of the channel with the role counts as success (the members are checked after a failed add), like the group scripts.
- **permissions/teamChannels/revokePermission.ps1**: the channel members are read with paging (`@odata.nextLink`), so the account is also found in large channels.
- **permissions/teamChannels**: grant and revoke report success in DryRun (preview).
- **permissions/groups/grantPermission.ps1** and **permissions/educationalGroups/*/grantPermission.ps1**: an error is reported with its HTTP details, like elsewhere, instead of the raw JSON. An error without a JSON body is reported as well (before, `ConvertFrom-Json` failed on it).

## [2.8.0] - 2026-11-09

### Added
- **Revoke sign-in sessions on disable**: new configuration option `revokeSignInSessionsOnDisable` (checkbox, default `false`). When enabled, the disable script revokes all active sign-in sessions of the user through the Graph API endpoint `/users/{id}/revokeSignInSessions`. Requires `User.RevokeSessions.All` (least privileged) or `User.ReadWrite.All`.
  - `disable.ps1`: adds the `RevokeSignInSessions` action as the last action, after the Entra ID and Exchange Online disable actions, when the MS-Entra account is found.
  - `correlateOnly/disable.ps1`: revokes sign-in sessions for every origin (not only Reconciliation) and also for AD synced accounts. This happens before the disable, so sessions are also revoked when the disable is blocked for an AD synced account during Reconciliation.
  - `configuration.json` and `correlateOnly/configuration.json`: added the `revokeSignInSessionsOnDisable` option.

### Changed
- **correlateOnly/disable.ps1**: when `revokeSignInSessionsOnDisable` is enabled, the Entra ID account is queried for every origin. The action then fails when the account reference is empty or the account is not found. With the option disabled (default) the behavior is unchanged: non-Reconciliation origins are skipped. The disable itself is still limited to Reconciliation and to cloud-only accounts.

## [2.7.1] - 2026-10-16

### Fix
- **update.ps1**: Added `-CaseSensitive` to attribute comparisons so changes that differ only by letter casing are detected for Entra ID and Exchange Online. Now this fields will also be updated in Entra ID and Exchange Online.

## [2.7.0] - 2026-09-30

### Changed
- **Import and sub-permission scripts** now use Microsoft Graph JSON batching (`$batch`, max 20 requests per batch) for all per-item GET requests (group members/owners, team channels, channel members) instead of one request per item. This makes imports of large tenants significantly faster. Failed sub-requests (429/5xx) are retried individually with respect to `Retry-After`.
  - `permissions/groups/importPermission.ps1` and `subPermissionsImport.ps1`
  - `permissions/groups/filterExamples/importOnlyGuestGroups.ps1` and `importOnlyMemberGroups.ps1`
  - `permissions/teamChannels/importPermission.ps1` and `permissions.ps1`
  - `permissions/educationalGroups/members/import.ps1` and `importSubPermissions.ps1`
  - `permissions/educationalGroups/owners/import.ps1` and `importSubPermissions.ps1`
- **Invoke-MSEntraBatchRequest** takes a list of requests (`Method` and `Uri`), so no ScriptBlocks are used (these are blocked by HelloID).

## [2.6.2] - 2026-09-09

### Hotfix
- Disable and Delete script failed when `Origin` = `enforcement`
- 
## [2.6.1] - 2026-09-08

### Changed
- **correlateOnly/import.ps1**: Accounts with `onPremisesSyncEnabled -eq $true` are now always imported with `Enabled = false`, regardless of their actual `accountEnabled` value in Entra ID. This prevents reconciliation actions/errors on AD synced accounts, since that insight is already provided by the AD connector.

### Fixed
- **permissions/teamChannels/grantPermission.ps1**: Removed a leftover debug `Write-Warning` that dumped the request body.
- **permissions/teamChannels/importPermission.ps1**: Removed a leftover debug `Write-Warning` that dumped the raw error object at the start of the catch block.
- **permissions/teamChannels/permissions.ps1**: Removed a leftover debug `Write-Warning` that dumped the raw error object at the start of the catch block.
- **README.md**: Removed a misplaced `Configuration` subsection under `Inviting Guest Accounts` that actually described the correlate only setup, which is already covered by `Correlate only mode` and `correlateOnly/README.md`.

## [2.6.0] - 02-09-2026

### Fixed
- **update.ps1**: Fixed a bug where the Entra account comparison was skipped whenever `actionContext.Data` was not empty but did not contain any mapped fields, preventing `None` mapped fields (e.g. `userPrincipalName`) from being read and stored in the account data.

### Added
- **correlateOnly/README.md**: Added documentation for the correlate only setup: when to use it, how to set it up, its limitations compared to the full CRUD connector, how to add the regular update/enable/disable/delete scripts on top of it, and how to keep read-only fields in sync using a `None` mapping.
- **README.md**: Added `Correlate only` to the supported features table and a pointer to `correlateOnly/README.md`.

## [2.5.5] - 2026-08-19

### Added
- **correlateOnly/delete.ps1**: Added support for deleting cloud-only accounts via Reconciliation. The script validates that accounts are not synchronized from on-premises Active Directory before allowing deletion.
- **correlateOnly/disable.ps1**: Added support for disabling cloud-only accounts via Reconciliation. The script validates that accounts are not synchronized from on-premises Active Directory before allowing the disable action.
- **correlateOnly/fieldMapping.json**: Added `onPremisesSyncEnabled` as a read-only attribute to determine whether an account is synchronized from on-premises AD. This attribute is used by the delete and disable scripts to prevent actions on synced accounts.

### Changed
- **correlateOnly**: Delete and disable actions now only execute when triggered from Reconciliation (`$actionContext.Origin -eq 'Reconciliation'`). Regular provisioning flows are unaffected.

### Fixed
- Manager not found catch was not working when running the connector on-prem (PSv5)

## [2.5.4] - 2026-08-11

### Fixed
- Fixed an issue where import scripts without field mapping added a trailing whitespace character to `accountEnabled`.

## [2.5.3] - 04-08-2026

### Added
- Import examples how to filter data for account and memberships

### Fixed
- Added private key check in scripts where it was missing

### Changed
- Empty or whitespace `department` values are now converted to `$null`, allowing the field to be cleared correctly instead of placing a whitespace.

## [2.5.2] - 30-07-2026
### Fixed
- **correlateOnly/create.ps1**: Changed correlation value from `accountFieldValue` to `personFieldValue` to support Governance correlation scenarios correctly.
- **create.ps1**: Fixed Exchange mailbox creation to use `mailNickName` for the `Name` parameter (which must be unique) and added explicit `DisplayName` parameter. This resolves errors when creating mailboxes for users with duplicate display names.
- **permissions/emailAuthenticationMethods/grantPermission.ps1**: Changed email authentication method to use personal email address instead of business email address. This ensures password reset codes are sent to an accessible email address rather than the business account being reset.
- **permissions/groups/subPermissions.ps1**: Fixed undefined `$resource` variable in `$actionMessage`. The message now correctly displays `$correlationField`, `$correlationValue`, and `$contract.ExternalId` for improved logging clarity.

### Added
- **correlateOnly/fieldMapping.json**: Added `userPrincipalName` as an additional correlation field alongside `employeeId`, enabling environments to correlate on either attribute as needed.

## [2.5.1] - 30-07-2026
### Fixed
- **uniquenessCheck.ps1**: Fixed bug where email addresses were incorrectly flagged as non-unique during `create` operations, even when the person was already using that email address themselves. The script now properly performs correlation lookup (employeeId → givenName fallback) during create to identify if the account already exists, and correctly checks self-usage across all operation types.

### Changed
- **uniquenessCheck.ps1**: Added explicit `$correlationField` and `$entraMailboxFallbackLookupPropertyValue` variables for consistency with `create.ps1`.

### Added
- **README.md**: Added documentation explaining that correlation configuration must be manually updated in `uniquenessCheck.ps1` when using different correlation fields, as `$actionContext.CorrelationConfiguration` is not available in the uniqueness check lifecycle action.

## [2.5.0] - 10-07-2026
### Added
- Support for managing team channels

## [2.4.0] - 11-05-2026
### Added
- Support for managing en creating educational groups

## [2.3.0] - 13-04-2026
### Added
- Resource creation for teams.
- PerUserMfaState permissions.

### Fixed
- Reconciliation action to disable or delete account was not working.
- Correlation now works for `onPremisesExtensionAttributes.extensionAttribute`

## [2.2.0] - 16-02-2026
### Added
- Feature: Added guest invite capability to invite external users as guest accounts in Microsoft Entra ID.
- Added separate `guestInvite` folder containing:
  - `configuration.json`: Configuration template for guest invite operations.
  - `create.ps1`: PowerShell script to create and invite guest accounts.
  - `fieldMapping.json`: Field mapping for guest account attributes including invitation details and guest-specific properties.
- Added documentation for "Inviting Guest Accounts" section in README with detailed setup and usage instructions.
- Add a check to throw the script when `The certificate does not have a private key`

## [2.1.2] - 03-02-2026
- Fix: when no account was found, the script used a throw. This was changed so the script flow works as intended.

## [2.1.1] - 03-02-2026
- Fix, success was not true when no person was found when revoking a group

## [2.1.0] - 29-12-2025
- Feature, skip ExO actions in update, disable and delete when no ExO account was found.
- Fix, data returned to in create script was incomplete

## [2.0.4] - 18-12-2025
- Fixed retrieving security groups from Entra ID returned duplicate records when the number of groups exceeded 1,000.
- Removed license scripts from the repository in accordance with Microsoft best practices.

## [2.0.3] - 09-12-2025
### Fixed
- Corrected audit logging messages in the disable script for Entra account updates (previously incorrectly referenced "delete action").

## [2.0.2] - 14-11-2025
### Updated
 - Update import scripts because length to max 100 char was calculated incorrectly.
 - Update import account to return data to HelloID with each page.

## [2.0.1] - 12-11-2025
### Updated
 - Update configuration placeholders to use empty GUIDs instead of fake GUIDs.


## [2.0.0] - 29-10-2025
### Updated
- Field mapping logic for `mail`, `mailNickname`, `userPrincipalName`, and `exchangeOnline.EmailAddresses` updated to follow best practices for naming conventions, uniqueness, and attribute length limits.

### Added
- Project logo/icon added to the README for improved visual identification.

### Changed
- Expanded and improved documentation in the README, including:
  - Clearer explanation of group-based licensing.
  - Addition and clarification of used Graph API endpoints.
  - Extended explanation about the custom cmdlet `Connect-ManagedExchangeOnline` and the HelloID cloud agent.
  - Various textual and structural improvements.
- Feature table updated: "Resources: Groups" now marked as supported.
- Consistent use of `.Id` instead of `.Reference` for permission identifiers in all permission scripts (groups and licenses).
- Improved output formatting and handling of display names and descriptions in group and license import scripts.
- More robust logic for batching and reporting group and license members.
- Clarified and corrected endpoint documentation in README.
- README: clarified that `Connect-ManagedExchangeOnline` is only available in the HelloID cloud agent environment.
- Minor textual corrections in README and script comments.
- Minor corrections and additions in the changelog and feature table.

### Fixed
- Multiple small fixes in the import scripts for permissions (groups and licenses).

## [1.2.2] - 28-10-2025

### Authentication methods
- Fixed: Changed only boolean names back to onlySetMobileWhenEmpty and onlySetEmailWhenEmpty
- Fixed: Changed a true/false bug in the processing logic of these booleans
- Fixed: Changed dryRun and actionMessages so that the changed attribute value is shown
- Fixed: Changed dryRun and actionMessages so it doesn't use the Permission.displayName as this doesn't work in the dryRun

## [1.2.1] - 14-10-2025

### Changed
- Fixed: Granting already granted permissions no longer results in an error.
- Fixed: Retrieving security groups.
- Fixed: `Update` action does no longer result in an error when no ExchangeOnline properties are required to be updated.
- Fixed: `Update` action now supports the switch between primary and alias.
- Fixed: `UniquenessCheck` now supports the issue that occurred when mailbox was created but the `Create` action fails.
- Fixed: Issue in the PhoneAuthenticationMethod where the `Grant` and `Revoke` looked up the wrong permission property.
- Fixed: Actions in `Grant` and `Revoke` for email and phone authenticationMethods now work correctly.
- Improvements to the `Readme`.

### Removed
- Removed: displayName from the `UniquenessCheck` script.

## [1.2.0] - 10-07-2025

### Added
- Added support for reconciliation actions on unmanaged accounts.
- Added notification support for `enable`, `disable`, and `delete` actions (Data vs PreviousData).

### Changed
- Optimized field mapping to store less accountData.
- Fixed: ActionMessage in the delete script.
- Fixed: Boolean comparisons in the `Update`, `Disable`, and `Delete` scripts.
- Fixed: Get user in the disable script.
- Fixed: Missing audit logging for Entra updates in the disable script.


## [1.1.0] - 12-06-2025

### Added
- Permissions functionality added, based on existing permissions in the target system. The following permissions are available:
 - Groups
 - Licenses
 - Phone authentication methods
 - Email authentication methods

Note that for both groups and licenses, the _import_ feature is also supported.

## [1.0.0] - 15-03-2025

This is the first official release of _HelloID-Conn-Prov-Target-MS-Entra-Exo_. This release is based on template version _v2.0.1_.

### Added

### Changed

### Deprecated

### Removed
