# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

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
