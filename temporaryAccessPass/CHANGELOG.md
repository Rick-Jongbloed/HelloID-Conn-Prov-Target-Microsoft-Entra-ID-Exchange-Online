# Changelog - temporaryAccessPass

All notable changes in this folder are documented in this file.

## [Unreleased] - 2026-05-27

Compared with `main` (`git diff main...HEAD -- temporaryAccessPass`):

- Added 5 files
- 626 insertions

### Added

- `configuration.json`
  - Added connector configuration fields for:
    - `TenantID`
    - `AppId`
    - `AppCertificateBase64String`
    - `AppCertificatePassword`
    - `TemporaryAccesPassLifetime`

- `enable.ps1`
  - Added Enable action script for Temporary Access Pass issuance.
  - Added certificate-based app authentication to Microsoft Graph.
  - Added validation for `TemporaryAccesPassLifetime` as required positive integer.
  - Added TAP creation via Graph endpoint:
    - `/users/{id}/authentication/temporaryAccessPassMethods`
  - Added `Data.temporaryAccessPass` output for notification usage.
  - Added `Data.validUntil` output with Dutch formatting without seconds (`dd-MM-yyyy HH:mm`).
  - Added dry-run behavior and structured audit logging.
  - Added error normalization and HTTP error handling.

- `fieldMapping.json`
  - Added mapping for correlation fields:
    - `id` (AccountReference)
    - `employeeId` (Correlation key)
  - Added notification output fields:
    - `temporaryAccessPass` (`UsedInNotifications: true`)
    - `validUntil` (`UsedInNotifications: true`)

- `notification.mjml`
  - Added minimal notification template based on the shared MJML template style.
  - Included TAP-specific variables:
    - `{{ Data.temporaryAccessPass }}`
    - `{{ Data.validUntil }}`

- `README.md`
  - Added full documentation for Temporary Access Pass module.
  - Added requirements, including license group assignment requirement.
  - Added go-live warning for active sessions and rollout guidance.
  - Added explicit notification variables section.
  - Added minimal notification template reference.
  - Fixed markup/lint issues and aligned section structure.

### Notes

- Scope is limited to the `temporaryAccessPass` folder.
- This changelog reflects branch changes relative to `main`.
