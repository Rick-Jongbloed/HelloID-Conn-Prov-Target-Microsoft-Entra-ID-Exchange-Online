# Temporary Access Pass (TAP)

> [!NOTE]
> The Temporary Access Pass feature is an optional provisioning operation for HelloID targets. This module enables issuing temporary access passes for user accounts in Microsoft Entra ID.

## Table of contents

- [Temporary Access Pass (TAP)](#temporary-access-pass-tap)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Supported features](#supported-features)
  - [Getting started](#getting-started)
    - [Requirements](#requirements)
    - [Connection settings](#connection-settings)
    - [Field mapping](#field-mapping)
  - [Configuration](#configuration)
  - [Remarks](#remarks)
    - [Temporary Access Pass Lifecycle](#temporary-access-pass-lifecycle)
    - [Go-live and active sessions](#go-live-and-active-sessions)
    - [Script flow](#script-flow)
  - [Troubleshooting](#troubleshooting)
  - [Notifications](#Notifications)
    - [Minimal notification template](#minimal-notification-template)
    - [Notification variables](#notification-variables)
  - [Development resources](#development-resources)
    - [GraphAPI documentation](#graphapi-documentation)

## Introduction

The _Temporary Access Pass_ module provides a mechanism to enable temporary authentication credentials for Microsoft Entra ID user accounts. This feature is particularly useful for:

- Initial account provisioning where users need immediate access before permanent credentials are set up
- Onboarding scenarios where passwordless authentication methods are being configured
- Emergency access scenarios where traditional authentication methods are temporarily unavailable

The Temporary Access Pass feature operates within the context of a provisioning flow, generating a time-limited credential that can be used for initial sign-in.

## Supported features

- **Temporary Access Pass**: Supported `Yes`, Action `Enable`, generates a temporary access credential for the user.
- **Correlate only mode**: Supported `Yes`, no action, works with correlate-only provisioning flows.
- **Configurable lifetime**: Supported `Yes`, no action, allows customization of TAP validity period.
- **Single-use tokens**: Supported `Yes`, no action, supports one-time use credentials.

## Getting started

### Requirements

To use the Temporary Access Pass feature, ensure that:

1. **App Registration Permissions**: Your Azure App Registration must have the following API permission:
   - `UserAuthenticationMethod.ReadWrite.All` - Required to create and manage temporary access passes

2. **HelloID Configuration**: The standard HelloID connector configuration must be in place with:
   - App Registration ID
   - Tenant ID
   - Certificate-based authentication

3. **Target System**: Microsoft Entra ID environment with sufficient permissions

4. **License assignment**: The user must already have the required Microsoft license assigned (for example through a license group) before issuing a Temporary Access Pass.

### Connection settings

The Temporary Access Pass configuration uses the standard MS Entra connection settings:

- **TenantID**: Azure AD Tenant ID (Directory ID). Required: `Yes`.
- **AppId**: Application (Client) ID from App Registration. Required: `Yes`.
- **AppCertificateBase64String**: Base64-encoded certificate for authentication. Required: `Yes`.
- **AppCertificatePassword**: Password for the certificate. Required: `Yes`.
- **TemporaryAccessPassLifetime**: Lifetime of the TAP in minutes (e.g., `60` = 1 hour). Must be within the minimum and maximum lifetime of the Temporary Access Pass policy of the tenant (see [Troubleshooting](#troubleshooting)). Required: `Yes`.

For details on setting up certificate-based authentication, refer to the main connector README and Microsoft's official documentation:

- [App-only authentication with certificate](https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access)

### Field mapping

The Temporary Access Pass mapping includes the following fields:

- **id**: Unique identifier for the user (AccountReference). Type: `Text`. Used in: `Create`.
- **employeeId**: Employee identifier (Correlation Key). Type: `Text`. Used in: `Create`.
- **temporaryAccessPass**: The generated TAP credential. Type: `Text`. Used in: `Enable`.

## Configuration

### Enabling Temporary Access Pass

To enable TAP in your HelloID provisioning target:

1. Select the **Temporary Access Pass** option from the available provisioning features
2. Configure the **TemporaryAccessPassLifetime** parameter with the desired lifetime in minutes, within the lifetime range of the tenant policy:
   - Example: `60` minutes = 1 hour
   - Example: `1440` minutes = 1 day (the maximum lifetime of the policy must be raised for this)

3. Map the `temporaryAccessPass` field to your notification system or audit logs to capture the generated credentials

> [!IMPORTANT]
> Temporary Access Pass credentials should be communicated to users through secure channels only. Ensure that your HelloID notification system is configured to handle sensitive credential data appropriately.

## Remarks

### Temporary Access Pass Lifecycle

- **Generation**: A TAP is generated when the Enable action is triggered during provisioning
- **Validity**: The credential remains valid for the configured lifetime
- **Single-Use**: By default, the TAP is configured as single-use, meaning it can only be used once for authentication
- **Retrieval**: The generated TAP value is returned in the `temporaryAccessPass` field and can be included in notifications

> [!WARNING]
> Once a Temporary Access Pass is generated, it cannot be retrieved from Microsoft Entra ID. The credential is only visible at generation time. Ensure that your provisioning workflow captures and securely distributes the credential to the user immediately.

### Go-live and active sessions

When a TAP is issued while a user is already signed in, some devices may prompt that user to sign in again with the Temporary Access Pass.

For go-live scenarios, it is recommended to first assign account access entitlement without immediately issuing TAP, for example by:

- running with `DryRun = $true`, or
- executing account access import first via the account access import functionality.

After access is in place and timing is controlled, issue the TAP.

### Script flow

The Temporary Access Pass Enable operation follows this process:

1. **Authentication**: Establishes connection to Microsoft Graph API using certificate-based authentication
2. **User Lookup**: Correlates the provisioning account to an existing Microsoft Entra ID user
3. **Validation**: Verifies that the user account exists and is valid
4. **TAP Creation**: Calls the Microsoft Graph API to create a new Temporary Access Pass for the user
5. **Credential Return**: Returns the generated TAP credential in the provisioning context
6. **Notification**: The TAP is made available for inclusion in provisioning notifications

## Troubleshooting

The Temporary Access Pass must be enabled in the tenant before the connector can issue one. This is a setting of the tenant, not an API permission of the app registration.

| Error | Meaning | Solution |
| ----- | ------- | -------- |
| `badRequest: Converged UserCredentialPolicy does not allow creating or updating ...` | The Temporary Access Pass method is disabled in the Authentication methods policy of the tenant, or the user is not in a group the method is enabled for. | Microsoft Entra admin center > **Protection** > **Authentication methods** > **Policies** > **Temporary Access Pass**: enable it and include all users or a group that contains the users. |
| `badRequest` about the lifetime | `TemporaryAccessPassLifetime` is outside the minimum and maximum lifetime of the policy (default 1 hour minimum, 8 hours maximum). | Change `TemporaryAccessPassLifetime`, or the lifetime range in the policy (**Configure** tab of the Temporary Access Pass policy; at most 30 days). |
| `badRequest` about one-time use | The connector requests a one-time pass (`isUsableOnce = true`). This is refused when the policy only allows passes that can be used more than once. | Set **Require one-time use** in the policy to *Yes*, or to *No* (both types allowed). |
| `403 Forbidden` | The app registration misses `UserAuthenticationMethod.ReadWrite.All`, or admin consent is missing. | Add the permission and grant admin consent. |

For more information:

- [Configure a Temporary Access Pass in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass)
- [temporaryAccessPassAuthenticationMethodConfiguration resource type](https://learn.microsoft.com/en-us/graph/api/resources/temporaryaccesspassauthenticationmethodconfiguration?view=graph-rest-1.0) (the policy settings in Microsoft Graph)

## Notifications

### Minimal notification template

A minimal MJML example is available in [temporaryAccessPass/notification.mjml](temporaryAccessPass/notification.mjml). Use this as a base template for customer-specific branding and wording.

### Notification variables

The following variables are available in notifications after TAP creation:

- `Data.temporaryAccessPass`: the generated Temporary Access Pass value.
- `Data.validUntil`: the TAP validity end date/time (Dutch format, without seconds).

## Development resources

### GraphAPI documentation

The following Microsoft Graph API endpoint is used by the Temporary Access Pass feature:

- Endpoint: `/users/{id}/authentication/temporaryAccessPassMethods`
  Description: Create and manage TAP credentials
  Method: `POST`

For more information, refer to Microsoft's official documentation:

- [Temporary Access Pass API Documentation](https://learn.microsoft.com/en-us/graph/api/resources/temporaryaccesspass?view=graph-rest-1.0)
- [Create Temporary Access Pass](https://learn.microsoft.com/en-us/graph/api/authentication-post-temporaryaccesspassmethods?view=graph-rest-1.0&tabs=http)
