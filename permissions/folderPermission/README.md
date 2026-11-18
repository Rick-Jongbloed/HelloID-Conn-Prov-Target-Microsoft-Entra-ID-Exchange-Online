# Calendar folder permissions

Sets the access right of a user (by default `Default`, meaning everyone in the organization) on the calendar of the account's own mailbox. This determines how much others see of the account's calendar.

- **Permissions:** one per access right: `AvailabilityOnly`, `LimitedDetails`, `Reviewer` and `Editor` (see [Set-MailboxFolderPermission](https://learn.microsoft.com/en-us/powershell/module/exchange/set-mailboxfolderpermission)). Adjust `permissions.ps1` to offer other users or access rights.
- **Grant:** looks up the calendar folder (its name depends on the mailbox language, e.g. `Calendar` or `Agenda`) and sets the access right.
- There is **no revoke script**: the access right stays as it is when the entitlement is revoked. Grant a different access right to change it.

| Script                | Action                                                                  |
| --------------------- | ----------------------------------------------------------------------- |
| `permissions.ps1`     | Lists the access rights as permissions                                  |
| `grantPermission.ps1` | Sets the access right on the calendar (`Get-MailboxFolderStatistics`, `Set-MailboxFolderPermission`) |

## Required permissions

These scripts use the [Exchange Online Admin API](https://learn.microsoft.com/en-us/exchange/reference/admin-api-overview) (REST). The ExchangeOnlineManagement module is not used and no Microsoft Graph permissions are needed.

| Type                                                   | Permission                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| API permission (Office 365 Exchange Online, application) | `Exchange.ManageAsApp`                                        |
| Entra ID role assigned to the app registration         | **Exchange Recipient Administrator**                          |
