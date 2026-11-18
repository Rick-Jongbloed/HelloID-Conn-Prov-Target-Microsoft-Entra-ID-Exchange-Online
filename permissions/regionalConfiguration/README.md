# Regional configuration

Sets the language, date and time format and time zone of the account's mailbox.

- **Permissions:** one per configuration. The default is `MailboxRegionalConfiguration-NL`: language `nl-NL`, date format `dd-MM-yy`, time format `H:mm`, time zone `W. Europe Standard Time`, default folder names localized (e.g. `Inbox` becomes `Postvak IN`).
- To add a configuration, add a permission to `permissions.ps1` and an entry with the same id to `$regionalConfigurations` in `grantPermission.ps1`.
- There is **no revoke script**: the configuration stays as it is when the entitlement is revoked.

| Script                | Action                                                                 |
| --------------------- | ---------------------------------------------------------------------- |
| `permissions.ps1`     | Lists the regional configurations as permissions                      |
| `grantPermission.ps1` | Applies the configuration (`Set-MailboxRegionalConfiguration`)        |

## Required permissions

These scripts use the [Exchange Online Admin API](https://learn.microsoft.com/en-us/exchange/reference/admin-api-overview) (REST). The ExchangeOnlineManagement module is not used and no Microsoft Graph permissions are needed.

| Type                                                   | Permission                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| API permission (Office 365 Exchange Online, application) | `Exchange.ManageAsApp`                                        |
| Entra ID role assigned to the app registration         | **Exchange Recipient Administrator**                          |

## Remarks

### Invalid formats
Exchange Online can take more than 30 seconds to return an error for an invalid date or time format. The action then fails with a timeout instead of a clear error. Test a new configuration on one account first.
