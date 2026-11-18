# Shared mailboxes

Grants an account rights on a shared mailbox in Exchange Online.

- **Permissions:** three per shared mailbox: `Shared Mailbox - <name> - Full Access`, `- Send As` and `- Send on Behalf`. The `Id` is the `ExternalDirectoryObjectId` of the mailbox.
- **Full Access** (`Add/Remove-MailboxPermission`) and **Send As** (`Add/Remove-RecipientPermission`) use the beta `InvokeCommand` endpoint; after the change the script checks that the right is visible (or gone) before it reports success. **Send on Behalf** uses the v2.0 `Mailbox` endpoint (`Set-Mailbox -GrantSendOnBehalfTo`).
- Grant and revoke are idempotent: a right that is already present (grant) or already gone (revoke) counts as success.
- All requests for one shared mailbox are routed to the same Exchange backend server (`X-AnchorMailbox: Oid:<mailbox id>@<tenant id>`).

| Script                 | Action                                                                  |
| ---------------------- | ----------------------------------------------------------------------- |
| `permissions.ps1`      | Lists the shared mailboxes as permissions (three per mailbox)           |
| `grantPermission.ps1`  | Grants Full Access, Send As or Send on Behalf                            |
| `revokePermission.ps1` | Revokes Full Access, Send As or Send on Behalf                           |
| `importPermission.ps1` | Imports the current rights (entitlement import), explicit rights only   |

## Required permissions

These scripts use the [Exchange Online Admin API](https://learn.microsoft.com/en-us/exchange/reference/admin-api-overview) (REST). The ExchangeOnlineManagement module is not used and no Microsoft Graph permissions are needed.

| Type                                                   | Permission                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| API permission (Office 365 Exchange Online, application) | `Exchange.ManageAsApp`                                        |
| Entra ID role assigned to the app registration         | **Exchange Recipient Administrator**                          |

## Remarks

### Send As after large batches
When Exchange Online switches backend server between consecutive Send As changes on the same mailbox, the newest changes can be overwritten without an error. Check Send As after large batches (first enforcement, a business rule for a whole department). See the CHANGELOG (Known limitations).
