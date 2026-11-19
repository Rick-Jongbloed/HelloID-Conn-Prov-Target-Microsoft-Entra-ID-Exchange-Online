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
| `subPermissions.ps1`   | Grants and revokes rights on shared mailboxes dynamically, based on the contracts of the person |
| `subPermissionsImport.ps1` | Imports the rights on the HelloID shared mailboxes as sub permissions (entitlement import) |

## Dynamic permissions (sub permissions)

`subPermissions.ps1` determines the shared mailboxes from the contracts of the person:

1. For every contract in conditions, the shared mailbox is the one where `CustomAttribute1` = `Department.ExternalId` of the contract.
2. Not found or more than one: an audit log with an error, no grant for that contract.
3. Mailboxes that are desired but not granted yet are granted; mailboxes granted before but no longer desired are revoked. Grant and revoke work the same as the static scripts, including the verification of Full Access and Send As.

The right is the **reference of the dynamic permission** in HelloID: create one dynamic permission per right, all with this script:

| Dynamic permission (example) | Reference |
| ---------------------------- | --------- |
| Shared mailboxes - Full Access | `FullAccess` |
| Shared mailboxes - Send As | `SendAs` |
| Shared mailboxes - Send on Behalf | `SendOnBehalf` |

The sub permissions are named `Shared Mailbox - <name> - Full Access` (or `- Send As`, `- Send on Behalf`), the same as the static permissions. In the preview of the script the reference can be empty; set `$permissionType` in the script to test it.

`subPermissionsImport.ps1` imports the explicit rights on the shared mailboxes with `CustomAttribute2` = `HelloID Dynamic Shared Mailbox`, as sub permissions of the three permissions above. Use either the static import (`importPermission.ps1`) or this one for the same mailboxes, not both.

The shared mailboxes are created per department with the [resource script](../../resources/sharedMailboxes/README.md), which sets `CustomAttribute1` and `CustomAttribute2`.

> [!NOTE]
> All mailboxes of one person are handled in one action of at most 25 seconds. Every Full Access or Send As change is verified, which takes a few seconds; a person with many shared mailboxes can need more than one run. HelloID retries the action.

## Required permissions

These scripts use the [Exchange Online Admin API](https://learn.microsoft.com/en-us/exchange/reference/admin-api-overview) (REST). The ExchangeOnlineManagement module is not used and no Microsoft Graph permissions are needed.

| Type                                                   | Permission                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| API permission (Office 365 Exchange Online, application) | `Exchange.ManageAsApp`                                        |
| Entra ID role assigned to the app registration         | **Exchange Recipient Administrator**                          |

## Remarks

The lookup in `subPermissions.ps1` and the import in `subPermissionsImport.ps1` use `-Filter` on `Get-Mailbox` via the beta `InvokeCommand` endpoint.

### Send As after large batches
When Exchange Online switches backend server between consecutive Send As changes on the same mailbox, the newest changes can be overwritten without an error. Check Send As after large batches (first enforcement, a business rule for a whole department). See the CHANGELOG (Known limitations).
