# Exchange groups

Manages the membership of an account in distribution groups and mail-enabled security groups in Exchange Online. These groups cannot be managed via Microsoft Graph, see [groups](../groups/README.md) for Microsoft 365 groups and security groups.

- **Permissions:** every distribution group and mail-enabled security group is a permission. The `Id` is the `ExchangeObjectId` of the group (the `Guid` can change during a tenant relocation). Grant and revoke also accept the `Guid` of existing entitlements.
- Grant and revoke are idempotent: already a member (grant) or not a member (revoke) counts as success.

| Script                 | Action                                                         |
| ---------------------- | -------------------------------------------------------------- |
| `permissions.ps1`      | Lists the groups as permissions                                |
| `grantPermission.ps1`  | Adds the account as member (`Add-DistributionGroupMember`)     |
| `revokePermission.ps1` | Removes the account as member (`Remove-DistributionGroupMember`) |
| `importPermission.ps1` | Imports the current memberships (entitlement import)           |

## Required permissions

These scripts use the [Exchange Online Admin API](https://learn.microsoft.com/en-us/exchange/reference/admin-api-overview) (REST). The ExchangeOnlineManagement module is not used and no Microsoft Graph permissions are needed.

| Type                                                   | Permission                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| API permission (Office 365 Exchange Online, application) | `Exchange.ManageAsApp`                                        |
| Entra ID role assigned to the app registration         | **Exchange Recipient Administrator**                          |
