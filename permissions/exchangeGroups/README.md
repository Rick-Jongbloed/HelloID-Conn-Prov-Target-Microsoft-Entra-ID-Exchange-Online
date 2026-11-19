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
| `subPermissions.ps1`   | Grants and revokes groups dynamically, based on the contracts of the person |
| `subPermissionsImport.ps1` | Imports the memberships of the HelloID groups as sub permissions (entitlement import) |

## Dynamic permissions (sub permissions)

`subPermissions.ps1` determines the groups from the contracts of the person, like the dynamic permissions of the Exchange Online connector:

1. For every contract in conditions, the group is the group where `CustomAttribute1` = `Department.ExternalId` of the contract (server-side filter, groups synchronized from on-premises are skipped).
2. Not found or more than one: an audit log with an error, no grant for that contract.
3. Groups that are desired but not granted yet are granted; groups that were granted before (`CurrentPermissions`) but are no longer desired are revoked. Already a member (grant) or not a member (revoke) counts as success.

One dynamic permission in HelloID (for example *Exchange Online groups*) covers all groups of the person. The groups are created per department with the [resource script](../../resources/exchangeGroups/README.md), which sets `CustomAttribute1` and `CustomAttribute2`.

`subPermissionsImport.ps1` imports the members of the groups with `CustomAttribute2` = `HelloID Dynamic Distribution Group` as sub permissions of the permission with reference `exchangeGroups`. Use either the static import (`importPermission.ps1`) or this one for the same groups, not both.

> [!NOTE]
> Adjust `$correlationField` and the contract field (`Department.ExternalId`) in `subPermissions.ps1` when the groups are linked to something else, for example the title. The value must match what the resource script writes.

| Situation | Use |
| --------- | --- |
| A fixed set of groups, granted with business rules or requested in the self-service product | Static: `permissions.ps1`, `grantPermission.ps1`, `revokePermission.ps1`, `importPermission.ps1` |
| One group per department (or other contract field), automatically following the contracts | Resource script + `subPermissions.ps1` + `subPermissionsImport.ps1` |

## Required permissions

These scripts use the [Exchange Online Admin API](https://learn.microsoft.com/en-us/exchange/reference/admin-api-overview) (REST). The ExchangeOnlineManagement module is not used and no Microsoft Graph permissions are needed.

| Type                                                   | Permission                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| API permission (Office 365 Exchange Online, application) | `Exchange.ManageAsApp`                                        |
| Entra ID role assigned to the app registration         | **Exchange Recipient Administrator**                          |

## Remarks

The lookup in `subPermissions.ps1` and the import in `subPermissionsImport.ps1` use `-Filter` on `Get-DistributionGroup` via the beta `InvokeCommand` endpoint.
