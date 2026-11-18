# Entra ID groups

Manages the membership of an account in Microsoft 365 groups and Entra ID security groups via Microsoft Graph.

- **Groups in scope:** Microsoft 365 groups (`Unified`) and security groups that are cloud-only, not dynamic and not mail-enabled. Mail-enabled security groups and distribution groups are managed in Exchange Online, see [exchangeGroups](../exchangeGroups/README.md).
- **Static permissions:** every group is a permission (`Id` = object id of the group).
- **Sub permissions (dynamic):** `subPermissions.ps1` determines the groups from the contract data of the person. By default it looks up the group with display name `department_<department>`. Adjust the correlation in the script to the customer's naming convention.

| Script                     | Action                                                                  |
| -------------------------- | ----------------------------------------------------------------------- |
| `permissions.ps1`          | Lists the groups as permissions                                         |
| `grantPermission.ps1`      | Adds the account as member (`POST /groups/{id}/members/$ref`)           |
| `revokePermission.ps1`     | Removes the account as member (`DELETE /groups/{id}/members/{id}/$ref`) |
| `importPermission.ps1`     | Imports the current memberships (entitlement import)                    |
| `subPermissions.ps1`       | Grants and revokes groups dynamically, based on the contracts           |
| `subPermissionsImport.ps1` | Imports the current memberships for the sub permissions                 |
| `filterExamples/`          | Example import scripts that filter on member or guest accounts          |

## Required permissions

API permissions (Microsoft Graph, application):

| Permission                  | Used for                                                       |
| --------------------------- | -------------------------------------------------------------- |
| `GroupMember.ReadWrite.All` | Listing groups and members, adding and removing members        |
| `User.Read.All`             | Reading the account. Included in `User.ReadWrite.All` of the account scripts |

> [!NOTE]
> For **role-assignable groups** the app registration also needs `RoleManagement.ReadWrite.Directory`. Only add this when role-assignable groups must be managed, because it allows assigning admin roles.
