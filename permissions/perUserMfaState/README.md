# Per-user MFA state

Sets the per-user MFA state of the account via Microsoft Graph.

> [!CAUTION]
> The `perUserMfaState` scripts rely on a **Beta** endpoint. APIs in the Beta version are subject to change, and **we do not recommend using them in production applications** until Microsoft releases a stable version.
> For more details, see: [Microsoft Graph Beta API Overview](https://learn.microsoft.com/nl-nl/graph/api/overview?view=graph-rest-beta).

- **Permission:** one permission, `perUserMFAState - Enabled`.
- **Grant:** sets the state to `enabled` when it is `disabled`. An account that is already `enabled` or `enforced` is skipped.
- **Revoke:** sets the state to `disabled`.

| Script                 | Action                               |
| ---------------------- | ------------------------------------ |
| `permissions.ps1`      | Lists the MFA state as permission    |
| `grantPermission.ps1`  | Sets the per-user MFA state to enabled |
| `revokePermission.ps1` | Sets the per-user MFA state to disabled |

## Required permissions

API permissions (Microsoft Graph, application):

| Permission                             | Used for                                                                 |
| -------------------------------------- | ------------------------------------------------------------------------ |
| `Policy.ReadWrite.AuthenticationMethod` | Reading and updating the per-user MFA state (`/beta/users/{id}/authentication/requirements`) |
| `User.Read.All`                        | Reading the account. Included in `User.ReadWrite.All` of the account scripts |

See [Enable per-user Microsoft Entra multifactor authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates#use-microsoft-graph-to-manage-per-user-mfa).
