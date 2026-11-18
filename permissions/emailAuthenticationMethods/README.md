# Email authentication method

Registers an email address as authentication method (used for self-service password reset) for the account via Microsoft Graph.

- **Permission:** one permission, `email authentication method - email`.
- **Email address:** `$email` at the top of `grantPermission.ps1`, default `Person.Contact.Personal.Email`.
- **Grant:** with `$onlySetEmailWhenEmpty = $true` (default) an existing address is not overwritten. When the person has no email address, the grant fails with a clear error.
- **Revoke:** with `$removeWhenRevokingEntitlement = $false` (default) the email method stays registered.

| Script                 | Action                                                   |
| ---------------------- | -------------------------------------------------------- |
| `permissions.ps1`      | Lists the email method as permission                     |
| `grantPermission.ps1`  | Adds or updates the email method                          |
| `revokePermission.ps1` | Removes the email method (only when configured to do so) |

## Required permissions

API permissions (Microsoft Graph, application):

| Permission                               | Used for                                                     |
| ---------------------------------------- | ------------------------------------------------------------ |
| `UserAuthenticationMethod.ReadWrite.All` | Reading, adding, updating and removing the email method. The narrower `UserAuthMethod-Email.ReadWrite.All` is also sufficient |
| `User.Read.All`                          | Reading the account. Included in `User.ReadWrite.All` of the account scripts |
