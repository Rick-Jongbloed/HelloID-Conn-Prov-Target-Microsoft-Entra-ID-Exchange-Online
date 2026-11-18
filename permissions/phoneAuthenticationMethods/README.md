# Phone authentication methods

Registers a phone number as authentication method (MFA / SSPR) for the account via Microsoft Graph.

- **Permissions:** `mobile`, `alternateMobile` and `office` (one permission per phone type).
- **Phone number:** taken from the person: `mobile` and `alternateMobile` use `Person.Contact.Personal.Phone.Mobile`, `office` uses `Person.Contact.Business.Phone.Mobile`. Dutch numbers are converted to the international format (`+31...`).
- **Grant:** with `$onlySetMobileWhenEmpty = $true` (default) an existing number is not overwritten.
- **Revoke:** with `$removeWhenRevokingEntitlement = $false` (default) the phone method stays registered.

| Script                 | Action                                                  |
| ---------------------- | ------------------------------------------------------- |
| `permissions.ps1`      | Lists the phone types as permissions                    |
| `grantPermission.ps1`  | Adds or updates the phone method of the type             |
| `revokePermission.ps1` | Removes the phone method (only when configured to do so) |

## Required permissions

API permissions (Microsoft Graph, application):

| Permission                               | Used for                                                     |
| ---------------------------------------- | ------------------------------------------------------------ |
| `UserAuthenticationMethod.ReadWrite.All` | Reading, adding, updating and removing phone methods. The narrower `UserAuthMethod-Phone.ReadWrite.All` is also sufficient |
| `User.Read.All`                          | Reading the account. Included in `User.ReadWrite.All` of the account scripts |
