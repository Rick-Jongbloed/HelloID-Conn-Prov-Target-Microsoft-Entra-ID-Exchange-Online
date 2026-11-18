# Phone authentication methods

Registers a phone number as authentication method (MFA / SSPR) for the account via Microsoft Graph.

- **Permissions:** `mobile`, `alternateMobile` and `office` (one permission per phone type).
- **Phone number:** every type has its own person field in `$phoneNumberMapping` at the top of `grantPermission.ps1`. Default: `mobile` = `Person.Contact.Personal.Phone.Mobile`, `alternateMobile` = `Person.Contact.Business.Phone.Mobile`, `office` = `Person.Contact.Business.Phone.Fixed`. Adjust this to the source data of the customer. Dutch numbers are converted to the international format (`+31...`).
- **Grant:** with `$onlySetMobileWhenEmpty = $true` (default) an existing number is not overwritten. When the person has no number for the type, the grant fails with a clear error.
- **alternateMobile:** Microsoft only accepts it when the account already has a `mobile` phone method.
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
