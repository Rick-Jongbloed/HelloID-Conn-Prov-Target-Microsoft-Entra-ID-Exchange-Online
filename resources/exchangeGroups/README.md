# Resources: Exchange distribution groups

`resources.ps1` creates distribution groups in Exchange Online, based on the resource data (`ExternalId` and `DisplayName` of the source data, for example departments). The distribution groups are used by the dynamic permissions in [permissions/exchangeGroups](../../permissions/exchangeGroups/README.md). The script uses the [Exchange Online Admin API](https://learn.microsoft.com/en-us/exchange/reference/admin-api-overview) (REST), not the ExchangeOnlineManagement module.

## How it works

1. All distribution groups are retrieved (`Get-DistributionGroup` with `-Filter "IsDirSynced -eq 'False'"`).
2. For every unique resource the distribution group with `CustomAttribute1` = `ExternalId` is looked up. Found: correlated, nothing changes (also not the name).
3. Not found: `New-DistributionGroup` creates the distribution group, then `Set-DistributionGroup` sets `CustomAttribute1` = `ExternalId` and `CustomAttribute2` = `HelloID Dynamic Distribution Group` (these cannot be set at creation). A new distribution group is not always found directly, so *not found* is retried within the time limit.

| Property | Value | Example (`DisplayName` = Human Resources - Zuid) |
| -------- | ----- | ------- |
| Name, DisplayName | `dg_` + `DisplayName` (max. 64 characters) | `dg_Human Resources - Zuid` |
| Alias, e-mail address | `dg_` + sanitized `DisplayName` @ `Organization` from the configuration | `dg_Human_Resources_Zuid@contoso.onmicrosoft.com` |
| `CustomAttribute1` | `ExternalId` of the resource (correlation) | `D02` |
| `CustomAttribute2` | `HelloID Dynamic Distribution Group` (used by the import) | |

- When setting the attributes failed in an earlier run, the next run finds the distribution group on its e-mail address and sets them (no second distribution group).
- An e-mail address used by an object with another `CustomAttribute1`, or more than one distribution group with the same `CustomAttribute1`: an error, nothing is created for that resource.
- At most `$maximumAmountToCreatePerRun` (50) per run; the remaining resources are created in the next run. Resource scripts are not bound to the 30-second limit of an action; `$maximumRuntimeSeconds` (900) is only a safety limit.
- DryRun (preview) creates nothing and logs what would be created.
- Distribution groups are never renamed or removed by this script.

Adjust `$namePrefix`, the name and the attributes in the script when the customer uses another convention. `$correlationField` and `$markerValue` must match the sub permission scripts.

## Configuration

`Organization` (for example `contoso.onmicrosoft.com` or a verified domain) is used as domain of the e-mail address and is required.

## Required permissions

| Type                                                   | Permission                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| API permission (Office 365 Exchange Online, application) | `Exchange.ManageAsApp`                                        |
| Entra ID role assigned to the app registration         | **Exchange Recipient Administrator**                          |
