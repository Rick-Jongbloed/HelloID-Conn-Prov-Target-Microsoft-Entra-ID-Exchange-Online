# Resources: Microsoft Teams

`resources.ps1` creates Microsoft Teams that do not exist yet, based on the resource data (`ExternalId` and `DisplayName` of the source data, e.g. departments). The owner is the Entra ID user set in `$ownerAccountId` in the script.

## Required permissions

API permissions (Microsoft Graph, application):

| Permission           | Used for                                   |
| -------------------- | ------------------------------------------ |
| `Team.ReadBasic.All` | Listing the existing teams                 |
| `Team.Create`        | Creating teams                             |
| `User.Read.All`      | Binding the owner. Included in `User.ReadWrite.All` of the account scripts |
