# Resources: Entra ID groups

`resources.ps1` creates Entra ID groups that do not exist yet, based on the resource data (`ExternalId` and `DisplayName` of the source data, e.g. departments). The created groups can then be used with the [groups](../../permissions/groups/README.md) permission scripts.

## Required permissions

API permissions (Microsoft Graph, application):

| Permission            | Used for                             |
| --------------------- | ------------------------------------ |
| `Group.ReadWrite.All` | Listing existing groups and creating new groups |
