# Microsoft Teams Channels

## Supported features

The following features are available:

| Feature                                   | Supported | Actions                             | Remarks            |
| ----------------------------------------- | --------- | ----------------------------------- | ------------------ |
| **Account Lifecycle**                     | ✅         | Correlate                           |                    |
| **Permissions**                           | ✅         | Retrieve, Grant, Revoke             | Static             |
| **Resources**                             | ❌         | -                                   |                    |
| **Entitlement Import: Permissions**       | ✅         | -                                   |                    |
| **Governance Reconciliation Resolutions** | ✅⚠️       | -                                   |                    |

### ⚠️ Governance Reconciliation Resolutions

Governance reconciliation is supported for permissions only. Accounts are dependent on the use of the Entra ID connector

## Required permissions

API permissions (Microsoft Graph, application):

| Permission                    | Used for                                                          |
| ----------------------------- | ----------------------------------------------------------------- |
| `GroupMember.Read.All`        | Listing the teams (`/groups` filtered on `resourceProvisioningOptions`) |
| `Channel.ReadBasic.All`       | Listing the private and shared channels of the teams              |
| `ChannelMember.ReadWrite.All` | Listing, adding and removing channel members                      |

## Remarks

### Members of private channels

You can only add a member to a private channel once it's member of the team of which the channel is part of. Team memberships can be provisions using the default group memberships. Once there is no order in which permissions will be provisioned. You can get an error that the user is not member of the team when they get provisioned in the same enforcement.

## Development resources

### API endpoints

The following endpoints are used by the connector

| Endpoint                           | Description                                                  |
| ---------------------------------- | ------------------------------------------------------------ |
| /groups                            | Retrieve teams                                               |
| /teams/{teamId}/channels           | Retrieve channels and members                                |
