# Inviting guest accounts

Creates accounts in Microsoft Entra ID as **guest users** (B2B collaboration) by sending an invitation via Microsoft Graph, instead of creating member accounts. Use it as a separate target connector: the create script, field mapping and configuration from this folder (without Exchange Online settings), and the other account scripts (update, enable, disable, delete) from the main connector. Without the `exchangeOnlineIntegration` setting those scripts only manage the Entra ID account.

| Script / file        | Action                                                                                         |
| -------------------- | ---------------------------------------------------------------------------------------------- |
| `create.ps1`         | Correlates an existing account, or invites the person as guest and updates the created account |
| `fieldMapping.json`  | Field mapping for the invitation (`invitedUser*`, `inviteRedirectUrl`, `sendInvitationMessage`) and the account fields |
| `configuration.json` | Configuration of the connector (`deleteAccount`, `setManagerOnCreate`, `updateManagerOnUpdate`, no Exchange Online) |

## How create works

1. **Correlation**: looks up the account on the correlation field (for example `employeeId`). When it is found, the account is correlated and nothing is invited.
2. **Invite**: `POST /invitations` with only the invitation fields (`invitedUserEmailAddress`, `invitedUserDisplayName`, `invitedUserMessageInfo`, `inviteRedirectUrl`, `sendInvitationMessage`). The guest account is created directly; the invitation itself can still be pending.
3. **Update**: `PATCH /users/{id}` with all other mapped fields, including the correlation field, so the next create correlates.
4. **Manager** (with `setManagerOnCreate`): the manager is looked up by `employeeId` = `Person.Manager.ExternalId`, because a manager reference is mostly not available for a guest account.

The e-mail address of the invitation is an external address of the person (default `Person.Contact.Personal.Email`). With `sendInvitationMessage` = `TRUE` Microsoft sends the invitation e-mail; set it to `FALSE` when the customer sends its own message.

## Required permissions

API permissions (Microsoft Graph, application):

| Permission           | Used for                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------ |
| `User.Invite.All`    | Inviting guest users (`POST /invitations`)                                                 |
| `User.ReadWrite.All` | Reading, correlating and updating the account. Included in the permissions of the account scripts |

## Required tenant settings

Inviting guests is also controlled by the **external collaboration settings** of the tenant. These are not API permissions: with the permission granted, the invitation is still refused when these settings do not allow it.

Microsoft Entra admin center > **External Identities** > **External collaboration settings**:

- **Guest invite settings**: must not be *No one in the organization can invite guest users including admins (most restrictive)*. Any of the other options allows the app to invite.
- **Collaboration restrictions**: the domains of the invited e-mail addresses must be allowed (not in the deny list, or in the allow list when *Allow invitations only to the specified domains* is used).

## Troubleshooting

| Error | Meaning | Solution |
| ----- | ------- | -------- |
| `Forbidden: Guest invitations not allowed for your company` | Guest invitations are disabled in the external collaboration settings (most restrictive option). | Change **Guest invite settings**, see [Required tenant settings](#required-tenant-settings). |
| `Forbidden: Guest invitations not allowed for your company`, while the external collaboration settings allow invitations | Microsoft refuses invitations to some domains, for example the reserved domain `example.com` (also in the admin center, there with *Insufficient privileges to complete the operation*). | Use a real e-mail address of the person. Check the mapping of `invitedUserEmailAddress`. |
| An error that the domain of the e-mail address is not allowed | The domain is blocked by the collaboration restrictions. | Allow the domain in **Collaboration restrictions**. |
| `403 Forbidden` / `Authorization_RequestDenied` without the message above | The app registration misses `User.Invite.All`, or admin consent is missing. | Add the permission and grant admin consent. |
| `Set Manager on create is enabled, but no manager account is found ...` | No account with `employeeId` = the manager's external id. The guest is created without manager. | Check that the manager's account has the `employeeId`. |

For more information:

- [Configure external collaboration settings](https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure)
- [Create invitation (Microsoft Graph)](https://learn.microsoft.com/en-us/graph/api/invitation-post?view=graph-rest-1.0)
