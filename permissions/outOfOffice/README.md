# Out of Office permission

This permission toggles the out of office reply on the mailbox:

| Script                  | Action                                                                              |
| ----------------------- | ----------------------------------------------------------------------------------- |
| `grantPermission.ps1`   | Disables the out of office reply and clears the internal and external message       |
| `revokePermission.ps1`  | Enables the out of office reply with the message from the configuration (internal and external) |

Typical use: grant the entitlement while the person is in service, so the reply is off. When it is revoked, for example at the end of the employment, the reply is turned on with the configured message.

## Configuration

The out of office message used by `revokePermission.ps1` is read from the configuration key `OutOfOfficeReply`. This field is **not** part of the default `configuration.json`, so it must be added to the configuration of the target system (**Custom connector configuration**) before using the revoke script.

Add the following multiline element to the configuration:

```json
{
  "key": "OutOfOfficeReply",
  "type": "textarea",
  "defaultValue": "",
  "templateOptions": {
    "label": "Out of office reply",
    "placeholder": "Please enter the out of office message",
    "description": "Message that is set as internal and external out of office reply when the entitlement is revoked. Line breaks are converted to HTML line breaks.",
    "required": false,
    "rows": 5
  }
}
```

> [!NOTE]
> Separate multiple configuration elements in the JSON array with a comma. When the `OutOfOfficeReply` value is empty, the revoke script returns an error.

## Required permissions

These scripts use the [Exchange Online Admin API](https://learn.microsoft.com/en-us/exchange/reference/admin-api-overview) (REST). The ExchangeOnlineManagement module is not used and no Microsoft Graph permissions are needed.

| Type                                                   | Permission                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------- |
| API permission (Office 365 Exchange Online, application) | `Exchange.ManageAsApp`                                        |
| Entra ID role assigned to the app registration         | **Exchange Recipient Administrator**                          |
