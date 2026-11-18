# Out of Office permission

This permission toggles the out of office reply on the mailbox:

| Script                  | Action                                                                              |
| ----------------------- | ----------------------------------------------------------------------------------- |
| `grantPermission.ps1`   | Disables the out of office reply and clears the internal and external message       |
| `revokePermission.ps1`  | Enables the out of office reply with the message from the configuration (internal and external) |

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
