#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-RegionalConfiguration
# List mailbox regional configuration options as permissions
# PowerShell V2
#####################################################

# The settings per option are defined in grantPermission.ps1
$outputContext.Permissions.Add(
    @{
        displayName    = 'Mailbox Regional Configuration - NL'
        identification = @{
            Id = 'MailboxRegionalConfiguration-NL'
        }
    }
)
