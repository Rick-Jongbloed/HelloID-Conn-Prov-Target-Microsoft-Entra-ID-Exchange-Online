#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-OutOfOffice
# List the Out of Office reply as permission (grant disables, revoke enables the reply)
# PowerShell V2
#####################################################

$outputContext.Permissions.Add(
    @{
        displayName    = 'Out Of Office reply'
        identification = @{
            Id = 'OutOfOffice'
        }
    }
)
