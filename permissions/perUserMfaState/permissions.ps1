#################################################
# HelloID-Conn-Prov-Target-MS-Entra-Exo-Permissions-PerUserMfaState-List
# List perUserMfaState as permissions
# Please see the Microsoft docs : https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates#use-microsoft-graph-to-manage-per-user-mfa
# PowerShell V2
#################################################

$outputContext.Permissions.Add(
    @{
        DisplayName    = "perUserMFAState - Enabled"
        Identification = @{
            Id = "perUserMFAStateEnabled"
        }
    }
)