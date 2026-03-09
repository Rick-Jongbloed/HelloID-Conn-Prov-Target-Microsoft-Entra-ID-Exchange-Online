##############################################################################
# HelloID-Conn-Prov-Target-MS-Entra-Exo-Permissions-PhoneAuthenticationMethods
# PowerShell V2
##############################################################################
# Please see the Microsoft docs on supported phone types: https://learn.microsoft.com/nl-nl/graph/api/phoneauthenticationmethod-get?view=graph-rest-1.0&tabs=http#http

$outputContext.Permissions.Add(
    @{
        DisplayName    = "phone authentication method - mobile"
        Identification = @{
            Reference = "3179e48a-750b-4051-897c-87b9720928f7"
            Type      = "mobile"
        }
    }
)
$outputContext.Permissions.Add(
    @{
        DisplayName    = "phone authentication method - alternateMobile"
        Identification = @{
            Reference = "b6332ec1-7057-4abe-9331-3d72feddfe41"
            Type      = "alternateMobile"
        }
    }
)
$outputContext.Permissions.Add(
    @{
        DisplayName    = "phone authentication method - office"
        Identification = @{
            Reference = "e37fc753-ff3b-4958-9484-eaa9425c82bc"
            Type      = "office"
        }
    }
)