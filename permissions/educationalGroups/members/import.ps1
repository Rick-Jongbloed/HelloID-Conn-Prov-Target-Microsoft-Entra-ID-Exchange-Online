####################################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-EducationalGroups-Members-ImportPermissions
# PowerShell V2
####################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Resolve-MS-Entra-ExoError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }

        try {
            if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
                $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message | ConvertFrom-Json
            }
            elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
                if ($null -ne $ErrorObject.Exception.Response) {
                    $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                    if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                        $httpErrorObj.ErrorDetails = $streamReaderResponse
                    }
                }
            }
            $errorDetailsObject = $httpErrorObj.ErrorDetails
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        # Get the DER encoded bytes of the certificate
        $derBytes = $Certificate.RawData

        # Compute the SHA-256 hash of the DER encoded bytes
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create a JWT (JSON Web Token) header
        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$($actionContext.Configuration.AppId)"
            'sub' = "$($actionContext.Configuration.AppId)"
            'aud' = "https://login.microsoftonline.com/$($actionContext.Configuration.TenantID)/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Extract the private key from the certificate
        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        # Sign the JWT
        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create the JWT token
        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $actionContext.Configuration.AppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($actionContext.Configuration.TenantID)/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($actionContext.Configuration.AppCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $actionContext.Configuration.AppCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-SchoolYear {
    # Calculate school year dependencies
    # School year definition in numbers of 4 or 2 digits
    $schoolYearLength = 2 # Length of school year used in the Teams name - e.g. 24-25 for 2 or 2024-2025 for 4
    $schoolYearSeperator = "" # Used in the Teams name - can be empty
    
    if ($schoolYearLength -eq 2) { $format = "yy" } else { $format = "yyyy" }
    
    $monthcurrent = (Get-Date).Month
    $yearcurrent = (Get-Date).ToString($format)
    $yearprevious = ([int]$yearcurrent - 1).ToString()
    $yearnext = ([int]$yearcurrent + 1).ToString()
    
    If ($monthcurrent -ge 8) {
        $schoolyear = $yearcurrent + $schoolYearSeperator + $yearnext
    }
    else {
        $schoolyear = $yearprevious + $schoolYearSeperator + $yearcurrent
    }
    return $schoolyear
}
#endregion functions

try {
    $schoolyear = Get-SchoolYear
    $filter = "*$schoolyear"

    # Setup Connection with Entra/Exo
    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    $headers.Add('Authorization', "Bearer $entraToken")
    $headers.Add('Accept', 'application/json')
    $headers.Add('Content-Type', 'application/json')
    # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
    $headers.Add('ConsistencyLevel', 'eventual')

    # API docs: https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying Educational groups"
    $uriGroups = "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c+eq+'Unified')&`$select=id,displayName,description,resourceProvisioningOptions&`$top=999"
    $m365GroupCount = 0
    do {
        $getM365GroupsSplatParams = @{
            Uri         = $uriGroups
            Headers     = $headers
            Method      = 'GET'
            ContentType = 'application/json; charset=utf-8'
            Verbose     = $false
            ErrorAction = "Stop"
        }
        $m365GroupsResponse = Invoke-RestMethod @getM365GroupsSplatParams
        #foreach ($entraIDGroup in ($m365GroupsResponse.value | Where-Object { $_.displayName -like "$filter" })) {
        foreach ($entraIDGroup in ($m365GroupsResponse.value | Where-Object { $_.resourceProvisioningOptions -contains "Team" -and $_.displayName -like "$filter" })) {
        
            $actionMessage = "querying Educational group members"
            # Make sure the displayName has a value of max 100 char
            if (-not([string]::IsNullOrEmpty($entraIDGroup.displayName))) {
                $displayName = "$($entraIDGroup.displayName)"
                $displayName = $($displayName).substring(0, [System.Math]::Min(100, $($displayName).Length))
            }
            else {
                $displayName = "$($entraIDGroup.id)"
            }
            # Make sure the description has a value of max 100 char
            if (-not([string]::IsNullOrEmpty($entraIDGroup.description))) {
                $description = $($entraIDGroup.description).substring(0, [System.Math]::Min(100, $($entraIDGroup.description).Length))
            }
            else {
                $description = $null
            }

            # Only top = 500 to maximize the amount of account references returned to HelloID
            $uriMembers = "https://graph.microsoft.com/v1.0/groups/$($entraIDGroup.id)/members/microsoft.graph.user?`$select=id&`$top=500"
            do {
                $getM365GroupMembershipsSplatParams = @{
                    Uri         = $uriMembers
                    Headers     = $headers
                    Method      = 'GET'
                    ContentType = 'application/json; charset=utf-8'
                    Verbose     = $false
                    ErrorAction = "Stop"
                }
                $groupMembersResponse = Invoke-RestMethod @getM365GroupMembershipsSplatParams                
                $accountReferences = ($groupMembersResponse.value | Where-Object { $_.id -ne $actionContext.Configuration.ownerGuid }).id

                if ($accountReferences.count -gt 0) {
                    Write-Output @(
                        @{
                            AccountReferences   = @( $accountReferences )
                            PermissionReference = @{ Id = $entraIDGroup.id }                        
                            Description         = $description
                            DisplayName         = $displayName
                        }
                    )
                }
                $uriMembers = $groupMembersResponse.'@odata.nextLink'
            } while ($uriMembers)
            $m365GroupCount++
        }
        $uriGroups = $m365GroupsResponse.'@odata.nextLink'
    } while ($uriGroups)
    Write-Information "Successfully queried [$m365GroupCount] existing Educational groups"
    
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    Write-Warning $warningMessage
    Write-Error $auditMessage
}