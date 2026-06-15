############################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-EducationalGroups-Members-Permissions
# PowerShell V2
############################################################

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
    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    $headers.Add('Authorization', "Bearer $entraToken")
    $headers.Add('Accept', 'application/json')
    $headers.Add('Content-Type', 'application/json')
    # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
    $headers.Add('ConsistencyLevel', 'eventual')

    $actionMessage = 'Retrieving permissions'
    Write-Information $actionMessage

    $baseUriM365Group = "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,resourceProvisioningOptions&`$top=999"
    $nextLink = $baseUriM365Group

    $schoolyear = Get-SchoolYear

    do {
        $getMicrosoftEntraIDM365GroupsSplatParams = @{
            Uri     = $nextLink
            Headers = $headers
            Method  = 'GET'
            Verbose = $false
        }
        $microsoftEntraIDM365Groups = Invoke-RestMethod @getMicrosoftEntraIDM365GroupsSplatParams

        foreach ($permission in ($microsoftEntraIDM365Groups.value | Where-Object { $_.resourceProvisioningOptions -contains "Team" -and $_.displayName -like "*_$($schoolyear)" })) {
            $displayName = "$($permission.displayName)"
            $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length))
            $outputContext.Permissions.Add(
                @{
                    DisplayName    = $displayName
                    Identification = @{
                        Id = $permission.id
                    }
                }
            )
        }
        $nextLink = $microsoftEntraIDM365Groups.'@odata.nextLink'
    } while (-not [string]::IsNullOrEmpty($nextLink))


    
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