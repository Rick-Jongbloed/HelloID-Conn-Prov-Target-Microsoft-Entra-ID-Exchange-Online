#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-UniquenessCheck
# Check if fields are unique
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Script Configuration, only Required for ExchangeOnlineIntegration.
$entraMailboxFallbackLookupProperty = 'givenName'
$correlationValue = $personContext.Person.ExternalId

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
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
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

        # Ensure the certificate has a private key
        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

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
#endregion functions

#region Fields to check
$fieldsToCheck = [PSCustomObject]@{
    'userPrincipalName'             = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'userPrincipalName' # Name of the field in the system itself, to be used in the query to the system.
        accountValue    = $actionContext.Data.userPrincipalName
        keepInSyncWith  = @('mail', 'mailNickname') # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = @('mail') # Properties to cross-check for uniqueness.
    }
    'mail'                          = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'mail' # Name of the field in the system itself, to be used in the query to the system.
        accountValue    = $actionContext.Data.mail
        keepInSyncWith  = @('userPrincipalName', 'mailNickname') # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = @('userPrincipalName') # Properties to cross-check for uniqueness.
    }
    'mailNickname'                  = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'mailNickname' # Name of the field in the system itself, to be used in the query to the system.
        accountValue    = $actionContext.Data.mailNickname
        keepInSyncWith  = @('userPrincipalName', 'mail') # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = $null # Properties to cross-check for uniqueness.
    }
    'exchangeOnline.emailAddresses' = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'proxyAddresses' # Name of the field in the system itself, to be used in the query to the system.
        accountValue    = $actionContext.Data.exchangeOnline.emailAddresses
        keepInSyncWith  = @('userPrincipalName', 'mail', 'mailNickname') # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = $null # Properties to cross-check for uniqueness.
    }
}
#endregion Fields to check

try {
    # Setup Connection with Entra/Exo
    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    # Convert Base64 string to certificate
    $rawCertificate = [system.convert]::FromBase64String($actionContext.Configuration.AppCertificateBase64String)
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $actionContext.Configuration.AppCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

    # Create Entra ID headers
    $actionMessage = 'creating Entra ID headers'
    $entraIDHeaders = @{
        'Accept'           = 'application/json'
        'Content-Type'     = 'application/json;charset=utf-8'
        'ConsistencyLevel' = 'eventual'
    }
    Write-Information "Created Entra ID headers. Result (without Authorization): $($entraIDHeaders | ConvertTo-Json)."
    # Add Authorization after printing splat
    $entraIDHeaders['Authorization'] = "Bearer $($entraToken)"

    # Verify account reference
    if ($actionContext.Operation.ToLower() -ne 'create') {
        $actionMessage = 'verifying account reference'
        if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
            throw 'The account reference could not be found'
        }
    }
    else {
        if ([string]::IsNullOrEmpty($correlationValue)) {
            throw 'The correlation value could not be found on the person'
        }
        # Get Entra account on Fallback field to handle ExchangeOnlineIntegration where the correlation field is not yet populated
        $actionMessage = "querying MS-Entra account on fallback field where [$entraMailboxFallbackLookupProperty] = [$($correlationValue)]"
        $selectPropertiesToGetUser = ($outputContext.Data | Select-Object * -ExcludeProperty ExchangeOnline, managerId ).PSObject.Properties.Name -join ','
        $splatGetEntraUser = @{
            Uri     = "https://graph.microsoft.com/v1.0/users?`$filter=$entraMailboxFallbackLookupProperty eq '$($correlationValue)'&`$select=$selectPropertiesToGetUser"
            Method  = 'GET'
            Headers = @{'Authorization' = "Bearer $($entraToken)" }
        }
        $correlatedAccountEntraFallBack = (Invoke-RestMethod @splatGetEntraUser).value
        Write-Warning "correlatedAccountEntraFallBack: $($correlatedAccountEntraFallBack | ConvertTo-Json)"
        if ($correlatedAccountEntraFallBack.Count -eq 1) {
            $actionContext.References.Account = $correlatedAccountEntraFallBack.id
        }
    }

    foreach ($fieldToCheck in $fieldsToCheck.PsObject.Properties | Where-Object { -not[String]::IsNullOrEmpty($_.Value.accountValue) }) {
        #region Get Entra ID account
        $actionMessage = "calculating filter account for property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)]"

        # Custom check for exchangeOnline.emailAddresses to verify against proxyAddresses in Entra ID.
        # This is necessary to check in Entra ID (instead of Exchange Online) because changes in Exchange Online reflect in Entra ID, but not all changes in Entra ID reflect in Exchange Online.
        # Additionally, this check is unique as it deals with an array of values.
        $filter = $null
        if ($fieldToCheck.Value.systemFieldName -eq 'proxyAddresses') {
            foreach ($fieldToCheckAccountValue in $fieldToCheck.Value.accountValue) {
                if ($null -eq $filter) {
                    $filter = "$($fieldToCheck.Value.systemFieldName)/any(c:c eq '$($fieldToCheckAccountValue)')" 
                }
                else {
                    $filter = $filter + " OR $($fieldToCheck.Value.systemFieldName)/any(c:c eq '$($fieldToCheckAccountValue)')"
                }
            }
        }
        else {
            $filter = "$($fieldToCheck.Value.systemFieldName) eq '$($fieldToCheck.Value.accountValue)'" 
        }

        if (@($fieldToCheck.Value.crossCheckOn).Count -ge 1) {
            foreach ($fieldToCrossCheckOn in $fieldToCheck.Value.crossCheckOn) {
                $filter = $filter + " OR $($fieldToCrossCheckOn) eq '$($fieldToCheck.Value.accountValue)'"
            }
        }

        $actionMessage = "querying Entra ID account where [filter] = [$filter]"
        try {
            $correlatedAccount = $null
            $splatGetEntraUser = @{
                Uri    = "https://graph.microsoft.com/v1.0/users?`$filter=$($filter)&`$select=id,$($fieldToCheck.Value.systemFieldName)&`$count=true"
                Method = 'GET'
            }
            Write-Information "splatGetEntraUser: $($splatGetEntraUser | ConvertTo-Json)"
            # Add headers after printing splat
            $splatGetEntraUser['Headers'] = $entraIDHeaders
            $correlatedAccount = (Invoke-RestMethod @splatGetEntraUser -Verbose:$false).Value
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq 404) {
                throw "Entra Account [$($actionContext.References.Account)] could not be found, possibly indicating that it could be deleted"
            }
            else {
                throw $_
            }
        }
        Write-Information "Queried Entra ID account where [filter] = [$filter]. Result count: $(@($correlatedAccount).Count)"

        # Check property uniqueness
        $actionMessage = "checking if property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is unique"
        if (@($correlatedAccount).count -gt 0) {
            if ($actionContext.Operation.ToLower() -ne 'create' -and $correlatedAccount.id -eq $actionContext.References.Account) {
                Write-Information "Person is using property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] themselves."
            }
            else {
                Write-Information "Property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is not unique. In use by account with ID: $($correlatedAccount.id)"
                [void]$outputContext.NonUniqueFields.Add($fieldToCheck.Name)
                if (@($fieldToCheck.Value.keepInSyncWith).Count -ge 1) {
                    foreach ($fieldToKeepInSyncWith in $fieldToCheck.Value.keepInSyncWith | Where-Object { $_ -in $actionContext.Data.PsObject.Properties.Name }) {
                        [void]$outputContext.NonUniqueFields.Add($fieldToKeepInSyncWith)
                    }
                }
            }
        }
        elseif (@($correlatedAccount).count -eq 0) {
            Write-Information "Property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is unique."
        }
    }

    # Set Success to true
    $outputContext.Success = $true
}
catch {
    $outputContext.Success = $false
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
    # Required to write an error as uniqueness check doesn't show auditlog
    Write-Error $auditMessage
}
finally {
    $outputContext.NonUniqueFields = @($outputContext.NonUniqueFields | Sort-Object -Unique)
}
