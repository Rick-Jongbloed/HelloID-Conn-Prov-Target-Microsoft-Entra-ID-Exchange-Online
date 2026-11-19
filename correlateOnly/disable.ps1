##################################################
# HelloID-Conn-Prov-Target-MS-Entra-Exo-Disable
# Correlate only - Reconciliation support
# PowerShell V2
##################################################

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
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
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

try {
    $revokeSignInSessions = [bool]$actionContext.Configuration.revokeSignInSessionsOnDisable

    # Nothing to do for other origins than Reconciliation, unless revoking sign-in sessions is enabled
    if ($actionContext.Origin -ne 'Reconciliation' -and -not $revokeSignInSessions) {
        Write-Information "Skipping action. [Origin] = [$($actionContext.Origin)]"
        $outputContext.Success = $true
        return
    }

    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    # Setup Connection with Entra ID
    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    Write-Information 'Verifying if a MS-Entra account exists'

    # Get Entra account with onPremisesSyncEnabled property
    $actionMessage = 'querying MS-Entra account'
    try {
        $correlatedAccountEntra = $null
        $splatGetEntraUser = @{
            Uri     = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)?`$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled"
            Method  = 'GET'
            Headers = @{'Authorization' = "Bearer $($entraToken)" }
        }
        $correlatedAccountEntra = Invoke-RestMethod @splatGetEntraUser -Verbose:$false
        $outputContext.PreviousData = $correlatedAccountEntra | Select-Object -Property *
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            $correlatedAccountEntra = $null
        }
        else {
            throw $_
        }
    }

    if ($null -eq $correlatedAccountEntra) {
        throw 'MS-Entra account not found'
    }

    # Revoke sign-in sessions. Runs for every origin and also for AD synced accounts.
    # This happens before the disable, so sessions are also revoked when the disable is blocked for AD synced accounts.
    if ($revokeSignInSessions) {
        # API docs: https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0&tabs=http
        $actionMessage = "revoking sign in sessions of MS-Entra account with AccountReference [$($actionContext.References.Account)]"
        $revokeUserSignInSplatParams = @{
            Uri         = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)/revokeSignInSessions"
            Headers     = @{'Authorization' = "Bearer $($entraToken)" }
            ContentType = 'application/json;charset=utf-8'
            Method      = 'POST'
            Verbose     = $false
            ErrorAction = 'Stop'
        }
        if (-not($actionContext.DryRun -eq $true)) {
            $null = Invoke-RestMethod @revokeUserSignInSplatParams
        }
        else {
            Write-Information "Dry run: would revoke sign in sessions of MS-Entra account [$($actionContext.References.Account)]"
        }

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = "Revoking sign in sessions of MS-Entra account [$($actionContext.References.Account)] was successful"
                IsError = $false
            })
    }

    # Only process disable action when triggered from Reconciliation
    if ($actionContext.Origin -eq 'Reconciliation') {
        # Check if account is synchronized from on-premises
        $actionMessage = "disabling MS-Entra account with AccountReference [$($actionContext.References.Account)]"
        if ($correlatedAccountEntra.onPremisesSyncEnabled -eq $true) {
            throw "Cannot disable user synchronized from on-premises Active Directory"
        }

        # Disable cloud-only account
        Write-Information "Disabling cloud-only MS-Entra account with accountReference: [$($actionContext.References.Account)]"

        $bodyUpdateAccountEntra = @{
            accountEnabled = $false
        }

        $splatUpdateEntraAccount = @{
            Uri         = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)"
            Method      = 'PATCH'
            Body        = $bodyUpdateAccountEntra | ConvertTo-Json -Depth 10
            ContentType = 'application/json;charset=utf-8'
            Headers     = @{'Authorization' = "Bearer $($entraToken)" }
        }

        if (-not($actionContext.DryRun -eq $true)) {
            $null = Invoke-RestMethod @splatUpdateEntraAccount -Verbose:$false
        }

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = 'Disable MS-Entra account was successful (reconciliation)'
                IsError = $false
            })
    }

    $outputContext.Success = $true
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
