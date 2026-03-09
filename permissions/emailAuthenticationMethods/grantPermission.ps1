##################################################################################
# HelloID-Conn-Prov-Target-MS-Entra-Exo-GrantPermission-EmailAuthenticationMethod
# PowerShell V2
##################################################################################

# Permission configuration
$onlySetEmailWhenEmpty = $true

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

# Begin
try {
    $actionMessage = "verifying account reference"
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference could not be found"
    }

    $email = $($personContext.Person.Contact.Business.Email)

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

    $actionMessage = 'verifying if a MS-Entra-Exo account exists'
    Write-Information $actionMessage
    try {
        $splatGetEntraUser = @{
            Uri     = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)?`$select=*"
            Method  = 'GET'
            Headers = @{'Authorization' = "Bearer $($entraToken)" }
        }
        $correlatedAccountEntra = Invoke-RestMethod @splatGetEntraUser -Verbose:$false
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            throw "Entra Account [$($actionContext.References.Account)] could not be found, possibly indicating that it could be deleted"
        }
        else {
            throw $_
        }
    }

    # Microsoft docs: https://learn.microsoft.com/nl-nl/graph/api/emailauthenticationmethod-get?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying email authentication methods for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"
    $splatGetCurrentEmailAuthenticationMethods = @{
        Uri     = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)/authentication/emailMethods"
        Headers = $headers
        Method  = 'GET'
        Verbose = $false
    }
    $currentEmailAuthenticationMethods = (Invoke-RestMethod @splatGetCurrentEmailAuthenticationMethods).Value
    $currentEmailAuthenticationMethod = ($currentEmailAuthenticationMethods | Where-Object { $_.id -eq "$($actionContext.References.Permission.Reference)" }).emailAddress

    if ($null -ne $correlatedAccountEntra) {
        $actionMessage = "calculating action"
        if (($currentEmailAuthenticationMethod | Measure-Object).count -eq 0) {
            $action = 'GrantPermission'
        }
        elseif ($onlySetEmailWhenEmpty -eq $true) {
            $action = "ExistingData-SkipUpdate"
        }
        elseif (($currentEmailAuthenticationMethod | Measure-Object).count -eq 1) {
            $currentEmailAuthenticationMethod = $currentEmailAuthenticationMethod.replace(" ", "")
            if ($currentEmailAuthenticationMethod -ne $email) {
                $action = "UpdatePermission"
            }
            else {
                $action = 'NoChanges'
            }
        }
    }
    else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'GrantPermission' {
            # Microsoft docs: https://learn.microsoft.com/nl-nl/graph/api/authentication-post-emailmethods?view=graph-rest-1.0&tabs=http
            $actionMessage = "creating email authentication method [email] for account to [$email]"
            Write-Information $actionMessage
            $createEmailAuthenticationMethodSplatParams = @{
                Uri     = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)/authentication/emailMethods"
                Method  = 'POST'
                Body    = @{
                    'emailAddress' = $email
                } | ConvertTo-Json -Depth 10
                Headers = $headers
                Verbose = $false
            }
            if (-Not($actionContext.DryRun -eq $true)) {
                $null = Invoke-RestMethod @createEmailAuthenticationMethodSplatParams
            }
            else {
                Write-Information "[DryRun] Grant MS-Entra-Exo EmailAutenticationMethod: [email] - [$($actionContext.References.Permission.Reference)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Grant EmailAutenticationMethod permission [$($actionContext.PermissionDisplayName)] was successful"
                    IsError = $false
                })
            break
        }

        'UpdatePermission' {
            # Microsoft docs: https://learn.microsoft.com/nl-nl/graph/api/emailauthenticationmethod-update?view=graph-rest-1.0&tabs=http
            $actionMessage = "updating email authentication method [email] for account to [$email]"
            Write-Information $actionMessage
            $updateEmailAuthenticationMethodSplatParams = @{
                Uri     = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)/authentication/emailMethods/$($actionContext.References.Permission.Reference)"
                Method  = 'PATCH'
                Body    = @{
                    'emailAddress' = $email
                } | ConvertTo-Json -Depth 10
                Verbose = $false
                Headers = $headers
            }

            if (-Not($actionContext.DryRun -eq $true)) {
                $null = Invoke-RestMethod @updateEmailAuthenticationMethodSplatParams
            }
            else {
                Write-Information "[DryRun] Update MS-Entra-Exo EmailAutenticationMethod : [email] to [$email]- [$($actionContext.References.Permission.Reference)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Update EmailAutenticationMethod permission [$($actionContext.PermissionDisplayName)] was successful"
                    IsError = $false
                })
            break
        }

        'NoChanges' {
            $actionMessage = "skipping setting email authentication method [email] for account"
            Write-Information $actionMessage
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Skipped setting email authentication method [$($actionContext.PermissionDisplayName)]. Reason: No changes"
                    IsError = $false
                })
            break
        }

        'ExistingData-SkipUpdate' {
            $actionMessage = "skipping setting email authentication method [email] for account"
            Write-Information $actionMessage
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Skipped setting email authentication method [$($actionContext.PermissionDisplayName)]. Reason: Configured to only update when empty but already contains data"
                    IsError = $false
                })
        }

        'NotFound' {
            Write-Information "MS-Entra account: [email] could not be found, possibly indicating that it already has been deleted"
            $outputContext.Success = $false
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "MS-Entra-Exo account: [$($actionContext.References.Account)] could not be found, possibly indicating that it already has been deleted"
                    IsError = $true
                })
            break
        }
    }
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