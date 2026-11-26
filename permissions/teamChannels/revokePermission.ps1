#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Permissions-TeamsChannels-Revoke
# Revoke Teams channel membership for account
# PowerShell V2
#################################################

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
                $parsedErrorDetails = $ErrorObject.ErrorDetails.Message | ConvertFrom-Json
                if ($null -ne $parsedErrorDetails) {
                    $httpErrorObj.ErrorDetails = $parsedErrorDetails
                }
            }
            elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
                if ($null -ne $ErrorObject.Exception.Response) {
                    # Windows PowerShell 5.1 only fills ErrorDetails for a response with a Content-Length (Graph sends
                    # chunked responses), so the body is read from the response and parsed like ErrorDetails
                    $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                    if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                        $httpErrorObj.ErrorDetails = $streamReaderResponse
                        $parsedErrorDetails = $streamReaderResponse | ConvertFrom-Json
                        if ($null -ne $parsedErrorDetails) {
                            $httpErrorObj.ErrorDetails = $parsedErrorDetails
                        }
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

        # The RSA private key of the certificate: works for exportable and non-exportable keys (CSP and CNG)
        if (-not $Certificate.HasPrivateKey) {
            throw "The certificate does not have a private key."
        }
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if ($null -eq $rsa) {
            throw "The private key of the certificate is not an RSA key."
        }

        # Sign the JWT
        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
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
function Get-TeamsChannelMembers {
    # All direct members of a channel, following @odata.nextLink
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TeamId,
        [Parameter(Mandatory)][string]$ChannelId,
        [Parameter(Mandatory)][object]$Headers
    )
    $members = [System.Collections.Generic.List[object]]::new()
    $uri = "https://graph.microsoft.com/v1.0/teams/$($TeamId)/channels/$($ChannelId)/members"
    do {
        $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method 'GET' -Verbose:$false -ErrorAction 'Stop'
        foreach ($member in @($response.value)) { $members.Add($member) }
        $uri = $response.'@odata.nextLink'
    } while (-not [string]::IsNullOrEmpty($uri))
    Write-Output $members -NoEnumerate
}
#endregion functions

try {
    # Verify account reference
    $actionMessage = "verifying account reference"
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference could not be found"
    }

    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    $headers.Add('Authorization', "Bearer $entraToken")
    $headers.Add('Accept', 'application/json')
    $headers.Add('Content-Type', 'application/json')
    # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
    $headers.Add('ConsistencyLevel', 'eventual')

    # Get permission for account
    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/channel-list-members?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying members of teams channel [$($actionContext.PermissionDisplayName)] with id [$($actionContext.References.Permission.ChannelId)]"

    # All pages, so the account is also found in large channels
    $getPermissionResponse = [PSCustomObject]@{
        Value = Get-TeamsChannelMembers -TeamId $actionContext.References.Permission.TeamId -ChannelId $actionContext.References.Permission.ChannelId -Headers $headers
    }

    Write-Information "Queried members of teams channel [$($actionContext.PermissionDisplayName)] with id [$($actionContext.References.Permission.ChannelId)]. Result count: $(($getPermissionResponse.Value | Measure-Object).Count)"

    # Calulate action
    $permissionToRevoke = $null
    # Role can be Owner in array, or Member, but for some reason the API returns empty array for Member
    if ($actionContext.References.Permission.Role -eq "Member") {
        $permissionToRevoke = $getPermissionResponse.Value | Where-Object { $_.userId -eq $actionContext.References.Account -and ($_.roles -is [System.Array] -and $_.roles.Count -eq 0) }
    }
    else {
        $permissionToRevoke = $getPermissionResponse.Value | Where-Object { $_.userId -eq $actionContext.References.Account -and $_.roles -eq @($actionContext.References.Permission.Role) }
    }
    Write-Information "Filtered members for account with id [$($actionContext.References.Account)] and role [$($actionContext.References.Permission.Role)]. Result count: $(($permissionToRevoke | Measure-Object).Count)"

    $actionMessage = "calculating action"
    if (($permissionToRevoke | Measure-Object).count -eq 1) {
        $action = "Revoke"
    }
    elseif (($permissionToRevoke | Measure-Object).count -eq 0) {
        $action = "NotFound"
    }

    #region Process
    switch ($action) {
        "Revoke" {
            # Revoke permission for account
            # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/channel-post-members?view=graph-rest-1.0&tabs=http
            $actionMessage = "revoking role [$($actionContext.References.Permission.Role)] to teams channel [$($actionContext.PermissionDisplayName)] with id [$($actionContext.References.Permission.ChannelId)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            $revokePermissionSplatParams = @{
                Uri         = "https://graph.microsoft.com/v1.0/teams/$($actionContext.References.Permission.TeamId)/channels/$($actionContext.References.Permission.ChannelId)/members/$($permissionToRevoke.id)"
                Headers     = $headers
                Method      = "DELETE"
                Verbose     = $false
                ErrorAction = "Stop"
            }

            if (-Not($actionContext.DryRun -eq $true)) {
                $revokedPermission = Invoke-RestMethod @revokePermissionSplatParams

                $outputContext.success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Revoked role [$($actionContext.References.Permission.Role)] to teams channel [$($actionContext.PermissionDisplayName)] with id [$($actionContext.References.Permission.ChannelId)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Information "[DryRun] Would revoke role [$($actionContext.References.Permission.Role)] to teams channel [$($actionContext.References.Permission.ChannelId)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                $outputContext.success = $true
            }
        
            break
        }

        "NotFound" {
            # Skip revoke permission for account
            if (-Not($actionContext.DryRun -eq $true)) {
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Skipped revoking role [$($actionContext.References.Permission.Role)] to teams channel [$($actionContext.PermissionDisplayName)] with id [$($actionContext.References.Permission.ChannelId)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: Permission not found."
                        IsError = $false
                    })
                $outputContext.success = $true
            }
            else {
                Write-Information "[DryRun] Would skip revoking teams channel [$($actionContext.PermissionDisplayName)] with id [$($actionContext.References.Permission.ChannelId)] for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: Permission not found."
                $outputContext.success = $true
            }

            break
        }
    }
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
        if ($errorObj.ErrorDetails.error.code -eq "Request_ResourceNotFound" -and $errorObj.ErrorDetails.error.message -like "*$($actionContext.References.Permission.id)*") {
            $auditMessage = "Skipped revoking group [$($actionContext.PermissionDisplayName)] with id [$($actionContext.References.Permission.id)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: User is already no longer a member or the group no longer exists."
            $auditError = $false
            $outputContext.success = $true
        }
        else {
            $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
            $auditError = $true
            Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            $outputContext.success = $false
        }
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $auditError = $true
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        $outputContext.success = $false
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $auditError
        })
}