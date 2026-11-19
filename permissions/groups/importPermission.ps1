#################################################
# HelloID-Conn-Prov-Target-MS-Entra-Exo-Permissions-Groups-Import
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

function Invoke-MSEntraBatchRequest {
    <#
        Executes a list of requests against the Microsoft Graph $batch endpoint
        (https://learn.microsoft.com/en-us/graph/json-batching), instead of one request per item.
        Each request is a hashtable with a 'Method' and a relative 'Uri' (e.g. '/groups/{id}/members').
        Returns a hashtable keyed by the (0-based) index of $Requests, where each value is the
        (paginated, fully resolved) 'value' array of that request's response.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]
        $Requests,

        [Parameter(Mandatory)]
        [hashtable]
        $Headers,

        [int]
        $BatchSize = 20
    )
    process {
        $resultsByIndex = @{}

        for ($i = 0; $i -lt $Requests.Count; $i += $BatchSize) {
            $batchItems = @($Requests[$i..[Math]::Min($i + $BatchSize - 1, $Requests.Count - 1)])

            $batchRequests = [System.Collections.Generic.List[object]]::new()
            for ($j = 0; $j -lt $batchItems.Count; $j++) {
                [void]$batchRequests.Add(
                    @{
                        id     = "$j"
                        method = $batchItems[$j].Method
                        url    = $batchItems[$j].Uri
                    }
                )
            }

            $batchSplatParams = @{
                Uri         = 'https://graph.microsoft.com/v1.0/$batch'
                Headers     = $Headers
                Method      = 'POST'
                Body        = (@{ requests = $batchRequests } | ConvertTo-Json -Depth 10)
                ContentType = 'application/json; charset=utf-8'
                Verbose     = $false
                ErrorAction = 'Stop'
            }

            $batchResponse = $null
            $retryCount = 0
            $maxRetries = 3
            do {
                try {
                    $batchResponse = Invoke-RestMethod @batchSplatParams
                    $retryCount = 0
                }
                catch {
                    if ([int]$_.Exception.Response.StatusCode -in @(429, 500, 502, 503, 504)) {
                        $retryCount++
                        # Wait for the Retry-After of the response when present, otherwise 5, 10, 15 seconds
                        $retryAfterSeconds = try { [int]"$($_.Exception.Response.Headers.GetValues('Retry-After') | Select-Object -First 1)" } catch { 0 }
                        $waitSeconds = if ($retryAfterSeconds -gt 0) { $retryAfterSeconds } else { $retryCount * 5 }
                        Write-Warning "Retry [$retryCount] for batch request covering requests [$i..$($i + $batchItems.Count - 1)] after [$waitSeconds] seconds"
                        Start-Sleep -Seconds $waitSeconds
                        continue
                    }
                    else {
                        throw
                    }
                }
            } while ($retryCount -gt 0 -and $retryCount -le $maxRetries)

            if ($retryCount -gt $maxRetries) {
                throw "Rate limit exceeded for batch request covering requests [$i..$($i + $batchItems.Count - 1)]."
            }

            foreach ($response in $batchResponse.responses) {
                $itemIndex = $i + [int]$response.id
                $responseBody = $response.body
                $responseStatus = [int]$response.status

                # Throttled or failed sub-request: retry that request on its own, so the result is never incomplete
                $subRetryCount = 0
                while ($responseStatus -in @(429, 500, 502, 503, 504) -and $subRetryCount -lt $maxRetries) {
                    $subRetryCount++
                    $retryAfter = [int]"$($response.headers.'Retry-After')"
                    $waitSeconds = if ($retryAfter -gt 0) { $retryAfter } else { $subRetryCount * 5 }
                    Write-Warning "Retry [$subRetryCount] for sub-request at index [$itemIndex] (status [$responseStatus]) after [$waitSeconds] seconds"
                    Start-Sleep -Seconds $waitSeconds
                    try {
                        $retrySplatParams = @{
                            Uri         = "https://graph.microsoft.com/v1.0$($Requests[$itemIndex].Uri)"
                            Headers     = $Headers
                            Method      = $Requests[$itemIndex].Method
                            ContentType = 'application/json; charset=utf-8'
                            Verbose     = $false
                            ErrorAction = 'Stop'
                        }
                        $responseBody = Invoke-RestMethod @retrySplatParams
                        $responseStatus = 200
                    }
                    catch {
                        $responseStatus = [int]$_.Exception.Response.StatusCode
                        if ($responseStatus -notin @(429, 500, 502, 503, 504)) {
                            throw
                        }
                    }
                }

                if ($responseStatus -ge 200 -and $responseStatus -lt 300) {
                    $values = [System.Collections.ArrayList]@()
                    if ($null -ne $responseBody.value) {
                        [void]$values.AddRange(@($responseBody.value))
                    }
                    $nextLink = $responseBody.'@odata.nextLink'
                    while (-not [string]::IsNullOrEmpty($nextLink)) {
                        $paginationSplatParams = @{
                            Uri         = $nextLink
                            Headers     = $Headers
                            Method      = 'GET'
                            ContentType = 'application/json; charset=utf-8'
                            Verbose     = $false
                            ErrorAction = 'Stop'
                        }
                        # Retry throttled or failed pagination calls, so the result is never incomplete
                        $paginationRetryCount = 0
                        $paginationDone = $false
                        while (-not $paginationDone) {
                            try {
                                $paginationResponse = Invoke-RestMethod @paginationSplatParams
                                $paginationDone = $true
                            }
                            catch {
                                if ([int]$_.Exception.Response.StatusCode -in @(429, 500, 502, 503, 504) -and $paginationRetryCount -lt $maxRetries) {
                                    $paginationRetryCount++
                                    $retryAfterSeconds = try { [int]"$($_.Exception.Response.Headers.GetValues('Retry-After') | Select-Object -First 1)" } catch { 0 }
                                    $waitSeconds = if ($retryAfterSeconds -gt 0) { $retryAfterSeconds } else { $paginationRetryCount * 5 }
                                    Write-Warning "Retry [$paginationRetryCount] for pagination call of request at index [$itemIndex] after [$waitSeconds] seconds"
                                    Start-Sleep -Seconds $waitSeconds
                                }
                                else {
                                    throw
                                }
                            }
                        }
                        [void]$values.AddRange(@($paginationResponse.value))
                        $nextLink = $paginationResponse.'@odata.nextLink'
                    }
                    $resultsByIndex[$itemIndex] = $values
                }
                elseif ($responseStatus -eq 404) {
                    # The object was deleted after it was listed
                    Write-Information "Batch sub-request at index [$itemIndex] returned 404, the object no longer exists"
                    $resultsByIndex[$itemIndex] = @()
                }
                else {
                    # Stop instead of returning an incomplete result
                    throw "Batch sub-request failed for request [$($Requests[$itemIndex].Uri)] with status [$responseStatus]: $($response.body.error.message)"
                }
            }
        }

        Write-Output $resultsByIndex
    }
}
#endregion functions

try {
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
    $actionMessage = "querying M365 groups"
    $uriGroups = "https://graph.microsoft.com/v1.0/groups?`$filter=groupTypes/any(c:c+eq+'Unified')&`$select=id,displayName,description&`$top=999"
    $m365Groups = [System.Collections.ArrayList]@()
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
        [void]$m365Groups.AddRange($m365GroupsResponse.value)
        $uriGroups = $m365GroupsResponse.'@odata.nextLink'
    } while ($uriGroups)

    # Using the Batch API to retrieve group members for all groups in batches of 20 (https://learn.microsoft.com/en-us/graph/json-batching)
    $actionMessage = "querying M365 group members"
    $m365GroupMembersRequests = @(foreach ($group in $m365Groups) {
        @{
            Method = 'GET'
            Uri    = "/groups/$($group.id)/members/microsoft.graph.user?`$select=id&`$top=999"
        }
    })
    $m365GroupMembers = Invoke-MSEntraBatchRequest -Requests $m365GroupMembersRequests -Headers $headers

    $m365GroupCount = 0
    for ($i = 0; $i -lt $m365Groups.Count; $i++) {
        $entraIDGroup = $m365Groups[$i]

        # Make sure the displayName has a value of max 100 char
        if (-not([string]::IsNullOrEmpty($entraIDGroup.displayName))) {
            $displayName = "M365 Group - $($entraIDGroup.displayName)"
            $displayName = $($displayName).substring(0, [System.Math]::Min(100, $($displayName).Length))
        }
        else {
            $displayName = "M365 Group - $($entraIDGroup.id)"
        }
        # Make sure the description has a value of max 100 char
        if (-not([string]::IsNullOrEmpty($entraIDGroup.description))) {
            $description = $($entraIDGroup.description).substring(0, [System.Math]::Min(100, $($entraIDGroup.description).Length))
        }
        else {
            $description = $null
        }

        $accountReferences = $m365GroupMembers[$i].id
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
        $m365GroupCount++
    }
    Write-Information "Successfully queried [$m365GroupCount] existing m365 groups"

    # API docs: https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying security groups"
    $uriGroups = "https://graph.microsoft.com/v1.0/groups?`$filter=NOT(groupTypes/any(c:c+eq+'DynamicMembership')) and onPremisesSyncEnabled eq null and mailEnabled eq false and securityEnabled eq true&`$select=id,displayName,description&`$top=999"
    $securityGroups = [System.Collections.ArrayList]@()
    do {
        $getSecurityGroupsSplatParams = @{
            Uri         = $uriGroups
            Headers     = $headers
            Method      = 'GET'
            ContentType = 'application/json; charset=utf-8'
            Verbose     = $false
            ErrorAction = "Stop"
        }
        $securityGroupsResponse = Invoke-RestMethod @getSecurityGroupsSplatParams
        [void]$securityGroups.AddRange($securityGroupsResponse.value)
        $uriGroups = $securityGroupsResponse.'@odata.nextLink'
    } while ($uriGroups)

    # Using the Batch API to retrieve group members for all groups in batches of 20 (https://learn.microsoft.com/en-us/graph/json-batching)
    $actionMessage = "querying security group members"
    $securityGroupMembersRequests = @(foreach ($group in $securityGroups) {
        @{
            Method = 'GET'
            Uri    = "/groups/$($group.id)/members/microsoft.graph.user?`$select=id&`$top=999"
        }
    })
    $securityGroupMembers = Invoke-MSEntraBatchRequest -Requests $securityGroupMembersRequests -Headers $headers

    $securityGroupCount = 0
    for ($i = 0; $i -lt $securityGroups.Count; $i++) {
        $entraIDGroup = $securityGroups[$i]

        # Make sure the displayName has a value of max 100 char
        if (-not([string]::IsNullOrEmpty($entraIDGroup.displayName))) {
            $displayName = "Security Group - $($entraIDGroup.displayName)"
            $displayName = $($displayName).substring(0, [System.Math]::Min(100, $($displayName).Length))
        }
        else {
            $displayName = "Security Group - $($entraIDGroup.id)"
        }
        # Make sure the description has a value of max 100 char
        if (-not([string]::IsNullOrEmpty($entraIDGroup.description))) {
            $description = $($entraIDGroup.description).substring(0, [System.Math]::Min(100, $($entraIDGroup.description).Length))
        }
        else {
            $description = $null
        }

        $accountReferences = $securityGroupMembers[$i].id
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
        $securityGroupCount++
    }
    Write-Information "Successfully queried [$securityGroupCount] existing security groups"
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
