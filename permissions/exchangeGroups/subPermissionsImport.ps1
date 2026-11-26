#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-SubPermissionsImport-ExchangeGroups
# Import the memberships of the dynamic Exchange Online groups (sub permissions, see subPermissions.ps1)
# PowerShell V2
#####################################################

# Reference and name of the dynamic permission in HelloID that uses subPermissions.ps1
$permissionReference = 'exchangeGroups'
$permissionDisplayName = 'Exchange Online groups'

# Only the groups with this marker are imported: the groups created by resources/exchangeGroups/resources.ps1
$markerField = 'CustomAttribute2'
$markerValue = 'HelloID Dynamic Distribution Group'

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region Functions
function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()

    try {
        $rawCertificate = [System.Convert]::FromBase64String($ActionContext.Configuration.AppCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $rawCertificate,
            $ActionContext.Configuration.AppCertificatePassword,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        )

        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate,

        [Parameter()]
        [string]$Resource = 'https://graph.microsoft.com'
    )

    try {
        $derBytes = $Certificate.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        $currentUnixTimestamp = [Math]::Round(((Get-Date).ToUniversalTime() - ([DateTime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        $payload = [ordered]@{
            'iss' = "$($ActionContext.Configuration.AppId)"
            'sub' = "$($ActionContext.Configuration.AppId)"
            'aud' = "https://login.microsoftonline.com/$($ActionContext.Configuration.TenantID)/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600)
            'nbf' = ($currentUnixTimestamp - 300)
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

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $ActionContext.Configuration.AppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = $Resource
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($ActionContext.Configuration.TenantID)/oauth2/token"
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

function Get-ExODistributionGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Filter
    )

    # ExchangeObjectId instead of Guid: the Guid can change during a tenant relocation, the ExchangeObjectId not
    $Uri = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand?`$select=ExchangeObjectId,DisplayName,RecipientTypeDetails,Description,IsDirSynced"
    $Body = @{
        CmdletInput = @{
            CmdletName = 'Get-DistributionGroup'
            Parameters = @{
                Filter      = $Filter
                ResultSize  = 'Unlimited'
                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                ErrorAction = 'Stop'
            }
        }
    }

    do {
        $Response = Invoke-ExOPageRequest -Uri $Uri -Body $Body -Authorization $Authorization

        $Response.Value |
            Where-Object { "$($_.IsDirSynced)" -ne 'True' -and -not [string]::IsNullOrEmpty($_.ExchangeObjectId) } |
            Select-Object ExchangeObjectId, DisplayName, RecipientTypeDetails, Description

        # A large result is returned in pages; the next page is requested with the same body
        $Uri = $Response.'@odata.nextLink'
    } while ($Uri)
}

function New-ExORequestHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$BaseHeaders
    )

    $headers = @{}
    foreach ($key in $BaseHeaders.Keys) {
        $headers[$key] = $BaseHeaders[$key]
    }

    # A unique id per request makes calls traceable in Exchange Online (and in support cases with Microsoft)
    $headers['X-ResponseFormat'] = 'json'
    $headers['return-client-request-id'] = 'true'
    $headers['client-request-id'] = [guid]::NewGuid().ToString()

    Write-Output $headers
}

function Invoke-ExOPageRequest {
    <#
        Executes one request (one page of a list) against the Exchange Admin API and returns the response.
        Retries on 429, 5xx and timeouts. A cmdlet error inside an HTTP 200 response ('@adminapi.errors') stops the
        script, so HelloID never receives a partial list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $Uri,

        [Parameter(Mandatory)]
        [hashtable]
        $Body,

        [Parameter(Mandatory)]
        [hashtable]
        $Authorization,

        [int]
        $MaxRetries = 3
    )

    $cmdletName = $Body.CmdletInput.CmdletName
    $target = if ($Body.CmdletInput.Parameters.Identity) { " for [$($Body.CmdletInput.Parameters.Identity)]" } else { '' }
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $Body -Depth 10 -Compress))

    for ($attempt = 0; ; $attempt++) {
        $headers = New-ExORequestHeaders -BaseHeaders $Authorization
        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Post -Headers $headers -ContentType 'application/json' -Body $bodyBytes -TimeoutSec 120
            break
        }
        catch {
            $statusCode = $null
            if ($null -ne $_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            $isRetryable = $statusCode -eq 429 -or $statusCode -ge 500 -or $_.Exception.GetType().FullName -eq 'System.Threading.Tasks.TaskCanceledException'
            if ($attempt -ge $MaxRetries -or -not $isRetryable) {
                throw
            }

            $delaySeconds = [int](2 * [System.Math]::Pow(2, $attempt))
            Write-Warning "$($cmdletName)$($target) failed (client-request-id $($headers['client-request-id'])), retrying in $($delaySeconds) seconds. Error: $($_.Exception.Message)"
            Start-Sleep -Seconds $delaySeconds
        }
    }

    if ($response.'@adminapi.errors') {
        throw "$($cmdletName)$($target) failed (client-request-id $($headers['client-request-id'])): $($response.'@adminapi.errors' -join ' | ')"
    }

    Write-Output $response
}

function Get-ExONextPages {
    <#
        Follows '@odata.nextLink' of a large result: the Exchange Admin API returns a large result in pages, and every
        next page is requested with the same cmdlet body. Returns the items of all remaining pages.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $NextLink,

        [Parameter(Mandatory)]
        [hashtable]
        $Request,

        [Parameter(Mandatory)]
        [hashtable]
        $Authorization,

        [int]
        $MaxRetries = 3
    )

    $parameters = $Request.Parameters.Clone()
    $parameters['ErrorAction'] = 'Stop'
    $body = @{ CmdletInput = @{ CmdletName = $Request.CmdletName; Parameters = $parameters } }

    $uri = $NextLink
    while (-not [string]::IsNullOrEmpty($uri)) {
        $response = Invoke-ExOPageRequest -Uri $uri -Body $body -Authorization $Authorization -MaxRetries $MaxRetries
        foreach ($item in @($response.value)) {
            if ($null -ne $item) {
                Write-Output $item
            }
        }

        $uri = $response.'@odata.nextLink'
    }
}

function Invoke-ExOBatchRequest {
    <#
        Executes a list of Exchange cmdlets against the Exchange Admin API $batch endpoint, instead of one request per item
        (same approach as Invoke-MSEntraBatchRequest for Microsoft Graph in this connector).
        Each request is a hashtable with 'CmdletName', 'Parameters' and optionally 'Select' (properties for $select).
        Returns a hashtable keyed by the (0-based) index of $Requests, where each value is the 'value' array of that response.
        Sub-requests that fail with 429 or 5xx are retried. A sub-request for an object that no longer exists returns an
        empty result. Any other failure stops the import, so HelloID never receives an incomplete import.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]
        $Requests,

        [Parameter(Mandatory)]
        [hashtable]
        $Authorization,

        [Parameter(Mandatory)]
        [string]
        $TenantID,

        [int]
        $BatchSize = 10,

        [int]
        $MaxRetries = 3
    )

    $resultsByIndex = @{}
    [int[]]$pendingIndexes = @(if ($Requests.Count -gt 0) { 0..($Requests.Count - 1) })

    for ($attempt = 0; $pendingIndexes.Count -gt 0; $attempt++) {
        if ($attempt -gt 0) {
            if ($attempt -gt $MaxRetries) {
                throw "$($pendingIndexes.Count) batch sub-request(s) still failed after $($MaxRetries) retries"
            }

            $delaySeconds = [int](2 * [System.Math]::Pow(2, $attempt - 1))
            Write-Warning "Retrying $($pendingIndexes.Count) failed batch sub-request(s) in $($delaySeconds) seconds (retry $($attempt) of $($MaxRetries))"
            Start-Sleep -Seconds $delaySeconds
        }

        $retryIndexes = [System.Collections.Generic.List[int]]::new()

        for ($i = 0; $i -lt $pendingIndexes.Count; $i += $BatchSize) {
            $batchIndexes = @($pendingIndexes[$i..[System.Math]::Min($i + $BatchSize - 1, $pendingIndexes.Count - 1)])

            $batchRequests = [System.Collections.Generic.List[object]]::new()
            foreach ($index in $batchIndexes) {
                $request = $Requests[$index]
                $url = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand"
                if (-not [string]::IsNullOrEmpty($request.Select)) {
                    $url = "$($url)?`$select=$($request.Select)"
                }

                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                $parameters = $request.Parameters.Clone()
                $parameters['ErrorAction'] = 'Stop'

                [void]$batchRequests.Add(
                    @{
                        id      = "$index"
                        method  = 'POST'
                        url     = $url
                        headers = @{ 'Content-Type' = 'application/json' }
                        body    = @{
                            CmdletInput = @{
                                CmdletName = $request.CmdletName
                                Parameters = $parameters
                            }
                        }
                    }
                )
            }

            $headers = New-ExORequestHeaders -BaseHeaders $Authorization
            $batchSplatParams = @{
                Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/`$batch"
                Method      = 'Post'
                Headers     = $headers
                ContentType = 'application/json'
                Body        = [System.Text.Encoding]::UTF8.GetBytes(
                    (ConvertTo-Json @{ requests = $batchRequests } -Depth 10 -Compress)
                )
                TimeoutSec  = 120
            }

            try {
                $batchResponse = Invoke-RestMethod @batchSplatParams
            }
            catch {
                $statusCode = $null
                if ($null -ne $_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }

                # Throttling, server errors and timeouts: retry the whole batch
                if ($statusCode -eq 429 -or $statusCode -ge 500 -or $_.Exception.GetType().FullName -eq 'System.Threading.Tasks.TaskCanceledException') {
                    Write-Warning "Batch request failed (client-request-id $($headers['client-request-id'])): $($_.Exception.Message)"
                    $batchIndexes | ForEach-Object { $retryIndexes.Add($_) }
                    continue
                }
                throw
            }

            $answeredIndexes = [System.Collections.Generic.List[int]]::new()
            foreach ($response in @($batchResponse.responses)) {
                $index = [int]$response.id
                $answeredIndexes.Add($index)
                $status = [int]$response.status
                $errorText = "$($response.body.error.message) $($response.body.error.innererror.internalexception.message) $($response.body.'@adminapi.errors' -join ' | ')".Trim()
                $request = $Requests[$index]

                if ($status -ge 200 -and $status -lt 300 -and -not $response.body.'@adminapi.errors') {
                    $values = [System.Collections.Generic.List[object]]::new()
                    foreach ($item in @($response.body.value)) {
                        if ($null -ne $item) {
                            $values.Add($item)
                        }
                    }

                    # A large result (many members or permissions) is returned in pages: get the remaining pages
                    if (-not [string]::IsNullOrEmpty($response.body.'@odata.nextLink')) {
                        Get-ExONextPages -NextLink $response.body.'@odata.nextLink' -Request $request -Authorization $Authorization -MaxRetries $MaxRetries |
                            ForEach-Object { $values.Add($_) }
                    }

                    $resultsByIndex[$index] = @($values)
                }
                elseif ($status -eq 429 -or $status -ge 500) {
                    $retryIndexes.Add($index)
                }
                elseif ($status -eq 404 -or $errorText -match 'ManagementObjectNotFoundException|couldn''t be found') {
                    # The object was removed between retrieving the list and retrieving its permissions or members
                    Write-Warning "$($request.CmdletName) for [$($request.Parameters.Identity)]: object no longer exists, no results"
                    $resultsByIndex[$index] = @()
                }
                else {
                    throw "$($request.CmdletName) for [$($request.Parameters.Identity)] failed with status [$($status)] (client-request-id $($headers['client-request-id'])): $($errorText)"
                }
            }

            # A sub-request without a response is retried as well
            $batchIndexes | Where-Object { $_ -notin $answeredIndexes } | ForEach-Object { $retryIndexes.Add($_) }
        }

        $pendingIndexes = @($retryIndexes)
    }

    Write-Output $resultsByIndex
}

function Resolve-MS-Entra-ExoError {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]
        [object]$ExceptionResponse
    )

    process {
        $ErrorObject = $ExceptionResponse
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }

        try {
            if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
                $parsedDetails = $ErrorObject.ErrorDetails.Message | ConvertFrom-Json
                if ($null -ne $parsedDetails) {
                    $httpErrorObj.ErrorDetails = $parsedDetails
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
#endregion Functions

#region script
try {
    Write-Information 'Starting Exchange Online groups sub permission import'

    $actionMessage = 'authenticating to the Exchange Admin API'
    $certificate = Get-MSEntraCertificate
    $exoAccessToken = Get-MSEntraAccessToken -Certificate $certificate -Resource 'https://outlook.office365.com'

    $ExOAuthorization = @{
        Authorization  = "Bearer $($exoAccessToken)"
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
    }

    Write-Information 'Successfully authenticated the Exchange Admin API'

    $tenantId = $ActionContext.Configuration.TenantID

    # Routing hint for the Exchange Admin API, format per Microsoft docs: APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@<tenantIdOrOrganization>
    $ExOAuthorization['X-AnchorMailbox'] = "APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$($ActionContext.Configuration.TenantID)"

    $actionMessage = "retrieving Exchange Online groups where [$($markerField)] = [$($markerValue)]"
    Write-Information $actionMessage
    $Groups = Get-ExODistributionGroups -Authorization $ExOAuthorization -TenantID $tenantId -Filter "$($markerField) -eq '$($markerValue -replace "'", "''")'"
    Write-Information "Retrieved $(($Groups | Measure-Object).Count) Exchange Online groups."

    $Groups = @($Groups | Where-Object { $null -ne $_ })

    # Members of all groups via $batch (1 request per group, 10 per batch call)
    $actionMessage = 'retrieving members of the Exchange Online groups'
    Write-Information $actionMessage
    $memberRequests = [System.Collections.Generic.List[object]]::new()
    foreach ($group in $Groups) {
        $memberRequests.Add(@{
                CmdletName = 'Get-DistributionGroupMember'
                Parameters = @{ Identity = $group.ExchangeObjectId; ResultSize = 'Unlimited' }
                Select     = 'Guid,ExternalDirectoryObjectId,RecipientTypeDetails'
            })
    }

    $memberResults = Invoke-ExOBatchRequest -Requests $memberRequests -Authorization $ExOAuthorization -TenantID $tenantId
    Write-Information "Retrieved members of $($Groups.Count) groups with $([System.Math]::Ceiling($memberRequests.Count / 10)) batch call(s)."

    for ($groupIndex = 0; $groupIndex -lt $Groups.Count; $groupIndex++) {
        $group = $Groups[$groupIndex]
        $groupMembers = @($memberResults[$groupIndex] | Where-Object {
                $_.RecipientTypeDetails -eq 'UserMailbox' -and -not [string]::IsNullOrEmpty($_.ExternalDirectoryObjectId)
            })

        $accountReferences = @($groupMembers | ForEach-Object { $_.ExternalDirectoryObjectId })

        $displayNamePrefix = if ($group.RecipientTypeDetails -eq 'MailUniversalSecurityGroup') {
            'Mail-enabled Security Group'
        }
        else {
            'Distribution Group'
        }

        $displayName = "$displayNamePrefix - $($group.DisplayName)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length))

        # Same names as subPermissions.ps1
        $permission = @{
            PermissionReference      = @{
                Reference = $permissionReference
            }
            DisplayName              = "Permission - $($permissionDisplayName)"
            SubPermissionReference   = @{
                Id = $group.ExchangeObjectId
            }
            SubPermissionDisplayName = $displayName
        }

        $numberOfAccounts = $accountReferences.Count
        $batchSize = 500
        for ($i = 0; $i -lt $numberOfAccounts; $i += $batchSize) {
            # A new object per chunk: the same hashtable written twice would only carry the last chunk
            $chunk = $permission.Clone()
            $chunk.AccountReferences = $accountReferences[$i..([Math]::Min($i + $batchSize - 1, $numberOfAccounts - 1))]
            Write-Output $chunk
        }
    }

    Write-Information 'Exchange Online groups sub permission import completed'
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MS-Entra-ExoError -ExceptionResponse $ex
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
#endregion script
