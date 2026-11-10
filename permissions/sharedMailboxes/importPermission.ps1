#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-SharedMailbox-Import
# Correlate accounts to shared mailbox permissions
# PowerShell V2
#####################################################

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
        $currentUnixTimestamp = [Math]::Round(((Get-Date).ToUniversalTime() - ([DateTime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
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
            throw 'The certificate does not have a private key.'
        }

        # Create the JWT token
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

function Get-ExOSharedMailboxes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [int]$ResultSize = 500
    )

    $Uri = "https://outlook.office365.com/adminapi/v2.0/$TenantID/Mailbox?`$select=ExternalDirectoryObjectId,DisplayName,UserPrincipalName,RecipientTypeDetails,GrantSendOnBehalfTo,Identity"

    do {
        $Body = @{
            CmdletInput = @{
                CmdletName = 'Get-Mailbox'
                Parameters = @{
                    ResultSize = $ResultSize
                }
            }
        }

        $Request = @{
            Uri         = $Uri
            Method      = 'Post'
            Headers     = $Authorization
            ContentType = 'application/json'
            Body        = [System.Text.Encoding]::UTF8.GetBytes(
                (ConvertTo-Json $Body -Depth 10 -Compress)
            )
        }

        $Response = Invoke-RestMethod @Request

        $Response.Value |
            Where-Object RecipientTypeDetails -eq 'SharedMailbox' |
            Select-Object ExternalDirectoryObjectId,
            DisplayName,
            UserPrincipalName,
            GrantSendOnBehalfTo,
            Identity

        $Uri = $Response.'@odata.nextLink'

    } while ($Uri)
}

function Get-ExOUserMailboxes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [int]$ResultSize = 500
    )

    $Uri = "https://outlook.office365.com/adminapi/v2.0/$TenantID/Mailbox?`$select=ExternalDirectoryObjectId,UserPrincipalName,RecipientTypeDetails,Identity"

    do {
        $Body = @{
            CmdletInput = @{
                CmdletName = 'Get-Mailbox'
                Parameters = @{
                    ResultSize = $ResultSize
                }
            }
        }

        $Request = @{
            Uri         = $Uri
            Method      = 'Post'
            Headers     = $Authorization
            ContentType = 'application/json'
            Body        = [System.Text.Encoding]::UTF8.GetBytes(
                (ConvertTo-Json $Body -Depth 10 -Compress)
            )
        }

        $Response = Invoke-RestMethod @Request

        $Response.Value |
            Where-Object RecipientTypeDetails -eq 'UserMailbox' |
            Select-Object @{
                Name='ExternalDirectoryObjectId'
                Expression={$_.ExternalDirectoryObjectId}
            },
            UserPrincipalName,
            Identity

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
                if ($statusCode -eq 429 -or $statusCode -ge 500 -or $_.Exception -is [System.Threading.Tasks.TaskCanceledException]) {
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
                    $resultsByIndex[$index] = @($response.body.value)
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
        [System.Object]$ExceptionResponse
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
#endregion Functions

#region script
try {
    $certificate = Get-MSEntraCertificate
    $exoAccessToken = Get-MSEntraAccessToken -Certificate $certificate -Resource 'https://outlook.office365.com'

    $ExOAuthorization = @{
        Authorization  = "Bearer $($exoAccessToken)"
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
    }

    Write-Information 'Successfully authenticated the Exchange Admin API'

    $tenantId = $ActionContext.Configuration.TenantID

    # Use the same routing hint for every request, so all calls (including verification) are routed to the same backend.
    # Format per Microsoft docs: APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@<tenantIdOrOrganization>
    $ExOAuthorization['X-AnchorMailbox'] = "APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$($ActionContext.Configuration.TenantID)"

    $actionMessage = 'retrieving shared mailboxes'
    Write-Information $actionMessage
    $SharedMailboxes = Get-ExOSharedMailboxes -Authorization $ExOAuthorization -TenantID $tenantId
    Write-Information "Retrieved $(($SharedMailboxes | Measure-Object).Count) shared mailboxes."

    $SharedMailboxes = @($SharedMailboxes | Where-Object { $null -ne $_ })

    # Full Access and Send As for all shared mailboxes via $batch (2 requests per shared mailbox, 10 per batch call)
    $actionMessage = 'retrieving mailbox permissions (Full Access) and recipient permissions (Send As)'
    Write-Information $actionMessage
    $permissionRequests = [System.Collections.Generic.List[object]]::new()
    foreach ($SharedMailbox in $SharedMailboxes) {
        $permissionRequests.Add(@{
                CmdletName = 'Get-MailboxPermission'
                Parameters = @{ Identity = $SharedMailbox.Identity; ResultSize = 'Unlimited' }
                Select     = 'User,AccessRights,Deny,IsInherited'
            })
        $permissionRequests.Add(@{
                CmdletName = 'Get-RecipientPermission'
                Parameters = @{ Identity = $SharedMailbox.Identity; ResultSize = 'Unlimited' }
                Select     = 'Trustee,AccessRights,AccessControlType,IsInherited'
            })
    }

    $permissionResults = Invoke-ExOBatchRequest -Requests $permissionRequests -Authorization $ExOAuthorization -TenantID $tenantId

    # Only explicit (not inherited, not denied) permissions of real accounts
    $MailboxPermissions = @{}
    $RecipientPermissions = @{}
    for ($i = 0; $i -lt $SharedMailboxes.Count; $i++) {
        $SharedMailbox = $SharedMailboxes[$i]
        $MailboxPermissions[$SharedMailbox.Identity] = @($permissionResults[2 * $i] | Where-Object {
                $_.User -notin @('NT AUTHORITY\SELF', 'NULL SID') -and
                "$($_.Deny)" -ne 'True' -and
                "$($_.IsInherited)" -ne 'True'
            })
        $RecipientPermissions[$SharedMailbox.Identity] = @($permissionResults[2 * $i + 1] | Where-Object {
                $_.Trustee -notin @('NT AUTHORITY\SELF', 'NULL SID') -and
                "$($_.AccessControlType)" -notin @('Deny', '1') -and
                "$($_.IsInherited)" -ne 'True'
            })
    }
    Write-Information "Retrieved permissions of $($SharedMailboxes.Count) shared mailboxes with $([System.Math]::Ceiling($permissionRequests.Count / 10)) batch call(s)."

    $actionMessage = 'retrieving user mailboxes'
    Write-Information $actionMessage
    $Mailboxes = Get-ExOUserMailboxes -Authorization $ExOAuthorization -TenantID $tenantId
    Write-Information "Retrieved $(($Mailboxes | Measure-Object).Count) user mailboxes."

    $Identities = $Mailboxes | Group-Object -Property 'Identity' -AsHashTable -AsString
    $Mailboxes = $Mailboxes | Group-Object -Property 'UserPrincipalName' -AsHashTable -AsString

    foreach ($SharedMailbox in $SharedMailboxes) {
        # Full Access
        $fullAccessUsers = @()
        $fullAccessPermissions = $MailboxPermissions[$SharedMailbox.Identity] | Where-Object {
            'FullAccess' -in $_.AccessRights
        }

        foreach ($record in $fullAccessPermissions) {
            $fullAccessUser = $Mailboxes[$record.User].ExternalDirectoryObjectId
            if ($fullAccessUser) { $fullAccessUsers += $fullAccessUser }
        }

        $permission = @{
            PermissionReference = @{
                Id         = $SharedMailbox.ExternalDirectoryObjectId
                Permission = 'FullAccess'
            }
            Description = $SharedMailbox.UserPrincipalName
            DisplayName = 'Shared Mailbox - ' + $SharedMailbox.DisplayName + ' - Full Access'
        }

        $numberOfAccounts = $fullAccessUsers.Count
        $batchSize = 500
        for ($i = 0; $i -lt $numberOfAccounts; $i += $batchSize) {
            $permission.AccountReferences = $fullAccessUsers[$i..([Math]::Min($i + $batchSize - 1, $numberOfAccounts - 1))]
            Write-Output $permission
        }

        # Send As
        $sendAsUsers = @()
        $sendAsPermissions = $RecipientPermissions[$SharedMailbox.Identity] | Where-Object {
            'SendAs' -in $_.AccessRights
        }

        foreach ($record in $sendAsPermissions) {
            $sendAsUser = $Mailboxes[$record.Trustee].ExternalDirectoryObjectId
            if ($sendAsUser) { $sendAsUsers += $sendAsUser }
        }

        $permission = @{
            PermissionReference = @{
                Id         = $SharedMailbox.ExternalDirectoryObjectId
                Permission = 'SendAs'
            }
            Description = $SharedMailbox.UserPrincipalName
            DisplayName = 'Shared Mailbox - ' + $SharedMailbox.DisplayName + ' - Send As'
        }

        $numberOfAccounts = $sendAsUsers.Count
        $batchSize = 500
        for ($i = 0; $i -lt $numberOfAccounts; $i += $batchSize) {
            $permission.AccountReferences = $sendAsUsers[$i..([Math]::Min($i + $batchSize - 1, $numberOfAccounts - 1))]
            Write-Output $permission
        }

        # Send On Behalf
        $sendOnBehalfUsers = @()
        if ($null -ne $SharedMailbox.GrantSendOnBehalfTo -and $SharedMailbox.GrantSendOnBehalfTo.Count -gt 0) {
            foreach ($trustee in $SharedMailbox.GrantSendOnBehalfTo) {
                $sendOnBehalfUser = $null
                $trusteeValue = [string]$trustee

                $trusteeMailbox = $Mailboxes[$trusteeValue]
                if (-not $trusteeMailbox) {
                    $trusteeMailbox = $Identities[$trusteeValue]
                }

                if ($trusteeMailbox) {
                    $sendOnBehalfUser = $trusteeMailbox.ExternalDirectoryObjectId
                }

                if ($sendOnBehalfUser) { $sendOnBehalfUsers += $sendOnBehalfUser }
            }
        }

        $permission = @{
            PermissionReference = @{
                Id         = $SharedMailbox.ExternalDirectoryObjectId
                Permission = 'SendOnBehalf'
            }
            Description = $SharedMailbox.UserPrincipalName
            DisplayName = 'Shared Mailbox - ' + $SharedMailbox.DisplayName + ' - Send on Behalf'
        }

        $numberOfAccounts = $sendOnBehalfUsers.Count
        $batchSize = 500
        for ($i = 0; $i -lt $numberOfAccounts; $i += $batchSize) {
            $permission.AccountReferences = $sendOnBehalfUsers[$i..([Math]::Min($i + $batchSize - 1, $numberOfAccounts - 1))]
            Write-Output $permission
        }
    }
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
