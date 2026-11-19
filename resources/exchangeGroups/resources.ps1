#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Resources-ExchangeGroups
# Creates distribution groups in Exchange Online dynamically, based on the resource data (for example departments)
# Uses the Exchange Admin API (no ExchangeOnlineManagement module)
# PowerShell V2
#####################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# The distribution group of a resource is the distribution group where the correlation field has the external id of the resource.
# The sub permission scripts (permissions/exchangeGroups/subPermissions.ps1) use the same field and value.
$correlationField = 'CustomAttribute1'
# The marker field identifies the distribution groups created by HelloID (used by subPermissionsImport.ps1)
$markerField = 'CustomAttribute2'
$markerValue = 'HelloID Dynamic Distribution Group'
# Prefix of the name and e-mail address, for example dg_Sales -> dg_Sales@contoso.com
$namePrefix = 'dg_'

# Time limit of this run. Resources that are not processed within this time are processed in the next run.
$maximumRuntimeSeconds = 25
# Maximum number of distribution groups created per run
$maximumAmountToCreatePerRun = 50

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

        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw 'The certificate does not have a private key.'
        }

        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
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

function Get-ExORequestTimeout {
    # Returns the number of seconds left before the deadline of this action, used as timeout for a single request
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    $remainingSeconds = [int][System.Math]::Floor(($Deadline - [datetime]::UtcNow).TotalSeconds)
    if ($remainingSeconds -lt 1) {
        throw 'The time limit for this action has been reached'
    }

    Write-Output $remainingSeconds
}

function Get-ExORetryDelay {
    # Returns the number of milliseconds to wait before a retry, or -1 when the error is not retryable
    # or when there is not enough time left before the deadline of this action
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory)]
        [int]$Attempt,

        [Parameter(Mandatory)]
        [datetime]$Deadline,

        [Parameter()]
        [int]$MaxRetries = 3
    )

    if ($Attempt -ge $MaxRetries) {
        return -1
    }

    # Transient Exchange Online errors, these can be returned by the cmdlet itself
    $retryableExceptions = @(
        'DCOverloadedException'
        'SuitabilityDirectoryException'
        'ServerInMMException'
        'ADServerSettingsChangedException'
        'StorageTransientException'
    )

    $errorText = "$($ErrorRecord.Exception.Message) $($ErrorRecord.ErrorDetails.Message)"
    $statusCode = $null
    if ($null -ne $ErrorRecord.Exception.Response) {
        $statusCode = [int]$ErrorRecord.Exception.Response.StatusCode
    }

    $delay = -1
    if ($statusCode -eq 429) {
        $delay = [int](1000 * [System.Math]::Pow(2, $Attempt))
        try {
            if ($PSVersionTable.PSVersion.Major -le 5) {
                $retryAfter = $ErrorRecord.Exception.Response.Headers['Retry-After']
            }
            else {
                $retryAfter = $ErrorRecord.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
            }
            if ($retryAfter) {
                $delay = [int]([double]$retryAfter * 1000)
            }
        }
        catch {
            Write-Verbose 'Could not read the Retry-After header'
        }
    }
    elseif (
        $statusCode -in @(500, 502, 503, 504) -or
        # Type names as text: HelloID does not allow these .NET types in a script
        $ErrorRecord.Exception.GetType().FullName -in @('System.Threading.Tasks.TaskCanceledException', 'System.TimeoutException') -or
        ($retryableExceptions | Where-Object { $errorText.Contains($_) })
    ) {
        $delay = [int](1000 * [System.Math]::Pow(2, $Attempt)) + (Get-Random -Maximum 500)
    }

    # Only retry when there is still time left for the retry itself (at least 5 seconds)
    if ($delay -lt 0 -or [datetime]::UtcNow.AddMilliseconds($delay).AddSeconds(5) -gt $Deadline) {
        return -1
    }

    Write-Output $delay
}

function Assert-ExOCommandResponse {
    # The Exchange Admin API can return cmdlet errors and warnings inside an HTTP 200 response
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$Response,

        [Parameter(Mandatory)]
        [string]$CmdletName,

        [Parameter(Mandatory)]
        [string]$ClientRequestId
    )

    if ($null -eq $Response) {
        return
    }

    foreach ($warning in @($Response.'@adminapi.warnings')) {
        if (-not [string]::IsNullOrEmpty($warning)) {
            Write-Warning "$($CmdletName): $($warning)"
        }
    }

    if ($Response.'@adminapi.errors') {
        throw "$($CmdletName) failed (client-request-id $($ClientRequestId)): $($Response.'@adminapi.errors' -join ' | ')"
    }
}

function Remove-StringLatinCharacters {
    # Removes diacritics, for example é -> e (works in PowerShell 7 without extra code pages)
    param ([string]$String)
    $normalized = $String.Normalize([Text.NormalizationForm]::FormD)
    $builder = [System.Text.StringBuilder]::new()
    foreach ($character in $normalized.ToCharArray()) {
        if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($character) -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$builder.Append($character)
        }
    }
    $builder.ToString().Normalize([Text.NormalizationForm]::FormC)
}

function Get-SanitizedGroupName {
    # Removes the characters that are not allowed in a name or e-mail address
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $newName = $Name.Trim()
    $newName = $newName -replace ' - ', '_'
    $newName = $newName -replace '[`,~,!,#,$,%,^,&,*,(,),+,=,<,>,?,/,'',",,:,\\,|,},{,.]', ''
    $newName = $newName -replace '\[', ''
    $newName = $newName -replace ']', ''
    $newName = $newName -replace ' ', '_'
    $newName = $newName -replace '\.{2,}', '.'

    # Remove diacritics
    $newName = Remove-StringLatinCharacters $newName

    # An alias and the local part of an e-mail address allow letters, digits and . - _ only
    $newName = $newName -replace '[^A-Za-z0-9._-]', ''

    Write-Output $newName
}

function Invoke-ExOAdminCommand {
    # Runs one Exchange Online cmdlet via the Exchange Admin API (beta InvokeCommand), with retries and paging.
    # RetryOnPattern: errors that match are retried until the deadline (for example an object that is not replicated yet).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$CmdletName,

        [Parameter(Mandatory)]
        [hashtable]$Parameters,

        [Parameter()]
        [string]$Select,

        [Parameter(Mandatory)]
        [datetime]$Deadline,

        [Parameter()]
        [string]$RetryOnPattern
    )

    # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
    $Parameters['ErrorAction'] = 'Stop'
    $body = @{
        CmdletInput = @{
            CmdletName = $CmdletName
            Parameters = $Parameters
        }
    }
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $body -Depth 10 -Compress))

    $uri = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand"
    if (-not [string]::IsNullOrEmpty($Select)) {
        $uri = "$($uri)?`$select=$($Select)"
    }

    $result = [System.Collections.Generic.List[object]]::new()
    do {
        for ($attempt = 0; ; $attempt++) {
            $headers = New-ExORequestHeaders -BaseHeaders $Authorization
            $request = @{
                Uri         = $uri
                Method      = 'Post'
                Headers     = $headers
                ContentType = 'application/json'
                Body        = $bodyBytes
                TimeoutSec  = Get-ExORequestTimeout -Deadline $Deadline
            }

            try {
                $response = Invoke-RestMethod @request
                Assert-ExOCommandResponse -Response $response -CmdletName $CmdletName -ClientRequestId $headers['client-request-id']
                break
            }
            catch {
                $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
                $errorText = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
                if ($retryDelay -lt 0 -and -not [string]::IsNullOrEmpty($RetryOnPattern) -and $errorText -match $RetryOnPattern -and
                    [datetime]::UtcNow.AddSeconds(8) -lt $Deadline) {
                    $retryDelay = 3000
                }
                if ($retryDelay -lt 0) {
                    throw
                }

                Write-Warning "$($CmdletName) failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
                Start-Sleep -Milliseconds $retryDelay
            }
        }

        foreach ($item in @($response.value)) {
            if ($null -ne $item) {
                $result.Add($item)
            }
        }

        # A large result is returned in pages; the next page is requested with the same body
        $uri = $response.'@odata.nextLink'
    } while (-not [string]::IsNullOrEmpty($uri))

    Write-Output $result -NoEnumerate
}
#endregion Functions

#region script
$deadline = [datetime]::UtcNow.AddSeconds($maximumRuntimeSeconds)

try {
    $actionMessage = 'authenticating to the Exchange Admin API'
    $certificate = Get-MSEntraCertificate
    $exoAccessToken = Get-MSEntraAccessToken -Certificate $certificate -Resource 'https://outlook.office365.com'

    $exoAuthorization = @{
        Authorization     = "Bearer $($exoAccessToken)"
        'Content-Type'    = 'application/json'
        Accept            = 'application/json'
        # Routing hint for the Exchange Admin API, format per Microsoft docs
        'X-AnchorMailbox' = "APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$($actionContext.Configuration.TenantID)"
    }
    $tenantId = $actionContext.Configuration.TenantID

    $domain = $actionContext.Configuration.Organization
    if ([string]::IsNullOrWhiteSpace($domain)) {
        throw 'The configuration setting Organization (for example contoso.onmicrosoft.com) is empty. It is needed for the e-mail address of the distribution groups.'
    }

    #region Get existing objects
    # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/get-distributiongroup
    $actionMessage = 'querying the Exchange Online distribution groups'
    $listParameters = @{
        Filter     = "IsDirSynced -eq 'False'"
        ResultSize = 'Unlimited'
    }
    $existingObjects = Invoke-ExOAdminCommand -Authorization $exoAuthorization -TenantID $tenantId -CmdletName 'Get-DistributionGroup' -Parameters $listParameters -Select "ExchangeObjectId,DisplayName,PrimarySmtpAddress,$($correlationField),$($markerField)" -Deadline $deadline

    # Lookups on the correlation field and on the e-mail address
    $objectsByCorrelation = @{}
    $objectsByAddress = @{}
    foreach ($object in $existingObjects) {
        $value = "$($object.$correlationField)"
        if (-not [string]::IsNullOrEmpty($value)) {
            if (-not $objectsByCorrelation.ContainsKey($value)) {
                $objectsByCorrelation[$value] = [System.Collections.Generic.List[object]]::new()
            }
            $objectsByCorrelation[$value].Add($object)
        }
        if (-not [string]::IsNullOrEmpty($object.PrimarySmtpAddress)) {
            $objectsByAddress["$($object.PrimarySmtpAddress)".ToLower()] = $object
        }
    }
    Write-Information "Queried the Exchange Online distribution groups. Result count: $($existingObjects.Count)"
    #endregion Get existing objects

    #region Process resources
    # Unique on ExternalId and DisplayName, always in the same order
    $resourceData = @($resourceContext.SourceData |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.ExternalId) -and -not [string]::IsNullOrWhiteSpace($_.DisplayName) } |
        Select-Object -Property ExternalId, DisplayName -Unique |
        Sort-Object -Property ExternalId, DisplayName)

    $createdCount = 0
    $skippedCount = 0
    foreach ($resource in $resourceData) {
        $correlationValue = "$($resource.ExternalId)"
        $correlatedObjects = $objectsByCorrelation[$correlationValue]

        if ($correlatedObjects.Count -eq 1) {
            Write-Information "Correlated to distribution group [$($correlatedObjects[0].DisplayName)] on [$($correlationField)] = [$($correlationValue)]."
            continue
        }
        if ($correlatedObjects.Count -gt 1) {
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Multiple distribution groups found with [$($correlationField)] = [$($correlationValue)]: $(($correlatedObjects.DisplayName) -join ', '). Make the value unique; no distribution group is created."
                    IsError = $true
                })
            continue
        }

        # Name, alias and e-mail address of the new distribution group
        $sanitizedName = Get-SanitizedGroupName -Name "$($resource.DisplayName)"
        $name = "$($namePrefix)$($resource.DisplayName)".Trim()
        if ($name.Length -gt 64) {
            $name = $name.Substring(0, 64).Trim()
        }
        $alias = "$($namePrefix)$($sanitizedName)"
        if ($alias.Length -gt 64) {
            $alias = $alias.Substring(0, 64)
        }
        $primarySmtpAddress = "$($alias)@$($domain)"

        # A distribution group with this address without the correlation value: created in an earlier run where setting the
        # attributes failed. It is repaired (attributes set) instead of created again.
        $existingByAddress = $objectsByAddress[$primarySmtpAddress.ToLower()]
        if ($null -ne $existingByAddress -and -not [string]::IsNullOrEmpty("$($existingByAddress.$correlationField)")) {
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "The address [$($primarySmtpAddress)] is already used by [$($existingByAddress.DisplayName)] with [$($correlationField)] = [$($existingByAddress.$correlationField)]. No distribution group is created for resource [$($resource.DisplayName)] ($($correlationValue))."
                    IsError = $true
                })
            continue
        }

        # Stop in time; the remaining resources are processed in the next run
        if ($createdCount -ge $maximumAmountToCreatePerRun -or [datetime]::UtcNow.AddSeconds(10) -gt $deadline) {
            $skippedCount++
            continue
        }

        if ($null -eq $existingByAddress) {
            # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/new-distributiongroup
            $actionMessage = "creating distribution group [$($name)] for resource [$($resource.DisplayName)] ($($correlationValue))"
            $newParameters = @{
                # Distribution or Security (mail-enabled security group)
                Type               = 'Distribution'
                Name               = $name
                DisplayName        = $name
                Alias              = $alias
                PrimarySmtpAddress = $primarySmtpAddress
            }

            if ($actionContext.DryRun -eq $true) {
                Write-Warning "[DryRun] Would create distribution group [$($name)] with address [$($primarySmtpAddress)] and set [$($correlationField)] = [$($correlationValue)], [$($markerField)] = [$($markerValue)]."
                continue
            }

            [void](Invoke-ExOAdminCommand -Authorization $exoAuthorization -TenantID $tenantId -CmdletName 'New-DistributionGroup' -Parameters $newParameters -Select 'DisplayName,PrimarySmtpAddress' -Deadline $deadline)
            $createdCount++
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = 'CreateResource'
                    Message = "Created distribution group [$($name)] with address [$($primarySmtpAddress)] for resource [$($resource.DisplayName)] ($($correlationValue))."
                    IsError = $false
                })
        }
        elseif ($actionContext.DryRun -eq $true) {
            Write-Warning "[DryRun] Would set [$($correlationField)] = [$($correlationValue)] on the existing distribution group [$($existingByAddress.DisplayName)] ($($primarySmtpAddress))."
            continue
        }

        # The correlation and marker fields cannot be set with New-DistributionGroup. A new object is not always found
        # directly after creation, so 'not found' is retried until the deadline.
        # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/set-distributiongroup
        $actionMessage = "setting [$($correlationField)] and [$($markerField)] on distribution group [$($primarySmtpAddress)]"
        $setParameters = @{
            Identity          = $primarySmtpAddress
            $correlationField = $correlationValue
            $markerField      = $markerValue
        }
        try {
            [void](Invoke-ExOAdminCommand -Authorization $exoAuthorization -TenantID $tenantId -CmdletName 'Set-DistributionGroup' -Parameters $setParameters -Deadline $deadline -RetryOnPattern "couldn't be found|ManagementObjectNotFound|isn't found|not found")
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = 'CreateResource'
                    Message = "Set [$($correlationField)] = [$($correlationValue)] and [$($markerField)] = [$($markerValue)] on distribution group [$($primarySmtpAddress)]."
                    IsError = $false
                })
        }
        catch {
            # The next run finds the distribution group on its address and sets the attributes then
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = 'CreateResource'
                    Message = "The distribution group [$($primarySmtpAddress)] exists, but [$($correlationField)] could not be set yet; the next run sets it. Error: $($_.Exception.Message)"
                    IsError = $true
                })
        }
    }

    if ($skippedCount -gt 0) {
        Write-Warning "$($skippedCount) resource(s) not processed in this run because of the time limit or the maximum per run ($($maximumAmountToCreatePerRun)); they are processed in the next run."
    }
    Write-Information "Resources: $($resourceData.Count), created: $($createdCount), remaining for the next run: $($skippedCount)."
    #endregion Process resources
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MS-Entra-ExoError -ExceptionResponse $ex
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
finally {
    $outputContext.Success = -not ($outputContext.AuditLogs.IsError -contains $true)
}
#endregion script
