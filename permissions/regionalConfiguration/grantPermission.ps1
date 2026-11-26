#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-RegionalConfiguration-Grant
# Set the regional configuration (language, date/time format, time zone) of the account's mailbox
# PowerShell V2
#####################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Settings per permission id (see permissions.ps1). Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/set-mailboxregionalconfiguration
$regionalConfigurations = @{
    'MailboxRegionalConfiguration-NL' = @{
        Language                  = 'nl-NL'
        DateFormat                = 'dd-MM-yy'
        TimeFormat                = 'H:mm'
        TimeZone                  = 'W. Europe Standard Time'
        LocalizeDefaultFolderName = $true
    }
}

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

function Set-ExOMailboxRegionalConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Identity,
        [Parameter(Mandatory)]
        [string]$Language,
        [Parameter(Mandatory)]
        [string]$DateFormat,
        [Parameter(Mandatory)]
        [string]$TimeFormat,
        [Parameter(Mandatory)]
        [string]$TimeZone,
        [Parameter(Mandatory)]
        [bool]$LocalizeDefaultFolderName,

        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    $body = @{
        CmdletInput = @{
            CmdletName = 'Set-MailboxRegionalConfiguration'
            Parameters = @{
                Identity                  = $Identity
                Language                  = $Language
                DateFormat                = $DateFormat
                TimeFormat                = $TimeFormat
                TimeZone                  = $TimeZone
                LocalizeDefaultFolderName = $LocalizeDefaultFolderName
                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                ErrorAction = 'Stop'
            }
        }
    }

    for ($attempt = 0; ; $attempt++) {
        $headers = New-ExORequestHeaders -BaseHeaders $Authorization
        $request = @{
            Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand"
            Method      = 'Post'
            Headers     = $headers
            ContentType = 'application/json'
            Body        = [System.Text.Encoding]::UTF8.GetBytes(
                (ConvertTo-Json $body -Depth 10 -Compress)
            )
            TimeoutSec  = Get-ExORequestTimeout -Deadline $Deadline
        }

        try {
            $response = Invoke-RestMethod @request
            Assert-ExOCommandResponse -Response $response -CmdletName 'Set-MailboxRegionalConfiguration' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Set-MailboxRegionalConfiguration failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    Write-Output $response
}

#endregion Functions

#region script
# HelloID stops an action after 30 seconds. All requests and retries must finish before this deadline.
$deadline = [datetime]::UtcNow.AddSeconds(25)

try {
    $actionMessage = 'validating account reference'

    $accountReference = [string]$ActionContext.References.Account
    if ([string]::IsNullOrWhiteSpace($accountReference)) {
        throw "The account reference could not be found"
    }
    $accountReference = $accountReference.Trim()

    $actionMessage = 'resolving the regional configuration of the permission'
    $settings = $regionalConfigurations[[string]$ActionContext.References.Permission.Id]
    if ($null -eq $settings) {
        throw "No regional configuration defined for permission id [$($ActionContext.References.Permission.Id)]"
    }

    $actionMessage = 'authenticating to the Exchange Admin API'
    $certificate = Get-MSEntraCertificate
    $exoAccessToken = Get-MSEntraAccessToken -Certificate $certificate -Resource 'https://outlook.office365.com'

    $ExOAuthorization = @{
        Authorization  = "Bearer $($exoAccessToken)"
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
    }

    Write-Information 'Successfully authenticated the Exchange Admin API'

    # Route every request of this action to the backend server of the account's own mailbox (Oid:<object id>@<tenant id>)
    $ExOAuthorization['X-AnchorMailbox'] = "Oid:$($accountReference)@$($ActionContext.Configuration.TenantID)"

    $exoRequestParams = @{
        Authorization = $ExOAuthorization
        TenantID      = $ActionContext.Configuration.TenantID
        Identity      = $accountReference
        Deadline      = $deadline
    }

    $actionMessage = "setting the regional configuration (language [$($settings.Language)], time zone [$($settings.TimeZone)]) on mailbox [$($accountReference)]"
    if ($ActionContext.DryRun -eq $true) {
        Write-Information "DryRun: Would set language [$($settings.Language)] and time zone [$($settings.TimeZone)] on mailbox [$($accountReference)]"
    }
    else {
        [void](Set-ExOMailboxRegionalConfiguration @exoRequestParams @settings)
    }

    $auditMessage = "Grant permission [$($ActionContext.PermissionDisplayName)] with id [$($ActionContext.References.Permission.Id)] to account with account reference [$($accountReference)] was successful (language [$($settings.Language)], time zone [$($settings.TimeZone)])"

    $OutputContext.AuditLogs.Add(
        [PSCustomObject]@{
            Message = $auditMessage
            IsError = $false
        }
    )

    $OutputContext.Success = $true
}
catch {
    $OutputContext.Success = $false
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
    $OutputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
#endregion script
