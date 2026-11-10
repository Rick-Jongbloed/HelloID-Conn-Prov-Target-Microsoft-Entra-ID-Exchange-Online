#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-ExchangeGroups-Grant
# Grant Exchange Online group membership to account
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
        $ErrorRecord.Exception -is [System.Threading.Tasks.TaskCanceledException] -or
        $ErrorRecord.Exception -is [System.TimeoutException] -or
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
function Add-ExODistributionGroupMember {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [string]$Member,

        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    $body = @{
        CmdletInput = @{
            CmdletName = 'Add-DistributionGroupMember'
            Parameters = @{
                Identity                        = $Identity
                Member                          = $Member
                BypassSecurityGroupManagerCheck = $true
                Confirm                         = $false
                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                ErrorAction                     = 'Stop'
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Add-DistributionGroupMember' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Add-DistributionGroupMember failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
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

    if ([string]::IsNullOrEmpty($ActionContext.References.Account)) {
        throw "The account reference could not be found"
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

    # Use the same routing hint for every request, so all calls (including verification) are routed to the same backend.
    # Format per Microsoft docs: APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@<tenantIdOrOrganization>
    $ExOAuthorization['X-AnchorMailbox'] = "APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$($ActionContext.Configuration.TenantID)"

    $actionMessage = "granting Exchange Online group [$($ActionContext.PermissionDisplayName)] with id [$($ActionContext.References.Permission.Id)] to account [$($ActionContext.References.Account)]"

    $alreadyMember = $false

    if ($ActionContext.DryRun -eq $false) {
        try {
            [void](Add-ExODistributionGroupMember -Authorization $ExOAuthorization `
                -TenantID $ActionContext.Configuration.TenantID `
                -Identity $ActionContext.References.Permission.Id `
                -Member $ActionContext.References.Account `
                -Deadline $deadline)
        }
        catch {
            # The account is already a member (for example after a timeout or a retry by HelloID)
            if ("$($PSItem.Exception.Message) $($PSItem.ErrorDetails.Message)" -match 'MemberAlreadyExistsException|is already a member') {
                $alreadyMember = $true
                Write-Information "Account is already a member of Exchange Online group $($ActionContext.References.Permission.Id)"
            }
            else {
                throw
            }
        }
    }
    else {
        Write-Information "DryRun: Would grant Exchange Online group $($ActionContext.References.Permission.Id) to $($ActionContext.References.Account)"
    }

    $auditMessage = "Grant permission [$($ActionContext.PermissionDisplayName)] with id [$($ActionContext.References.Permission.Id)] to account with account reference [$($ActionContext.References.Account)] was successful"
    if ($alreadyMember) {
        $auditMessage = "$($auditMessage) (the account was already a member)"
    }

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
