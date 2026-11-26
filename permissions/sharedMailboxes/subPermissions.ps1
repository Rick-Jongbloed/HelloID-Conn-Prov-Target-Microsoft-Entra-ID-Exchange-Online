#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-SubPermissions-SharedMailboxes
# Grant and revoke Full Access, Send As or Send on Behalf on shared mailboxes dynamically, based on the contracts of the person
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
function Test-ExOMailboxPermission {
    # Returns $true when the user has an explicit (not inherited, not denied) Full Access permission on the mailbox
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [string]$User,

        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    $body = @{
        CmdletInput = @{
            CmdletName = 'Get-MailboxPermission'
            Parameters = @{
                Identity    = $Identity
                User        = $User
                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                ErrorAction = 'Stop'
            }
        }
    }

    for ($attempt = 0; ; $attempt++) {
        $headers = New-ExORequestHeaders -BaseHeaders $Authorization
        $request = @{
            Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand?`$select=User,AccessRights,Deny,IsInherited"
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Get-MailboxPermission' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Get-MailboxPermission failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    $activeEntries = @(
        @($response.value) | Where-Object {
            "$($_.AccessRights)" -match 'FullAccess' -and
            "$($_.Deny)" -ne 'True' -and
            "$($_.IsInherited)" -ne 'True'
        }
    )

    Write-Output ($activeEntries.Count -gt 0)
}

function Test-ExORecipientPermission {
    # Returns $true when the trustee has an explicit (not inherited, not denied) Send As permission on the mailbox
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [string]$Trustee,

        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    $body = @{
        CmdletInput = @{
            CmdletName = 'Get-RecipientPermission'
            Parameters = @{
                Identity     = $Identity
                Trustee      = $Trustee
                AccessRights = 'SendAs'
                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                ErrorAction  = 'Stop'
            }
        }
    }

    for ($attempt = 0; ; $attempt++) {
        $headers = New-ExORequestHeaders -BaseHeaders $Authorization
        $request = @{
            Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand?`$select=Trustee,AccessRights,AccessControlType,IsInherited"
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Get-RecipientPermission' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Get-RecipientPermission failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    $activeEntries = @(
        @($response.value) | Where-Object {
            "$($_.AccessRights)" -match 'SendAs' -and
            "$($_.AccessControlType)" -notin @('Deny', '1') -and
            "$($_.IsInherited)" -ne 'True'
        }
    )

    Write-Output ($activeEntries.Count -gt 0)
}

function Add-ExOMailboxPermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [string]$User,

        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    $body = @{
        CmdletInput = @{
            CmdletName = 'Add-MailboxPermission'
            Parameters = @{
                Identity        = $Identity
                User            = $User
                AccessRights    = 'FullAccess'
                InheritanceType = 'All'
                AutoMapping     = $true
                Confirm         = $false
                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                ErrorAction     = 'Stop'
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Add-MailboxPermission' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Add-MailboxPermission failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    Write-Output $response
}

function Add-ExORecipientPermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [string]$Trustee,

        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    $body = @{
        CmdletInput = @{
            CmdletName = 'Add-RecipientPermission'
            Parameters = @{
                Identity     = $Identity
                Trustee      = $Trustee
                AccessRights = 'SendAs'
                Confirm      = $false
                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                ErrorAction  = 'Stop'
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Add-RecipientPermission' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Add-RecipientPermission failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    Write-Output $response
}

# Officially supported by Microsoft (v2.0 Mailbox endpoint). ErrorAction is not a supported parameter on this endpoint
function Set-ExOMailboxGrantSendOnBehalfV2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [string]$GrantSendOnBehalfTo,

        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    $body = @{
        CmdletInput = @{
            CmdletName = 'Set-Mailbox'
            Parameters = @{
                Identity            = $Identity
                GrantSendOnBehalfTo = @{
                    '@odata.type' = '#Exchange.GenericHashTable'
                    add           = @($GrantSendOnBehalfTo)
                }
            }
        }
    }

    for ($attempt = 0; ; $attempt++) {
        $headers = New-ExORequestHeaders -BaseHeaders $Authorization
        $request = @{
            Uri         = "https://outlook.office365.com/adminapi/v2.0/$TenantID/Mailbox"
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Set-Mailbox' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Set-Mailbox failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    Write-Output $response
}
function Remove-ExOMailboxPermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [string]$User,

        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    $body = @{
        CmdletInput = @{
            CmdletName = 'Remove-MailboxPermission'
            Parameters = @{
                Identity        = $Identity
                User            = $User
                AccessRights    = 'FullAccess'
                InheritanceType = 'All'
                Confirm         = $false
                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                ErrorAction     = 'Stop'
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Remove-MailboxPermission' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Remove-MailboxPermission failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    Write-Output $response
}

function Remove-ExORecipientPermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [string]$Trustee,

        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    $body = @{
        CmdletInput = @{
            CmdletName = 'Remove-RecipientPermission'
            Parameters = @{
                Identity     = $Identity
                Trustee      = $Trustee
                AccessRights = 'SendAs'
                Confirm      = $false
                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                ErrorAction  = 'Stop'
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Remove-RecipientPermission' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Remove-RecipientPermission failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    Write-Output $response
}

# Officially supported by Microsoft (v2.0 Mailbox endpoint). ErrorAction is not a supported parameter on this endpoint
function Set-ExOMailboxRevokeGrantSendOnBehalfV2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter(Mandatory)]
        [string]$GrantSendOnBehalfTo,

        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    $body = @{
        CmdletInput = @{
            CmdletName = 'Set-Mailbox'
            Parameters = @{
                Identity            = $Identity
                GrantSendOnBehalfTo = @{
                    '@odata.type' = '#Exchange.GenericHashTable'
                    remove        = @($GrantSendOnBehalfTo)
                }
            }
        }
    }

    for ($attempt = 0; ; $attempt++) {
        $headers = New-ExORequestHeaders -BaseHeaders $Authorization
        $request = @{
            Uri         = "https://outlook.office365.com/adminapi/v2.0/$TenantID/Mailbox"
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Set-Mailbox' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Set-Mailbox failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    Write-Output $response
}
function Get-ExOSharedMailboxesByAttribute {
    # Returns the shared mailboxes where the attribute has the value. Server-side filter, so only the matching
    # mailboxes are returned.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Field,

        [Parameter(Mandatory)]
        [string]$Value,

        [Parameter(Mandatory)]
        [datetime]$Deadline
    )

    # A ' in the value is doubled, as OPATH filters require
    $body = @{
        CmdletInput = @{
            CmdletName = 'Get-Mailbox'
            Parameters = @{
                Filter      = "$($Field) -eq '$($Value -replace "'", "''")' -and RecipientTypeDetails -eq 'SharedMailbox'"
                ResultSize  = 'Unlimited'
                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                ErrorAction = 'Stop'
            }
        }
    }

    for ($attempt = 0; ; $attempt++) {
        $headers = New-ExORequestHeaders -BaseHeaders $Authorization
        $request = @{
            Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand?`$select=ExternalDirectoryObjectId,DisplayName"
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Get-Mailbox' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Get-Mailbox failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    @($response.value | Where-Object { -not [string]::IsNullOrEmpty($_.ExternalDirectoryObjectId) })
}

function Grant-SharedMailboxPermission {
    # Grants one permission on one shared mailbox, the same way as grantPermission.ps1: an error while the permission is
    # already present counts as success, and Full Access and Send As are verified. Returns $true when it was already present.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$RequestParams,

        [Parameter(Mandatory)]
        [string]$Permission,

        [Parameter(Mandatory)]
        [string]$Account
    )

    $alreadyGranted = $false
    try {
        switch ($Permission) {
            'FullAccess' { [void](Add-ExOMailboxPermission @RequestParams -User $Account) }
            'SendAs' { [void](Add-ExORecipientPermission @RequestParams -Trustee $Account) }
            'SendOnBehalf' { [void](Set-ExOMailboxGrantSendOnBehalfV2 @RequestParams -GrantSendOnBehalfTo $Account) }
        }
    }
    catch {
        # Send on Behalf uses the officially supported v2.0 endpoint and is not verified
        if ($Permission -eq 'SendOnBehalf') {
            throw
        }

        # The grant can fail while the permission is already present (for example after a timeout or a retry by HelloID)
        $grantError = $PSItem
        try {
            if ($Permission -eq 'FullAccess') {
                $alreadyGranted = Test-ExOMailboxPermission @RequestParams -User $Account
            }
            else {
                $alreadyGranted = Test-ExORecipientPermission @RequestParams -Trustee $Account
            }
        }
        catch {
            throw $grantError
        }

        if (-not $alreadyGranted) {
            throw $grantError
        }

        Write-Information "Granting [$($Permission)] returned an error, but the permission is already present. Error: $($grantError.Exception.Message)"
    }

    # Verify that the permission is visible. The beta endpoint can report success while the change is not (yet) processed.
    if ($Permission -in @('FullAccess', 'SendAs') -and -not $alreadyGranted) {
        $isGranted = $false
        $verificationAttempt = 0
        while ($true) {
            $verificationAttempt++
            if ($Permission -eq 'FullAccess') {
                $isGranted = Test-ExOMailboxPermission @RequestParams -User $Account
            }
            else {
                $isGranted = Test-ExORecipientPermission @RequestParams -Trustee $Account
            }

            if ($isGranted) {
                break
            }

            # Stop when there is no time left for another check (wait + request)
            if ([datetime]::UtcNow.AddSeconds($verificationIntervalSeconds + 3) -gt $RequestParams.Deadline) {
                break
            }

            Start-Sleep -Seconds $verificationIntervalSeconds
        }

        if (-not $isGranted) {
            throw "The grant returned success, but the permission is not visible after $($verificationAttempt) checks. HelloID will retry the action."
        }
    }

    Write-Output $alreadyGranted
}

function Revoke-SharedMailboxPermission {
    # Revokes one permission on one shared mailbox, the same way as revokePermission.ps1: a mailbox or account that no
    # longer exists, or a permission that is already removed, counts as success, and Full Access and Send As are verified.
    # Returns the reason when nothing had to be removed, otherwise $null.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$RequestParams,

        [Parameter(Mandatory)]
        [string]$Permission,

        [Parameter(Mandatory)]
        [string]$Account
    )

    $skipReason = $null
    try {
        switch ($Permission) {
            'FullAccess' { [void](Remove-ExOMailboxPermission @RequestParams -User $Account) }
            'SendAs' { [void](Remove-ExORecipientPermission @RequestParams -Trustee $Account) }
            'SendOnBehalf' { [void](Set-ExOMailboxRevokeGrantSendOnBehalfV2 @RequestParams -GrantSendOnBehalfTo $Account) }
        }
    }
    catch {
        $revokeError = $PSItem
        $revokeErrorText = "$($revokeError.Exception.Message) $($revokeError.ErrorDetails.Message)"

        # The shared mailbox or the account no longer exists, so the permission no longer exists either
        if ($revokeErrorText -match 'ManagementObjectNotFoundException|Request_ResourceNotFound') {
            return 'The shared mailbox or the account no longer exists.'
        }

        # Send on Behalf uses the officially supported v2.0 endpoint and is not verified
        if ($Permission -eq 'SendOnBehalf') {
            throw
        }

        # The revoke can fail while the permission is already removed (for example after a timeout or a retry by HelloID)
        try {
            if ($Permission -eq 'FullAccess') {
                $stillPresent = Test-ExOMailboxPermission @RequestParams -User $Account
            }
            else {
                $stillPresent = Test-ExORecipientPermission @RequestParams -Trustee $Account
            }
        }
        catch {
            throw $revokeError
        }

        if ($stillPresent) {
            throw $revokeError
        }

        return 'The permission was already removed.'
    }

    # Verify that the permission is removed. The beta endpoint can report success while the change is not (yet) processed.
    if ($Permission -in @('FullAccess', 'SendAs')) {
        $isRevoked = $false
        $verificationAttempt = 0
        while ($true) {
            $verificationAttempt++
            if ($Permission -eq 'FullAccess') {
                $isRevoked = -not (Test-ExOMailboxPermission @RequestParams -User $Account)
            }
            else {
                $isRevoked = -not (Test-ExORecipientPermission @RequestParams -Trustee $Account)
            }

            if ($isRevoked) {
                break
            }

            # Stop when there is no time left for another check (wait + request)
            if ([datetime]::UtcNow.AddSeconds($verificationIntervalSeconds + 3) -gt $RequestParams.Deadline) {
                break
            }

            Start-Sleep -Seconds $verificationIntervalSeconds
        }

        if (-not $isRevoked) {
            throw "The revoke returned success, but the permission is still visible after $($verificationAttempt) checks. HelloID will retry the action."
        }
    }

    Write-Output $skipReason
}
#endregion Functions

#region script
# HelloID stops an action after 30 seconds. All requests, retries and verifications of all mailboxes of this action must
# finish before this deadline.
$deadline = [datetime]::UtcNow.AddSeconds(25)
$verificationIntervalSeconds = 2

# The shared mailbox of a contract is the shared mailbox where this attribute has the value of the department of the
# contract. The resource script resources/sharedMailboxes/resources.ps1 creates the shared mailboxes with this attribute.
$correlationField = 'CustomAttribute1'

# The permission (FullAccess, SendAs or SendOnBehalf) is the reference of the dynamic permission in HelloID: create one
# dynamic permission per permission, with this script. In the preview the reference can be empty; to test the preview,
# set the permission here, for example $permissionType = 'FullAccess'.
$permissionType = $ActionContext.References.Permission.Reference
# $permissionType = 'FullAccess'

$permissionNames = @{ FullAccess = 'Full Access'; SendAs = 'Send As'; SendOnBehalf = 'Send on Behalf' }

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{}
foreach ($permission in $ActionContext.CurrentPermissions) {
    $currentPermissions["$($permission.Reference.Id)"] = $permission.DisplayName
}

try {
    $actionMessage = 'validating account reference and permission'

    $accountReference = [string]$ActionContext.References.Account
    if ([string]::IsNullOrWhiteSpace($accountReference)) {
        throw "The account reference could not be found"
    }
    $accountReference = $accountReference.Trim()

    if ($permissionType -notin @('FullAccess', 'SendAs', 'SendOnBehalf')) {
        throw "Unsupported permission type [$($permissionType)]. The reference of the dynamic permission must be FullAccess, SendAs or SendOnBehalf."
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
    $tenantId = $ActionContext.Configuration.TenantID

    #region Define desired permissions
    $actionMessage = 'calculating desired permissions'
    $desiredPermissions = @{}
    if ($ActionContext.Operation -ne 'revoke') {
        # The lookup uses the system mailbox anchor, like the lists and imports
        $lookupAuthorization = $ExOAuthorization.Clone()
        $lookupAuthorization['X-AnchorMailbox'] = "APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$($tenantId)"

        # Example: contract based logic, one shared mailbox per department
        foreach ($contract in $PersonContext.Person.Contracts) {
            Write-Information "Contract: $($contract.ExternalId). In condition: $($contract.Context.InConditions)"
            if ($contract.Context.InConditions -or ($ActionContext.DryRun -eq $true)) {
                $correlationValue = [string]$contract.Department.ExternalId
                if ([string]::IsNullOrWhiteSpace($correlationValue)) {
                    Write-Warning "Contract [$($contract.ExternalId)] has no department, no shared mailbox for this contract"
                    continue
                }

                $actionMessage = "querying shared mailbox where [$($correlationField)] = [$($correlationValue)]"
                $mailboxes = Get-ExOSharedMailboxesByAttribute -Authorization $lookupAuthorization -TenantID $tenantId -Field $correlationField -Value $correlationValue -Deadline $deadline

                if ($mailboxes.Count -eq 0) {
                    $OutputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = 'GrantPermission'
                            Message = "No shared mailbox found where [$($correlationField)] = [$($correlationValue)]"
                            IsError = $true
                        })
                }
                elseif ($mailboxes.Count -gt 1) {
                    $OutputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = 'GrantPermission'
                            Message = "Multiple shared mailboxes found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the shared mailboxes are unique."
                            IsError = $true
                        })
                }
                else {
                    # Same names as the static permissions (permissions.ps1) and subPermissionsImport.ps1
                    $displayName = "Shared Mailbox - $($mailboxes[0].DisplayName)"
                    $displayName = $displayName.Substring(0, [System.Math]::Min(83, $displayName.Length))
                    $desiredPermissions["$($mailboxes[0].ExternalDirectoryObjectId)"] = "$($displayName) - $($permissionNames[$permissionType])"
                }
            }
        }
    }
    #endregion Define desired permissions

    Write-Information "Desired permissions: $(($desiredPermissions.Values | Sort-Object) -join ', ')"
    Write-Information "Current permissions: $(($currentPermissions.Values | Sort-Object) -join ', ')"

    #region Revoke the shared mailboxes that are no longer desired
    foreach ($permission in $currentPermissions.GetEnumerator()) {
        if ($desiredPermissions.ContainsKey($permission.Name) -or $permission.Name -eq 'No permissions defined') {
            continue
        }

        $mailboxId = $permission.Name
        $actionMessage = "revoking permission [$($permissionType)] on shared mailbox [$($mailboxId)] from account [$($accountReference)]"
        if ($ActionContext.DryRun -eq $true) {
            Write-Information "DryRun: Would revoke $($permissionType) on $($mailboxId) from $($accountReference)"
            continue
        }

        # Route all requests for this mailbox to its own backend server (Oid anchor), like grantPermission.ps1
        $mailboxAuthorization = $ExOAuthorization.Clone()
        $mailboxAuthorization['X-AnchorMailbox'] = "Oid:$($mailboxId)@$($tenantId)"
        $requestParams = @{ Authorization = $mailboxAuthorization; TenantID = $tenantId; Identity = $mailboxId; Deadline = $deadline }

        $skipReason = Revoke-SharedMailboxPermission -RequestParams $requestParams -Permission $permissionType -Account $accountReference
        $auditMessage = "Revoked permission [$($permission.Value)] with id [$($mailboxId)] from account with account reference [$($accountReference)]"
        if ($skipReason) {
            $auditMessage = "Skipped revoking permission [$($permission.Value)] with id [$($mailboxId)] from account with account reference [$($accountReference)]. Reason: $($skipReason)"
        }
        $OutputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = 'RevokePermission'
                Message = $auditMessage
                IsError = $false
            })
    }
    #endregion Revoke the shared mailboxes that are no longer desired

    #region Grant the desired shared mailboxes
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $mailboxId = $permission.Name
        $OutputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $mailboxId; Permission = $permissionType }
            })

        if ($currentPermissions.ContainsKey($mailboxId)) {
            continue
        }

        $actionMessage = "granting permission [$($permissionType)] on shared mailbox [$($mailboxId)] to account [$($accountReference)]"
        if ($ActionContext.DryRun -eq $true) {
            Write-Information "DryRun: Would grant $($permissionType) on $($mailboxId) to $($accountReference)"
            continue
        }

        # Route all requests for this mailbox to its own backend server (Oid anchor), like grantPermission.ps1
        $mailboxAuthorization = $ExOAuthorization.Clone()
        $mailboxAuthorization['X-AnchorMailbox'] = "Oid:$($mailboxId)@$($tenantId)"
        $requestParams = @{ Authorization = $mailboxAuthorization; TenantID = $tenantId; Identity = $mailboxId; Deadline = $deadline }

        $alreadyGranted = Grant-SharedMailboxPermission -RequestParams $requestParams -Permission $permissionType -Account $accountReference
        $auditMessage = "Granted permission [$($permission.Value)] with id [$($mailboxId)] to account with account reference [$($accountReference)]"
        if ($alreadyGranted) {
            $auditMessage = "$($auditMessage) (the permission was already present)"
        }
        $OutputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = 'GrantPermission'
                Message = $auditMessage
                IsError = $false
            })
    }
    #endregion Grant the desired shared mailboxes
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
    $OutputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
finally {
    # Without a sub permission the entitlement fails in HelloID, so an empty result gets a placeholder
    if ($ActionContext.Operation -match 'update|grant' -and $OutputContext.SubPermissions.Count -eq 0) {
        $OutputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = 'No permissions defined'
                Reference   = [PSCustomObject]@{ Id = 'No permissions defined' }
            })
        Write-Warning "Skipped granting permissions for account with account reference [$($ActionContext.References.Account)]. Reason: No permissions defined."
    }

    # Success when no audit log is an error
    $OutputContext.Success = -not ($OutputContext.AuditLogs.IsError -contains $true)
}
#endregion script
