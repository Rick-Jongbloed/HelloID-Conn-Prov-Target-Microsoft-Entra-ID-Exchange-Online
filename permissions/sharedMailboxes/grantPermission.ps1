#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-SharedMailbox-Grant
# Grant shared mailbox permission (full access, send as, send on behalf)
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
#endregion Functions

#region script
# HelloID stops an action after 30 seconds. All requests, retries and the verification must finish before this deadline.
$deadline = [datetime]::UtcNow.AddSeconds(25)
$verificationIntervalSeconds = 2

try {
    $actionMessage = 'validating account reference'
    $accountReference = [string]$ActionContext.References.Account

    # Verify account reference
    if ([string]::IsNullOrWhiteSpace($accountReference)) {
        throw "The account reference could not be found"
    }

    $accountReference = $accountReference.Trim()
    $mailboxId = $ActionContext.References.Permission.Id
    $permission = $ActionContext.References.Permission.Permission

    if ($permission -notin @('FullAccess', 'SendAs', 'SendOnBehalf')) {
        throw "Unsupported permission type: [$($permission)]"
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

    $exoRequestParams = @{
        Authorization = $ExOAuthorization
        TenantID      = $ActionContext.Configuration.TenantID
        Identity      = $mailboxId
        Deadline      = $deadline
    }

    $actionMessage = "granting permission [$($permission)] on shared mailbox [$($mailboxId)] to account [$($accountReference)]"

    $alreadyGranted = $false

    if ($ActionContext.DryRun -eq $true) {
        Write-Information "DryRun: Would grant $($permission) on $($mailboxId) to $($accountReference)"
    }
    else {
        try {
            switch ($permission) {
                'FullAccess' {
                    [void](Add-ExOMailboxPermission @exoRequestParams -User $accountReference)
                }
                'SendAs' {
                    [void](Add-ExORecipientPermission @exoRequestParams -Trustee $accountReference)
                }
                'SendOnBehalf' {
                    [void](Set-ExOMailboxGrantSendOnBehalfV2 @exoRequestParams -GrantSendOnBehalfTo $accountReference)
                }
            }
        }
        catch {
            # Send on Behalf uses the officially supported v2.0 endpoint and is not verified
            if ($permission -eq 'SendOnBehalf') {
                throw
            }

            # The grant can fail while the permission is already present (for example after a timeout or a retry by HelloID).
            # Check the actual state before reporting an error.
            $grantError = $PSItem
            try {
                if ($permission -eq 'FullAccess') {
                    $alreadyGranted = Test-ExOMailboxPermission @exoRequestParams -User $accountReference
                }
                else {
                    $alreadyGranted = Test-ExORecipientPermission @exoRequestParams -Trustee $accountReference
                }
            }
            catch {
                throw $grantError
            }

            if (-not $alreadyGranted) {
                throw $grantError
            }

            Write-Information "Granting [$($permission)] returned an error, but the permission is already present. Error: $($grantError.Exception.Message)"
        }

        # Verify that the permission is visible. The beta endpoint can report success while the change is not (yet) processed.
        if ($permission -in @('FullAccess', 'SendAs') -and -not $alreadyGranted) {
            $actionMessage = "verifying permission [$($permission)] on shared mailbox [$($mailboxId)] for account [$($accountReference)]"
            $isGranted = $false
            $verificationAttempt = 0

            while ($true) {
                $verificationAttempt++
                if ($permission -eq 'FullAccess') {
                    $isGranted = Test-ExOMailboxPermission @exoRequestParams -User $accountReference
                }
                else {
                    $isGranted = Test-ExORecipientPermission @exoRequestParams -Trustee $accountReference
                }

                if ($isGranted) {
                    break
                }

                # Stop when there is no time left for another check (wait + request)
                if ([datetime]::UtcNow.AddSeconds($verificationIntervalSeconds + 3) -gt $deadline) {
                    break
                }

                Start-Sleep -Seconds $verificationIntervalSeconds
            }

            if (-not $isGranted) {
                throw "The grant returned success, but the permission is not visible after $($verificationAttempt) checks. HelloID will retry the action."
            }

            Write-Information "Verified permission [$($permission)] after $($verificationAttempt) check(s)"
        }
    }

    $auditMessage = "Grant permission [$($ActionContext.PermissionDisplayName)] with id [$($mailboxId)] to account with account reference [$($accountReference)] was successful"
    if ($alreadyGranted) {
        $auditMessage = "$($auditMessage) (the permission was already present)"
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
