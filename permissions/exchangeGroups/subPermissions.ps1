#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-SubPermissions-ExchangeGroups
# Grant and revoke Exchange Online group memberships dynamically, based on the contracts of the person
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
function Remove-ExODistributionGroupMember {
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
            CmdletName = 'Remove-DistributionGroupMember'
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Remove-DistributionGroupMember' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Remove-DistributionGroupMember failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    Write-Output $response
}
function Get-ExOGroupsByAttribute {
    # Returns the Exchange Online groups (distribution groups and mail-enabled security groups, not synced from
    # on-premises) where the attribute has the value. Server-side filter, so only the matching groups are returned.
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
            CmdletName = 'Get-DistributionGroup'
            Parameters = @{
                Filter      = "$($Field) -eq '$($Value -replace "'", "''")' -and IsDirSynced -eq 'False'"
                ResultSize  = 'Unlimited'
                # Without ErrorAction Stop, cmdlet errors are returned inside an HTTP 200 response in '@adminapi.errors'
                ErrorAction = 'Stop'
            }
        }
    }

    for ($attempt = 0; ; $attempt++) {
        $headers = New-ExORequestHeaders -BaseHeaders $Authorization
        $request = @{
            Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand?`$select=ExchangeObjectId,DisplayName,RecipientTypeDetails"
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
            Assert-ExOCommandResponse -Response $response -CmdletName 'Get-DistributionGroup' -ClientRequestId $headers['client-request-id']
            break
        }
        catch {
            $retryDelay = Get-ExORetryDelay -ErrorRecord $_ -Attempt $attempt -Deadline $Deadline
            if ($retryDelay -lt 0) {
                throw
            }

            Write-Warning "Get-DistributionGroup failed (attempt $($attempt + 1), client-request-id $($headers['client-request-id'])), retrying in $($retryDelay) ms. Error: $($_.Exception.Message)"
            Start-Sleep -Milliseconds $retryDelay
        }
    }

    @($response.value | Where-Object { -not [string]::IsNullOrEmpty($_.ExchangeObjectId) })
}
#endregion Functions

#region script
# HelloID stops an action after 30 seconds. All requests and retries must finish before this deadline.
$deadline = [datetime]::UtcNow.AddSeconds(25)

# The group of a contract is the group where this attribute has the value of the department of the contract.
# The resource script resources/exchangeGroups/resources.ps1 creates the groups with this attribute.
$correlationField = 'CustomAttribute1'

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{}
foreach ($permission in $ActionContext.CurrentPermissions) {
    $currentPermissions["$($permission.Reference.Id)"] = $permission.DisplayName
}

try {
    $actionMessage = 'validating account reference'

    $accountReference = [string]$ActionContext.References.Account
    if ([string]::IsNullOrWhiteSpace($accountReference)) {
        throw "The account reference could not be found"
    }
    $accountReference = $accountReference.Trim()

    $actionMessage = 'authenticating to the Exchange Admin API'
    $certificate = Get-MSEntraCertificate
    $exoAccessToken = Get-MSEntraAccessToken -Certificate $certificate -Resource 'https://outlook.office365.com'

    $ExOAuthorization = @{
        Authorization  = "Bearer $($exoAccessToken)"
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
    }

    Write-Information 'Successfully authenticated the Exchange Admin API'

    # Routing hint for the Exchange Admin API, format per Microsoft docs: APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@<tenantIdOrOrganization>
    $ExOAuthorization['X-AnchorMailbox'] = "APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$($ActionContext.Configuration.TenantID)"
    $tenantId = $ActionContext.Configuration.TenantID

    #region Define desired permissions
    $actionMessage = 'calculating desired permissions'
    $desiredPermissions = @{}
    if ($ActionContext.Operation -ne 'revoke') {
        # Example: contract based logic, one group per department
        foreach ($contract in $PersonContext.Person.Contracts) {
            Write-Information "Contract: $($contract.ExternalId). In condition: $($contract.Context.InConditions)"
            if ($contract.Context.InConditions -or ($ActionContext.DryRun -eq $true)) {
                $correlationValue = [string]$contract.Department.ExternalId
                if ([string]::IsNullOrWhiteSpace($correlationValue)) {
                    Write-Warning "Contract [$($contract.ExternalId)] has no department, no group for this contract"
                    continue
                }

                $actionMessage = "querying Exchange Online group where [$($correlationField)] = [$($correlationValue)]"
                $groups = Get-ExOGroupsByAttribute -Authorization $ExOAuthorization -TenantID $tenantId -Field $correlationField -Value $correlationValue -Deadline $deadline

                if ($groups.Count -eq 0) {
                    $OutputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = 'GrantPermission'
                            Message = "No Exchange Online group found where [$($correlationField)] = [$($correlationValue)]"
                            IsError = $true
                        })
                }
                elseif ($groups.Count -gt 1) {
                    $OutputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = 'GrantPermission'
                            Message = "Multiple Exchange Online groups found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the groups are unique."
                            IsError = $true
                        })
                }
                else {
                    # Same names as the static permissions (permissions.ps1) and subPermissionsImport.ps1
                    $displayNamePrefix = if ($groups[0].RecipientTypeDetails -eq 'MailUniversalSecurityGroup') { 'Mail-enabled Security Group' } else { 'Distribution Group' }
                    $displayName = "$($displayNamePrefix) - $($groups[0].DisplayName)"
                    $desiredPermissions["$($groups[0].ExchangeObjectId)"] = $displayName.Substring(0, [System.Math]::Min(100, $displayName.Length))
                }
            }
        }
    }
    #endregion Define desired permissions

    Write-Information "Desired permissions: $(($desiredPermissions.Values | Sort-Object) -join ', ')"
    Write-Information "Current permissions: $(($currentPermissions.Values | Sort-Object) -join ', ')"

    #region Revoke the groups that are no longer desired
    foreach ($permission in $currentPermissions.GetEnumerator()) {
        if ($desiredPermissions.ContainsKey($permission.Name) -or $permission.Name -eq 'No permissions defined') {
            continue
        }

        $actionMessage = "revoking Exchange Online group [$($permission.Value)] with id [$($permission.Name)] from account [$($accountReference)]"
        if ($ActionContext.DryRun -eq $true) {
            Write-Information "DryRun: Would revoke Exchange Online group $($permission.Name) from $($accountReference)"
            continue
        }

        try {
            [void](Remove-ExODistributionGroupMember -Authorization $ExOAuthorization -TenantID $tenantId -Identity $permission.Name -Member $accountReference -Deadline $deadline)
            $OutputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = 'RevokePermission'
                    Message = "Revoked Exchange Online group [$($permission.Value)] with id [$($permission.Name)] from account with account reference [$($accountReference)]"
                    IsError = $false
                })
        }
        catch {
            # The account is no longer a member, or the group or account no longer exists
            if ("$($_.Exception.Message) $($_.ErrorDetails.Message)" -match 'Request_ResourceNotFound|ManagementObjectNotFoundException|MemberNotFoundException|not found|isn''t a member') {
                $OutputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = 'RevokePermission'
                        Message = "Skipped revoking Exchange Online group [$($permission.Value)] with id [$($permission.Name)] from account with account reference [$($accountReference)]. Reason: User is already no longer a member or the group no longer exists."
                        IsError = $false
                    })
            }
            else {
                throw
            }
        }
    }
    #endregion Revoke the groups that are no longer desired

    #region Grant the desired groups
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $OutputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })

        if ($currentPermissions.ContainsKey($permission.Name)) {
            continue
        }

        $actionMessage = "granting Exchange Online group [$($permission.Value)] with id [$($permission.Name)] to account [$($accountReference)]"
        if ($ActionContext.DryRun -eq $true) {
            Write-Information "DryRun: Would grant Exchange Online group $($permission.Name) to $($accountReference)"
            continue
        }

        $alreadyMember = $false
        try {
            [void](Add-ExODistributionGroupMember -Authorization $ExOAuthorization -TenantID $tenantId -Identity $permission.Name -Member $accountReference -Deadline $deadline)
        }
        catch {
            # The account is already a member (for example after a timeout or a retry by HelloID)
            if ("$($_.Exception.Message) $($_.ErrorDetails.Message)" -match 'MemberAlreadyExistsException|is already a member') {
                $alreadyMember = $true
            }
            else {
                throw
            }
        }

        $auditMessage = "Granted Exchange Online group [$($permission.Value)] with id [$($permission.Name)] to account with account reference [$($accountReference)]"
        if ($alreadyMember) {
            $auditMessage = "$($auditMessage) (the account was already a member)"
        }
        $OutputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = 'GrantPermission'
                Message = $auditMessage
                IsError = $false
            })
    }
    #endregion Grant the desired groups
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
