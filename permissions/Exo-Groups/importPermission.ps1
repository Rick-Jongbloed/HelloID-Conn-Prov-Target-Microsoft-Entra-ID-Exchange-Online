#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-Groups-Import
# Correlate accounts to Exchange Online group permissions
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

function Get-ExODistributionGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID
    )

    $Body = @{
        CmdletInput = @{
            CmdletName = 'Get-DistributionGroup'
            Parameters = @{
                ResultSize = 'Unlimited'
            }
        }
    }

    $Request = @{
        Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand?`$select=Guid,DisplayName,RecipientTypeDetails,Description,IsDirSynced"
        Method      = 'Post'
        Headers     = $Authorization
        ContentType = 'application/json'
        Body        = [System.Text.Encoding]::UTF8.GetBytes(
            (ConvertTo-Json $Body -Depth 10 -Compress)
        )
    }

    $Response = Invoke-RestMethod @Request
    $Response.Value |
        Where-Object { $_.IsDirSynced -notin @($true, 'True') -and -not [string]::IsNullOrEmpty($_.Guid) } |
        Select-Object Guid, DisplayName, RecipientTypeDetails, Description
}

function Get-ExODistributionGroupMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Identity
    )

    $Body = @{
        CmdletInput = @{
            CmdletName = 'Get-DistributionGroupMember'
            Parameters = @{
                Identity   = $Identity
                ResultSize = 'Unlimited'
            }
        }
    }

    $Request = @{
        Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand?`$select=Guid,ExternalDirectoryObjectId,RecipientTypeDetails"
        Method      = 'Post'
        Headers     = $Authorization
        ContentType = 'application/json'
        Body        = [System.Text.Encoding]::UTF8.GetBytes(
            (ConvertTo-Json $Body -Depth 10 -Compress)
        )
    }

    $Response = Invoke-RestMethod @Request
    $Response.Value |
        Where-Object { $_.RecipientTypeDetails -eq 'UserMailbox' -and -not [string]::IsNullOrEmpty($_.ExternalDirectoryObjectId) } |
        Select-Object ExternalDirectoryObjectId, Guid, RecipientTypeDetails
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
#endregion Functions

#region script
try {
    Write-Information 'Starting Exchange Online groups permission import'

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

    if ([string]::IsNullOrEmpty($ActionContext.Configuration.Organization)) {
        throw 'Organization field is required but is not configured'
    }

    $ExOAuthorization['X-AnchorMailbox'] = "APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$($ActionContext.Configuration.Organization.TrimStart('@').Trim())"

    $actionMessage = 'retrieving Exchange Online groups'
    Write-Information $actionMessage
    $Groups = Get-ExODistributionGroups -Authorization $ExOAuthorization -TenantID $tenantId
    Write-Information "Retrieved $(($Groups | Measure-Object).Count) Exchange Online groups."

    foreach ($group in $Groups) {
        $actionMessage = "retrieving members for Exchange Online group [$($group.Guid)]"

        try {
            $groupMembers = Get-ExODistributionGroupMembers -Authorization $ExOAuthorization -TenantID $tenantId -Identity $group.Guid
        }
        catch {
            Write-Warning "Failed to retrieve members for Exchange Online group [$($group.Guid)]: $($_.Exception.Message)"
            $groupMembers = @()
        }

        $accountReferences = @($groupMembers | ForEach-Object { $_.ExternalDirectoryObjectId })

        $displayNamePrefix = if ($group.RecipientTypeDetails -eq 'MailUniversalSecurityGroup') {
            'Mail-enabled Security Group'
        }
        else {
            'Distribution Group'
        }

        $displayName = "$displayNamePrefix - $($group.DisplayName)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length))

        $description = $group.Description | Select-Object -First 1
        if (-not [string]::IsNullOrEmpty($description)) {
            $description = $description.substring(0, [System.Math]::Min(100, $description.Length))
        }

        $permission = @{
            PermissionReference = @{
                Id = $group.Guid
            }
            Description = $description
            DisplayName = $displayName
        }

        $numberOfAccounts = $accountReferences.Count
        $batchSize = 500
        for ($i = 0; $i -lt $numberOfAccounts; $i += $batchSize) {
            $permission.AccountReferences = $accountReferences[$i..([Math]::Min($i + $batchSize - 1, $numberOfAccounts - 1))]
            Write-Output $permission
        }
    }

    Write-Information 'Exchange Online groups permission import completed'
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
