#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-SharedMailboxes-Grant
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

        [Parameter()]
        [string]$AccessRights = 'FullAccess',

        [Parameter()]
        [string]$InheritanceType = 'All'
    )

    $Body = @{
        CmdletInput = @{
            CmdletName = 'Add-MailboxPermission'
            Parameters = @{
                Identity        = $Identity
                User            = $User
                AccessRights    = $AccessRights
                InheritanceType = $InheritanceType
                AutoMapping     = $true
                Confirm         = $false
            }
        }
    }

    $Request = @{
        Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand"
        Method      = 'Post'
        Headers     = $Authorization
        ContentType = 'application/json'
        Body        = [System.Text.Encoding]::UTF8.GetBytes(
            (ConvertTo-Json $Body -Depth 10 -Compress)
        )
    }

    $Response = Invoke-RestMethod @Request
    $Response
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

        [Parameter()]
        [string]$AccessRights = 'SendAs'
    )

    $Body = @{
        CmdletInput = @{
            CmdletName = 'Add-RecipientPermission'
            Parameters = @{
                Identity     = $Identity
                Trustee      = $Trustee
                AccessRights = $AccessRights
                Confirm      = $false
            }
        }
    }

    $Request = @{
        Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand"
        Method      = 'Post'
        Headers     = $Authorization
        ContentType = 'application/json'
        Body        = [System.Text.Encoding]::UTF8.GetBytes(
            (ConvertTo-Json $Body -Depth 10 -Compress)
        )
    }

    $Response = Invoke-RestMethod @Request
    $Response
}

# Officially supported by Microsoft
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
        [string]$GrantSendOnBehalfTo
    )

    $Body = @{
        CmdletInput = @{
            CmdletName = 'Set-Mailbox'
            Parameters = @{
                Identity            = $Identity
                GrantSendOnBehalfTo = @{
                    '@odata.type' = '#Exchange.GenericHashTable'
                    add           = $GrantSendOnBehalfTo
                }
            }
        }
    }

    $Request = @{
        Uri         = "https://outlook.office365.com/adminapi/v2.0/$TenantID/Mailbox"
        Method      = 'Post'
        Headers     = $Authorization
        ContentType = 'application/json'
        Body        = [System.Text.Encoding]::UTF8.GetBytes(
            (ConvertTo-Json $Body -Depth 10 -Compress)
        )
    }

    $Response = Invoke-RestMethod @Request
    $Response
}
#endregion Functions

#region script
try {
    $actionMessage = 'validating account reference'

    # Verify account reference
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

    $anchorMailboxDomain = $ActionContext.Configuration.Organization

    if (-not [String]::IsNullOrEmpty($anchorMailboxDomain)) {
        if ($anchorMailboxDomain -notlike '*onmicrosoft.com') {
            $Domain = $anchorMailboxDomain -split '.' | Select-Object -First 1
            $anchorMailboxDomain = "$($Domain).onmicrosoft.com"
        }

        $ExOAuthorization['X-AnchorMailbox'] = "APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$($anchorMailboxDomain.TrimStart('@').Trim())"
    }

    $actionMessage = "granting permission [$($ActionContext.References.Permission.Permission)] on shared mailbox [$($ActionContext.References.Permission.Id)] to account [$($ActionContext.References.Account)]"

    switch ($ActionContext.References.Permission.Permission) {
        'FullAccess' {
            if ($ActionContext.DryRun -eq $false) {
                [void](Add-ExOMailboxPermission -Authorization $ExOAuthorization `
                    -TenantID $ActionContext.Configuration.TenantID `
                    -Identity $ActionContext.References.Permission.Id `
                    -User $ActionContext.References.Account `
                    -AccessRights 'FullAccess' `
                    -InheritanceType 'All')
            }
            else {
                Write-Information "DryRun: Would grant FullAccess on $($ActionContext.References.Permission.Id) to $($ActionContext.References.Account)"
            }
        }
        'SendAs' {
            if ($ActionContext.DryRun -eq $false) {
                [void](Add-ExORecipientPermission -Authorization $ExOAuthorization `
                    -TenantID $ActionContext.Configuration.TenantID `
                    -Identity $ActionContext.References.Permission.Id `
                    -Trustee $ActionContext.References.Account `
                    -AccessRights 'SendAs')
            }
            else {
                Write-Information "DryRun: Would grant SendAs on $($ActionContext.References.Permission.Id) to $($ActionContext.References.Account)"
            }
        }
        'SendOnBehalf' {
            if ($ActionContext.DryRun -eq $false) {
                [void](Set-ExOMailboxGrantSendOnBehalfV2 -Authorization $ExOAuthorization `
                    -TenantID $ActionContext.Configuration.TenantID `
                    -Identity $ActionContext.References.Permission.Id `
                    -GrantSendOnBehalfTo $ActionContext.References.Account)
            }
            else {
                Write-Information "DryRun: Would grant SendOnBehalf on $($ActionContext.References.Permission.Id) to $($ActionContext.References.Account)"
            }
        }
        default {
            throw "Unsupported permission type: [$($ActionContext.References.Permission.Permission)]"
        }
    }

    $OutputContext.AuditLogs.Add(
        [PSCustomObject]@{
            Message = "Grant permission [$($ActionContext.PermissionDisplayName)] was successful"
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
