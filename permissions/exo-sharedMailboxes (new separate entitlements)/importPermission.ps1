#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-SharedMailboxes-Import
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

    $Uri = "https://outlook.office365.com/adminapi/v2.0/$TenantID/Mailbox?`$select=Guid,DisplayName,UserPrincipalName,RecipientTypeDetails,GrantSendOnBehalfTo,Identity"

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
            Select-Object Guid,
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

function Get-ExOMailboxPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Mailbox
    )

    $Body = @{
        CmdletInput = @{
            CmdletName = 'Get-MailboxPermission'
            Parameters = @{
                Identity   = $Mailbox
                ResultSize = 'Unlimited'
            }
        }
    }

    $Request = @{
        Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand?`$select=User,AccessRights"
        Method      = 'Post'
        Headers     = $Authorization
        ContentType = 'application/json'
        Body        = [System.Text.Encoding]::UTF8.GetBytes(
            (ConvertTo-Json $Body -Depth 10 -Compress)
        )
    }

    $Response = Invoke-RestMethod @Request
    $Response.Value
}

function Get-ExORecipientPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Authorization,

        [Parameter(Mandatory)]
        [string]$TenantID,

        [Parameter(Mandatory)]
        [string]$Mailbox
    )

    $Body = @{
        CmdletInput = @{
            CmdletName = 'Get-RecipientPermission'
            Parameters = @{
                Identity   = $Mailbox
                ResultSize = 'Unlimited'
            }
        }
    }

    $Request = @{
        Uri         = "https://outlook.office365.com/adminapi/beta/$TenantID/InvokeCommand?`$select=Trustee,AccessRights"
        Method      = 'Post'
        Headers     = $Authorization
        ContentType = 'application/json'
        Body        = [System.Text.Encoding]::UTF8.GetBytes(
            (ConvertTo-Json $Body -Depth 10 -Compress)
        )
    }

    $Response = Invoke-RestMethod @Request
    $Response.Value
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

    if ([string]::IsNullOrEmpty($ActionContext.Configuration.Organization)) {
        throw 'Organization field is required but is not configured'
    }

    $ExOAuthorization['X-AnchorMailbox'] = "APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$($ActionContext.Configuration.Organization)"

    $actionMessage = 'retrieving shared mailboxes'
    Write-Information $actionMessage
    $SharedMailboxes = Get-ExOSharedMailboxes -Authorization $ExOAuthorization -TenantID $tenantId
    Write-Information "Retrieved $(($SharedMailboxes | Measure-Object).Count) shared mailboxes."

    $actionMessage = 'retrieving mailbox permissions'
    Write-Information $actionMessage
    $MailboxPermissions = @{}
    $RecipientPermissions = @{}
    foreach ($SharedMailbox in $SharedMailboxes) {
        try {
            $permissions = Get-ExOMailboxPermissions -Authorization $ExOAuthorization -TenantID $tenantId -Mailbox $SharedMailbox.Identity
            $permissions = $permissions | Where-Object {
                $_.User -notin @(
                    'NT AUTHORITY\SELF'
                    'NULL SID'
                )
            }
            if ($permissions) {
                $MailboxPermissions[$SharedMailbox.Identity] = @($permissions)
            }
        }
        catch {
            Write-Warning "Failed to retrieve mailbox permissions for $($SharedMailbox.Identity): $($_.Exception.Message)"
        }

        try {
            $permissions = Get-ExORecipientPermissions -Authorization $ExOAuthorization -TenantID $tenantId -Mailbox $SharedMailbox.Identity
            $permissions = $permissions | Where-Object {
                $_.Trustee -notin @(
                    'NT AUTHORITY\SELF'
                    'NULL SID'
                )
            }
            if ($permissions) {
                $RecipientPermissions[$SharedMailbox.Identity] = @($permissions)
            }
        }
        catch {
            Write-Warning "Failed to retrieve recipient permissions for $($SharedMailbox.Identity): $($_.Exception.Message)"
        }
    }

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
                Id         = $SharedMailbox.Guid
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
                Id         = $SharedMailbox.Guid
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
                Id         = $SharedMailbox.Guid
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
