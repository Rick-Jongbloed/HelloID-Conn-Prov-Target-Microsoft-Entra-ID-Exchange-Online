##################################################
# HelloID-Conn-Prov-Target-MS-Entra-Exo-Delete
# PowerShell V2
##################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions

function Resolve-MS-Entra-ExoError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
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


function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
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
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$($actionContext.Configuration.AppId)"
            'sub' = "$($actionContext.Configuration.AppId)"
            'aud' = "https://login.microsoftonline.com/$($actionContext.Configuration.TenantID)/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
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
            throw "The certificate does not have a private key."
        }

        # Create the JWT token
        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $actionContext.Configuration.AppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($actionContext.Configuration.TenantID)/oauth2/token"
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

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($actionContext.Configuration.AppCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $actionContext.Configuration.AppCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion

try {

    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }
    $actionList = @()

    # Setup Connection with EntraID/Exo
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate
    if ($actionContext.Configuration.ExchangeOnlineIntegration -and ($actionContext.Data.PSObject.Properties.Name -contains 'exchangeOnline' -or $actionContext.Origin -eq 'reconciliation')) {
        $actionMessage = "connecting to Exchange Online"
        $createExoSessionSplatParams = @{
            Organization = $actionContext.Configuration.Organization
            AppID        = $actionContext.Configuration.AppId
            Certificate  = $certificate
        }
        $null = Connect-ManagedExchangeOnline @createExoSessionSplatParams  -Verbose:$false -ErrorAction Stop
    }

    Write-Information 'Verifying if a MS-Entra-Exo account exists'

    # Get Entra account
    $actionMessage = 'verifying if a MS-Entra-Exo account exists'
    try {
        $correlatedAccountEntra = $null
        $selectPropertiesToGetUser = $selectPropertiesToGetUser = 'id,' + (($outputContext.Data | Select-Object * -ExcludeProperty ExchangeOnline ).PSObject.Properties.Name -join ',')
        $splatGetEntraUser = @{
            Uri     = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)?`$select=$selectPropertiesToGetUser"
            Method  = 'GET'
            Headers = @{'Authorization' = "Bearer $($entraToken)" }
        }
        $correlatedAccountEntra = Invoke-RestMethod @splatGetEntraUser -Verbose:$false
        $outputContext.PreviousData = $correlatedAccountEntra | Select-Object -Property *
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            $correlatedAccountEntra = $null
        }
        else {
            throw $_
        }
    }

    # Get Exo account
    if ($actionContext.Configuration.deleteAccount -eq $false -and $actionContext.Configuration.ExchangeOnlineIntegration -and ($actionContext.Data.PSObject.Properties.Name -contains 'exchangeOnline' -or $actionContext.Origin -eq 'reconciliation')) {
        if ($null -ne $correlatedAccountEntra) {
            $actionMessage = "querying Exchange Online Mailbox where [ExternalDirectoryObjectId - $($correlatedAccountEntra.Id)]"
            $exoAccountPropertiesToQuery = $outputContext.Data.ExchangeOnline.PsObject.Properties.Name
            $getExoAccountSplatParams = @{
                Filter     = "ExternalDirectoryObjectID -eq '$($correlatedAccountEntra.Id)'"
                Properties = $exoAccountPropertiesToQuery
            }
            $correlatedAccountExo = (Get-EXOMailbox @getExoAccountSplatParams -Verbose:$false -ErrorAction Stop) | Select-Object -First 1
            if ($correlatedAccountExo.PSObject.Properties.name -contains 'EmailAddresses') {
                $correlatedAccountExo.EmailAddresses = $correlatedAccountExo.EmailAddresses | Sort-Object
            }
            $outputContext.PreviousData | Add-Member @{
                exchangeOnline = $correlatedAccountExo
            } -Force
        }
        if ($null -ne $correlatedAccountEntra -and $correlatedAccountExo.Count -eq 0) {
            $correlatedAccountExo = $null
            Write-Warning 'An existing MS-Entra account was found, but no mailbox is associated with it. To add a mailbox for this account, you need to assign a license.'
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = 'An existing MS-Entra account was found, but no mailbox is associated with it. Update Exchange Online in delete action skipped'
                    IsError = $false
                })
        }
    }

    if ($null -ne $correlatedAccountEntra) {
        if ($actionContext.Configuration.deleteAccount) {
            $actionList += 'DeleteAccountEntra'
        }
        else {
            $actionList += 'UpdateAccountEntra'
            if ($null -ne $correlatedAccountExo -and $actionContext.Configuration.ExchangeOnlineIntegration) {
                $actionList += 'UpdateAccountExo'
            }
        }
    }
    else {
        $actionList += 'NotFound'
    }

    # Process
    foreach ($action in $actionList) {
        switch ($action) {
            'DeleteAccountEntra' {

                Write-Information "Deleting MS-Entra-Exo account with accountReference: [$($actionContext.References.Account)]"

                $actionMessage = "deleting account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

                $splatDeleteEntraAccount = @{
                    Uri         = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)"
                    Method      = "DELETE"
                    ContentType = 'application/json; charset=utf-8'
                    Headers     = @{'Authorization' = "Bearer $($entraToken)" }
                }

                if (-not($actionContext.DryRun -eq $true)) {
                    $null = Invoke-RestMethod @splatDeleteEntraAccount -Verbose:$false
                }

                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = 'Delete account was successful'
                        IsError = $false
                    })
                break
            }

            'UpdateAccountEntra' {

                $actionMessage = "updating  MS-Entra account in delete action with AccountReference [$($actionContext.References.Account)]"
                $bodyUpdateAccountEntra = @{}
                switch ($actionContext.Origin) {
                    'enforcement' {
                        $auditMessage = 'Update MS-Entra account in delete action was successful'
                        foreach ($entraAccountProperty in ($actionContext.Data | Select-Object * -ExcludeProperty ExchangeOnline, passwordProfile, managerId).PsObject.Properties ) {
                            $bodyUpdateAccountEntra["$($entraAccountProperty.Name)"] = $entraAccountProperty.Value
                        }
                        break
                    }
                    'reconciliation' {
                        $auditMessage = "Disable MS-Entra account [$($actionContext.References.Account)] in delete action was successful (reconciliation)"
                        $bodyUpdateAccountEntra = @{
                            accountEnabled = $false
                        }
                        break
                    }
                    default {
                        throw "Unknown action origin: [$($actionContext.Origin)] Valid values are 'reconciliation' or 'enforcement'."
                    }
                }

                $splatUpdateEntraAccount = @{
                    Uri         = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)"
                    Method      = "PATCH"
                    Body        = $bodyUpdateAccountEntra | ConvertTo-Json -Depth 10
                    ContentType = 'application/json;charset=utf-8'
                    Headers     = @{'Authorization' = "Bearer $($entraToken)" }
                }
                if (-not($actionContext.DryRun -eq $true)) {
                    $null = Invoke-RestMethod @splatUpdateEntraAccount -Verbose:$false
                }
                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = $auditMessage
                        IsError = $false
                    })
                break
            }

            'UpdateAccountEXO' {

                $actionMessage = "updating Exo mailbox with ExternalDirectoryObjectId: $($actionContext.References.Account)"
                $splatUpdateExoAccount = @{
                    Identity = $actionContext.References.Account
                }
                switch ($actionContext.Origin) {
                    'enforcement' {
                        $auditMessage = 'Update of MS-Exo mailbox in delete action was successful'
                        foreach ($exoAccountProperty in $actionContext.Data.exchangeOnline.PsObject.Properties) {
                            if ($exoAccountProperty.Name -eq 'HiddenFromAddressListsEnabled') {
                                $splatUpdateExoAccount['HiddenFromAddressListsEnabled'] = [bool]::Parse($exoAccountProperty.Value)
                                continue
                            }
                            $splatUpdateExoAccount[$exoAccountProperty.Name] = $exoAccountProperty.Value
                        }
                        break
                    }
                    'reconciliation' {
                        $auditMessage = "Update MS-Exo mailbox [$($actionContext.References.Account)] HiddenFromAddressListsEnabled to True was successful (reconciliation)"
                        $splatUpdateExoAccount['HiddenFromAddressListsEnabled'] = $true
                        break
                    }
                    default {
                        throw "Unknown action origin: [$($actionContext.Origin)] Valid values are 'reconciliation' or 'enforcement'."
                    }
                }

                if (-not($actionContext.DryRun -eq $true)) {
                    $null = Set-Mailbox @splatUpdateExoAccount -Verbose:$false -ErrorAction Stop
                }
                else {
                    $null = Set-Mailbox @splatUpdateExoAccount -Verbose:$false -ErrorAction Stop -WhatIf
                }
                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = $auditMessage
                        IsError = $false
                    })
                
                break
            }

            'NotFound' {
                Write-Information "MS-Entra-Exo account: [$($actionContext.References.Account)] could not be found, possibly indicating that it could have been deleted"
                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "MS-Entra-Exo account: [$($actionContext.References.Account)] could not be found, possibly indicating that it could have been deleted"
                        IsError = $false
                    })
                break
            }
        }
    }
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage).  Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
finally {
    # Returning data is only needed when origin is enforcement.
    if ($actionContext.Origin -eq 'enforcement') {
        # Filling the None output context with values from the Entra and Exo accounts.
        foreach ($property in $outputContext.Data.PSObject.Properties) {
            if ($property.name -notin $actionContext.Data.PSObject.Properties.Name ) {
                $outputContext.Data.$($property.name) = $correlatedAccountEntra.$($property.name)
            }
        }

        if ($actionContext.Configuration.ExchangeOnlineIntegration -and ($actionContext.Data.PSObject.Properties.Name -contains 'exchangeOnline' -or $actionContext.Origin -eq 'reconciliation')) {
            foreach ($property in $outputContext.Data.ExchangeOnline.PSObject.Properties) {
                if ($property.name -notin $actionContext.Data.ExchangeOnline.PSObject.Properties.Name ) {
                    $outputContext.Data.ExchangeOnline.$($property.name) = $correlatedAccountExo.$($property.name)
                }
            }
        }
    }
}
