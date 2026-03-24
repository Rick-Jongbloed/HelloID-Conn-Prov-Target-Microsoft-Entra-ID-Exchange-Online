#################################################
# HelloID-Conn-Prov-Target-MS-Entra-Exo-Create
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Script Configuration, only Required for ExchangeOnlineIntegration.
# Note that the property name should be the same! The givenName in Entra corresponds to FirstName in EXO.
$entraMailboxFallbackLookupProperty = 'givenName'
$exchangeMailboxFallbackLookupProperty = 'FirstName'

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

function Set-MailboxWithRetry {
    param(
        [Parameter(Mandatory)]
        [hashtable]
        $UpdateExoProperties
    )
    try {
        $retryCount = 0
        do {
            try {
                $null = Set-Mailbox @UpdateExoProperties -Verbose:$false -ErrorAction Stop -WarningAction SilentlyContinue
                $errorOccurred = $false
            }
            catch {
                if ($_.Exception.Message -like "*performed because object '*' couldn't be found on*") {
                    $errorOccurred = $true
                    Start-Sleep 2
                }
                else {
                    throw $_
                }
            }
            $retryCount++
        } while ( $errorOccurred -and $retryCount -lt 5)
        if ($errorOccurred -and $retryCount -ge 5) {
            throw "Set-Mailbox failed after $($retryCount) retries"
        }
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion

try {
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'

    # Setup Connection with Entra/Exo
    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate
    if ($actionContext.Configuration.ExchangeOnlineIntegration) {
        $actionMessage = 'connecting to Exchange Online'
        $createExoSessionSplatParams = @{
            Organization = $actionContext.Configuration.Organization
            AppID        = $actionContext.Configuration.AppId
            Certificate  = $certificate
        }
        $null = Connect-ManagedExchangeOnline @createExoSessionSplatParams -ErrorAction Stop
    }

    if (-not $actionContext.CorrelationConfiguration.Enabled) {
        throw 'The correlation configuration is not enabled, but this connector requires the correlation configuration to be set to enabled.'
    }

    # Validate correlation configuration
    $correlationField = $actionContext.CorrelationConfiguration.AccountField
    $correlationValue = $actionContext.CorrelationConfiguration.PersonFieldValue
    if ([string]::IsNullOrEmpty($($correlationField))) {
        throw 'Correlation is enabled but not configured correctly'
    }
    if ([string]::IsNullOrEmpty($($correlationValue))) {
        throw 'Correlation is enabled but [accountFieldValue] is empty. Please make sure it is correctly mapped'
    }

    # Get Entra account
    $actionMessage = "querying MS-Entra account where [$($correlationField)] [$($correlationValue)]"
    $selectPropertiesToGetUser = 'id,' + (($outputContext.Data | Select-Object * -ExcludeProperty ExchangeOnline, managerId ).PSObject.Properties.Name -join ',')
    $splatGetEntraUser = @{
        Uri     = "https://graph.microsoft.com/v1.0/users?`$filter=$($correlationField) eq '$($correlationValue)'&`$select=$selectPropertiesToGetUser"
        Method  = 'GET'
        Headers = @{'Authorization' = "Bearer $($entraToken)" }
    }
    $correlatedAccountEntra = (Invoke-RestMethod @splatGetEntraUser ).value
    if ($correlatedAccountEntra.Count -gt 1) {
        throw "Multiple Extra accounts found based on [$($correlationField) eq $($correlationValue)]"
    }

    if ($correlatedAccountEntra.Count -eq 0) {
        # Fallback
        $actionMessage = "querying MS-Entra account where [$entraMailboxFallbackLookupProperty] = [$($correlationValue)]"
        $selectPropertiesToGetUser = ($outputContext.Data | Select-Object * -ExcludeProperty ExchangeOnline, managerId ).PSObject.Properties.Name -join ','
        $splatGetEntraUser = @{
            Uri     = "https://graph.microsoft.com/v1.0/users?`$filter=$entraMailboxFallbackLookupProperty eq '$($correlationValue)'&`$select=$selectPropertiesToGetUser"
            Method  = 'GET'
            Headers = @{'Authorization' = "Bearer $($entraToken)" }
        }
        $correlatedAccountEntraFallBack = (Invoke-RestMethod @splatGetEntraUser).value
        if ($correlatedAccountEntraFallBack.Count -eq 1) {
            $outputContext.AuditLogs.Add(@{
                    Message = "Retrying account creation. The Entra account was found using fallback property [$entraMailboxFallbackLookupProperty] = [$($correlationValue)] and resuming follow-up actions for the previously failed creation."
                    IsError = $false
                })
        }
        if ($correlatedAccountEntraFallBack.Count -gt 1) {
            throw "Multiple Extra accounts found based on [$entraMailboxFallbackLookupProperty eq $($correlationValue)]"
        }
    }

    # Get Exo account
    if ($actionContext.Configuration.ExchangeOnlineIntegration) {
        if ($correlatedAccountEntra.Count -eq 1) {
            $actionMessage = "querying Exchange Online Mailbox where [ExternalDirectoryObjectId - $($correlatedAccountEntra.Id)]"
            $exoAccountPropertiesToQuery = $outputContext.Data.exchangeOnline.PsObject.Properties.Name
            $getExoAccountSplatParams = @{
                Filter     = "ExternalDirectoryObjectID -eq '$($correlatedAccountEntra.Id)'"
                Properties = $exoAccountPropertiesToQuery
            }
            $correlatedAccountExo = Get-EXOMailbox @getExoAccountSplatParams -Verbose:$false -ErrorAction Stop
        }
        if ($correlatedAccountEntra.Count -eq 1 -and $correlatedAccountExo.Count -lt 1) {
            throw "An existing MS-Entra account was found, but no mailbox is associated with it. To add a mailbox for this account, you need to assign a license."
        }
    }

    # Lookup manager Account
    if ($actionContext.Configuration.setManagerOnCreate -eq $true) {
        if (-not [String]::IsNullOrEmpty(($actionContext.References.ManagerAccount))) {
            $actionMessage = "querying MS-Entra-Exo Manager Account $($actionContext.References.ManagerAccount)]"
            try {
                $splatGetEntraManager = @{
                    Uri     = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.ManagerAccount)"
                    Method  = 'GET'
                    Headers = @{'Authorization' = "Bearer $($entraToken)" }
                }
                $null = Invoke-RestMethod @splatGetEntraManager
            }
            catch {
                if ($_.Exception.StatusCode -eq 404) {
                    throw "MS-Entra-Exo Manager account with accountReference: [$($actionContext.References.ManagerAccount)] could not be found, possibly indicating that it could be deleted"
                }
                throw $_
            }
        }
        else {
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = 'Set Manager on create is enabled, but no ManagerAccount is found in the References'
                    IsError = $false
                })
        }
    }

    $actionList = [System.Collections.Generic.list[string]]::new()
    $actionMessage = 'calculating actions'
    if ($actionContext.Configuration.ExchangeOnlineIntegration) {
        # If Entra and Exo account found = [CorrelateAccount]
        if ($correlatedAccountExo.Count -eq 1) {
            $actionList.Add('CorrelateAccount')
            $correlatedAccountEntra = $correlatedAccountEntra | Select-Object -First 1
            $outputContext.AccountReference = $correlatedAccountExo.ExternalDirectoryObjectId

        }
        elseif ($correlatedAccountExo.Count -lt 1 -or $correlatedAccountEntraFallBack.Count -eq 1) {
            # If Entra and Exo account not found = [CreateAccountExo],[UpdateAccountEntraCorrelationValueAfterCreateMailbox],[UpdateAccountEntra],[UpdateAccountExo]
            # If UpdateAccountEntraCorrelationValueAfterCreateMailbox Fails the retry will skip creating the mailbox, and continue with create process
            if (-not ($correlatedAccountEntraFallBack.Count -eq 1)) {
                $actionList.Add('CreateAccountExo')
            }
            else {
                $createdAccountExo = $correlatedAccountEntraFallBack | Select-Object -First 1
                $outputContext.AccountReference = $createdAccountExo.id
            }
            $actionList.Add('UpdateAccountEntraCorrelationValueAfterCreateMailbox')
            $actionList.Add('UpdateAccountEntra')
            if ($null -ne $actionContext.Data.exchangeOnline) {
                # When only the HiddenFromAddressListsEnabled property is present and its value is false, do not add the action to avoid an unnecessary update.
                # This extra check is required because it's common to only update the HiddenFromAddressListsEnabled property, and false is the default value.
                if ( -not (
                        (($actionContext.Data.exchangeOnline.PsObject.Properties | Measure-Object).Count -eq 1) -and
                        ('HiddenFromAddressListsEnabled' -in $actionContext.Data.exchangeOnline.PsObject.Properties.Name ) -and
                        ($actionContext.Data.exchangeOnline.HiddenFromAddressListsEnabled -eq $false)
                    )) {
                    # Only needed, when ActionContext.Data.ExchangeOnline contains properties
                    $actionList.Add('UpdateAccountExo')
                }
            }
        }

    }
    elseif (-not ($actionContext.Configuration.ExchangeOnlineIntegration)) {
        # If Entra account found = CorrelateAccount
        if ($correlatedAccountEntra.Count -eq 1) {
            $actionList.Add('CorrelateAccount')
            $correlatedAccountEntra = $correlatedAccountEntra | Select-Object -First 1
            $outputContext.AccountReference = $correlatedAccountEntra.Id

        }
        elseif ($correlatedAccountEntra.Count -lt 1) {
            # If Entra account not found = [CreateAccountEntra]
            $actionList.Add('CreateAccountEntra')
        }
    }
    else {
        throw "Unknown action context ExchangeOnlineIntegration [$($actionContext.Configuration.ExchangeOnlineIntegration)]. Please check the configuration"
    }

    # Determine Manager actions
    if ($actionContext.Configuration.setManagerOnCreate -eq $true) {
        if (-not[String]::IsNullOrEmpty(($actionContext.References.ManagerAccount))) {
            $actionList.Add('SetManager')
        }
    }
    # Process
    Write-Information "Actions to be executed: $($actionList -join ', ')"
    foreach ($action in $actionList) {
        switch ($action) {
            'CreateAccountEntra' {
                $actionMessage = "creating MS-Entra account with displayName [$($actionContext.Data.DisplayName)] userPrincipalName [$($actionContext.Data.userPrincipalName)]"
                # ?$Select=xxx returns all properties, except the passwordProfile, this is returned with Null.
                $splatCreateParams = @{
                    Uri         = 'https://graph.microsoft.com/v1.0/users?$select=*'
                    Method      = 'POST'
                    Body        = ($actionContext.Data | Select-Object * -ExcludeProperty exchangeOnline | ConvertTo-Json -Depth 10)
                    Headers     = @{'Authorization' = "Bearer $($entraToken)" }
                    ContentType = 'application/json;charset=utf-8'
                }
                if (-not($actionContext.DryRun -eq $true)) {
                    $createdAccountEntra = Invoke-RestMethod @splatCreateParams
                    $outputContext.Data = $createdAccountEntra
                    $outputContext.AccountReference = $createdAccountEntra.Id
                    if ($actionContext.Data.PSObject.Properties.Name -contains 'passwordProfile' -and $actionContext.Data.passwordProfile.PSObject.Properties.Name -contains 'password' ) {
                        $outputContext.Data | Add-Member @{passwordProfile = @{password = $actionContext.Data.passwordProfile.password } } -Force
                    }
                }
                else {
                    Write-Information '[DryRun] Create and correlate MS-Entra-Exo account, will be executed during enforcement'
                }
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Create Entra account with userPrincipalName [$($actionContext.Data.userPrincipalName)] was successful. AccountReference is: [$($outputContext.AccountReference)]"
                        IsError = $false
                    })
                break
            }

            'CreateAccountExo' {
                $actionMessage = "creating Exchange Online Mailbox with displayName [$($actionContext.Data.DisplayName)] and userPrincipalName [$($actionContext.Data.userPrincipalName)]"
                $createExoAccountSplatParams = @{
                    Alias                     = $actionContext.Data.mailNickName
                    Name                      = $actionContext.Data.displayName
                    PrimarySmtpAddress        = ($actionContext.Data.exchangeOnline.emailAddresses | Where-Object { $_ -cmatch '^SMTP:' } | Select-Object -First 1) -replace 'SMTP:', ''
                    MicrosoftOnlineServicesID = $actionContext.Data.userPrincipalName
                    ResetPasswordOnNextLogon  = [bool]($actionContext.Data.passwordProfile.forceChangePasswordNextSignIn)
                    Password                  = ConvertTo-SecureString -String $actionContext.Data.passwordProfile.password -AsPlainText -Force
                }
                $createExoAccountSplatParams["$exchangeMailboxFallbackLookupProperty"] = "$correlationValue"

                if (-not($actionContext.DryRun -eq $true)) {
                    # Create mailbox. This subsequently creates a entra account
                    $createdAccountExo = New-Mailbox @createExoAccountSplatParams -ErrorAction Stop -Verbose:$false -WarningAction SilentlyContinue
                    $outputContext.AccountReference = $createdAccountExo.ExternalDirectoryObjectId
                    $outputContext.Data | Add-Member @{id = $createdAccountExo.ExternalDirectoryObjectId } -Force
                }
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Create Exo account with userPrincipalName [$($actionContext.Data.userPrincipalName)] was successful. AccountReference is: [$($outputContext.AccountReference)]"
                        IsError = $false
                    })
                break
            }

            'UpdateAccountEntraCorrelationValueAfterCreateMailbox' {
                $actionMessage = "updating created MS-Entra-Exo account with AccountReference: [$($outputContext.AccountReference)] with correlation field [$correlationField] and value [$correlationValue]"
                if ( $null -eq $outputContext.AccountReference) {
                    throw 'AccountReference is null'
                }
                $body = @{
                    $correlationField = "$($correlationValue)"
                }
                $body["$entraMailboxFallbackLookupProperty"] = $actionContext.Data.$entraMailboxFallbackLookupProperty
                if (-not($actionContext.DryRun -eq $true)) {
                    $splatUpdateEntraAccount = @{
                        Uri         = "https://graph.microsoft.com/v1.0/users/$($outputContext.AccountReference)"
                        Method      = 'PATCH'
                        Headers     = @{'Authorization' = "Bearer $($entraToken)" }
                        Body        = ($body | ConvertTo-Json -Depth 10)
                        ContentType = 'application/json;charset=utf-8'
                    }
                    $null = Invoke-RestMethod @splatUpdateEntraAccount
                }
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Update correlation value Entra account was successful. AccountReference is: [$($outputContext.AccountReference)]"
                        IsError = $false
                    })
                break
            }
            'UpdateAccountExo' {
                $actionMessage = "updating Exchange Online Mailbox with and userPrincipalName [$($actionContext.Data.userPrincipalName)] with AccountReference: [$($outputContext.AccountReference)]"
                $splatUpdateExoAccount = @{
                    Identity = $createdAccountExo.UserPrincipalName
                }
                foreach ($exoAccountProperty in $actionContext.Data.exchangeOnline.PsObject.Properties) {
                    if ($exoAccountProperty.Name -eq 'HiddenFromAddressListsEnabled') {
                        if ($null -ne $exoAccountProperty.Value) {
                            $splatUpdateExoAccount['HiddenFromAddressListsEnabled'] = [bool]::Parse($exoAccountProperty.Value)
                            continue
                        }
                    }
                    $splatUpdateExoAccount[$exoAccountProperty.Name] = $exoAccountProperty.Value
                }
                if (-not ($actionContext.DryRun -eq $true)) {
                    Set-MailboxWithRetry -UpdateExoProperties $splatUpdateExoAccount
                }
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Update Exo account was successful. AccountReference is: [$($outputContext.AccountReference)]"
                        IsError = $false
                    })
                break
            }

            'UpdateAccountEntra' {
                $actionMessage = "updating created MS-Entra account with AccountReference [$($outputContext.AccountReference)]"
                $bodyUpdateAccountEntra = @{}
                foreach ($entraAccountProperty in ($actionContext.Data | Select-Object * -ExcludeProperty ExchangeOnline, passwordProfile).PsObject.Properties ) {
                    $bodyUpdateAccountEntra["$($entraAccountProperty.Name)"] = $entraAccountProperty.Value
                }
                $bodyUpdateAccountEntra['id'] = $outputContext.AccountReference
                $splatUpdateEntraAccount = @{
                    Uri         = "https://graph.microsoft.com/v1.0/users/$($outputContext.AccountReference)"
                    Method      = 'PATCH'
                    Body        = ($bodyUpdateAccountEntra | ConvertTo-Json -Depth 10)
                    ContentType = 'application/json;charset=utf-8'
                    Headers     = @{'Authorization' = "Bearer $($entraToken)" }
                }
                if (-not($actionContext.DryRun -eq $true)) {
                    $null = Invoke-RestMethod @splatUpdateEntraAccount
                }
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Update Entra account was successful. AccountReference is: [$($outputContext.AccountReference)]"
                        IsError = $false
                    })
                break
            }

            'CorrelateAccount' {
                $actionMessage = 'correlating MS-Entra-Exo account'
                $outputContext.Data = $correlatedAccountEntra
                if ($actionContext.Configuration.ExchangeOnlineIntegration) {
                    $outputContext.Data | Add-Member @{
                        exchangeOnline = $correlatedAccountExo
                    } -Force
                }
                $outputContext.AccountCorrelated = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = 'CorrelateAccount'
                        Message = "Correlated account: [$($outputContext.AccountReference)] on field: [$($correlationField)] with value: [$($correlationValue)]"
                        IsError = $false
                    })
                break
            }

            'SetManager' {
                $actionMessage = "setting manager for created MS-Entra account with AccountReference [$($outputContext.AccountReference)]"
                $bodySetManager = @{
                    '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.ManagerAccount)"
                }
                $setEntraManagerSplatParams = @{
                    Uri         = "https://graph.microsoft.com/v1.0/users/$($outputContext.AccountReference)/manager/`$ref"
                    Method      = 'PUT'
                    Body        = $bodySetManager | ConvertTo-Json -Depth 10
                    Headers     = @{'Authorization' = "Bearer $($entraToken)" }
                    ContentType = 'application/json;charset=utf-8'
                }
                if (-not($actionContext.DryRun -eq $true)) {
                    $null = Invoke-RestMethod @setEntraManagerSplatParams
                }
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Set manager for Entra ID account with AccountReference: [$($outputContext.AccountReference)] Manager: [$($actionContext.References.ManagerAccount)]"
                        IsError = $false
                    })
                $outputContext.Data | Add-Member @{
                    ManagerId = $($actionContext.References.ManagerAccount)
                } -Force
                break
            }
        }
    }
    if ( -not ($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
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
    # Filling the None output context with values from the Entra and Exo accounts.
    if (-not [string]::IsNullOrEmpty($correlatedAccountEntra)) {
        foreach ($property in $outputContext.Data.PSObject.Properties) {
            if ($property.name -notin $actionContext.Data.PSObject.Properties.Name ) {
                $outputContext.Data.$($property.name) = $correlatedAccountEntra.$($property.name)
            }
        }

        if ($actionContext.Configuration.ExchangeOnlineIntegration) {
            foreach ($property in $outputContext.Data.ExchangeOnline.PSObject.Properties) {
                if ($property.name -notin $actionContext.Data.ExchangeOnline.PSObject.Properties.Name ) {
                    $outputContext.Data.ExchangeOnline.$($property.name) = $correlatedAccountExo.$($property.name)
                }
            }
        }
    }
}