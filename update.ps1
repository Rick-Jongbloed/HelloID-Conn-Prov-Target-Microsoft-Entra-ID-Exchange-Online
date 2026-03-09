#################################################
# HelloID-Conn-Prov-Target-MS-Entra-Exo-Update
# PowerShell V2
#################################################

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

function ConvertTo-FlatObject {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]
        $Object,

        [string]
        $Prefix = ''
    )
    $result = [ordered]@{}
    foreach ($property in $Object.PSObject.Properties) {
        $name = if ($Prefix) {
            "$Prefix.$($property.Name)"
        }
        else {
            $property.Name
        }
        if ($null -ne $property.Value -and $property.Value.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
            # if ($property.Value -is [PSCustomObject]) {
            $property.Value = $property.Value | Sort-Object
            $flattenedSubObject = ConvertTo-FlatObject -Object $property.Value -Prefix $name
            foreach ($subProperty in $flattenedSubObject.PSObject.Properties) {
                # Set property name to lower case to ensure this doesn't trigger an update
                $result[$subProperty.Name] = [string]$subProperty.Value
            }
        }
        else {
            $property.Value = $property.Value | Sort-Object

            $result[$name] = [string]$property.Value
        }
    }
    Write-Output ([PSCustomObject]$result)
}

function ConvertTo-EntraUpdateBody {
    param (
        [Parameter()]
        $PropertiesChanged,

        [Parameter()]
        $Data
    )
    try {
        if ($null -eq $PropertiesChanged ) {
            Write-Information 'PropertiesChanged is null or empty'
            return $null
        }
        $body = @{}
        # Loop through the properties that have changed
        foreach ($property in $PropertiesChanged) {
            if ($($property.Name) -like '*.*') {
                $parentPropertyName = ($property.Name -Split '\.')[0]
                $subPropertyName = ($property.Name -Split '\.')[1]
                if (-not $body.ContainsKey($parentPropertyName)) {
                    $body[$parentPropertyName] = @{}
                }
                $body[$parentPropertyName][$subPropertyName] = $Data.$parentPropertyName.$subPropertyName
            }
            else {
                $body["$($property.Name)"] = $Data.$($property.Name)
            }
        }
        Write-Output $body
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Convert-StringBooleanToBoolean {
    param (
        [Parameter(Mandatory)]
        $InputObject
    )
    foreach ($property in $InputObject.PSObject.Properties) {
        if ($property.TypeNameOfValue -eq 'System.Management.Automation.PSCustomObject') {
            Convert-StringBooleanToBoolean -InputObject $property.Value
        }
        else {
            if ($property.Value -eq 'True' -or $property.Value -eq 'False') {
                $InputObject."$($property.Name)" = [bool]::Parse($property.Value)
            }
        }
    }
}
#endregion

try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    # Setup Connection with Entra/Exo
    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate
    if ($actionContext.Configuration.ExchangeOnlineIntegration -and $actionContext.Data.PSObject.Properties.Name -contains 'exchangeOnline') {
        $actionMessage = 'connecting to Exchange Online'
        $createExoSessionSplatParams = @{
            Organization = $actionContext.Configuration.Organization
            AppID        = $actionContext.Configuration.AppId
            Certificate  = $certificate
        }
        $null = Connect-ManagedExchangeOnline @createExoSessionSplatParams -ErrorAction Stop
    }

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
            throw "Entra Account [$($actionContext.References.Account)] could not be found, possibly indicating that it could be deleted"
        }
        else {
            throw $_
        }
    }

    # Get Exo account
    if ($actionContext.Configuration.ExchangeOnlineIntegration -and $actionContext.Data.PSObject.Properties.Name -contains 'exchangeOnline') {
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
            Write-Warning 'An existing MS-Entra account was found, but no mailbox is associated with it. To add a mailbox for this account, you need to assign a license.'
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = 'An existing MS-Entra account was found, but no mailbox is associated with it. Updating Exchange Online skipped'
                    IsError = $false
                })
        }
    }

    if ($actionContext.Configuration.updateManagerOnUpdate) {
        $splatGetEntraAccountManager = @{
            Uri     = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)/manager"
            Method  = 'GET'
            Headers = @{'Authorization' = "Bearer $($entraToken)" }
        }
        try {
            $previousManager = Invoke-RestMethod @splatGetEntraAccountManager
        }
        catch {
            if ($_.ErrorDetails.Message -like "*Resource *manager* does not exist or one of its queried reference-property objects are not present.*") {
                $previousManager = $null
            }
            else {
                throw $_
            }
        }
    }

    $actionList = [System.Collections.Generic.list[object]]::new()
    # Compare Entra Account
    if ($null -ne $correlatedAccountEntra) {
        $actionMessage = 'Compare Entra Account'
        $actionContextDataFiltered = $actionContext.Data | Select-Object * -ExcludeProperty passwordProfile*, exchangeOnline*
        $splatComparePropertiesEntra = @{
            ReferenceObject  = @((ConvertTo-FlatObject -Object $correlatedAccountEntra).PSObject.Properties)
            DifferenceObject = @((ConvertTo-FlatObject -Object $actionContextDataFiltered).PSObject.Properties)
        }
        $propertiesChangedEntra = Compare-Object @splatComparePropertiesEntra -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        if ($propertiesChangedEntra) {
            $actionList.Add('UpdateAccountEntra')
        }
    }

    # Compare Exo Account
    if ($actionContext.Configuration.ExchangeOnlineIntegration) {
        if (-not [string]::IsNullOrEmpty($correlatedAccountExo)) {
            # Add existing emailAddresses as aliases
            $actionMessage = 'Compare EXO Account'
            if ('emailAddresses' -in $actionContext.Data.ExchangeOnline.PSObject.Properties.Name) {
                $actionMessage = 'Compare EXO Account emailAddresses'
                # Merge and ensure uniqueness of existing and new emailAddresses
                $mergedEmailAddresses = @($correlatedAccountExo.emailAddresses) + $actionContext.Data.exchangeOnline.emailAddresses | Sort-Object -Unique
                # Get the primary SMTP address from the mapped properties
                $primarySMTP = $actionContext.Data.exchangeOnline.EmailAddresses | Where-Object { $_ -cmatch '^SMTP:' }
                if ($primarySMTP.Count -gt 1) {
                    throw 'Multiple primary SMTP addresses found in the mapped properties. Please ensure only one is set.'
                }
                # Ensure the primary SMTP is set correctly in the merged list
                $mergedEmailAddresses = $mergedEmailAddresses | ForEach-Object {
                    if ($_ -cmatch '^SMTP:') {
                        $_.ToLower() -replace '^smtp:', 'smtp:'
                    }
                    else {
                        $_
                    }
                }
                # Add the primary SMTP address at the beginning of the list
                $mergedEmailAddresses = @($primarySMTP) + @(($mergedEmailAddresses | Where-Object { $_ -ne $primarySMTP }))
                # Overwrite mapped emailAddresses with mergedEmailAddresses
                $actionContext.Data.exchangeOnline.emailAddresses = $mergedEmailAddresses
                $outputContext.Data.exchangeOnline.emailAddresses = @($mergedEmailAddresses | Sort-Object)
            }
            if ($correlatedAccountExo.PsObject.Properties.name -contains 'HiddenFromAddressListsEnabled' ) {
                $correlatedAccountExo.HiddenFromAddressListsEnabled = [string]$correlatedAccountExo.HiddenFromAddressListsEnabled
            }

            if ($null -ne $actionContext.Data.exchangeOnline) {
                $splatComparePropertiesExo = @{
                    ReferenceObject  = @((ConvertTo-FlatObject -Object $correlatedAccountExo).PSObject.Properties)
                    DifferenceObject = @((ConvertTo-FlatObject -Object $actionContext.Data.exchangeOnline | Select-Object * ).PSObject.Properties)
                }
                $propertiesChangedExo = Compare-Object @splatComparePropertiesExo -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
                if ($propertiesChangedExo) {
                    $actionList.Add('UpdateAccountExo')
                }

                # Separate compare for EmailAddresses
                if ($correlatedAccountExo.EmailAddresses.count -gt 0 -and $actionContext.Data.exchangeOnline.EmailAddresses.Count -gt 0) {
                    $correlatedAccountEmailAddresses = $correlatedAccountExo.EmailAddresses
                    $actionContextDataEmailAddresses = $actionContext.Data.exchangeOnline.EmailAddresses

                    $onlyInCorrelatedAccount = $correlatedAccountEmailAddresses | Where-Object { -not ($actionContextDataEmailAddresses -ccontains $_) }
                    $onlyInActionContextData = $actionContextDataEmailAddresses | Where-Object { -not ($correlatedAccountEmailAddresses -ccontains $_) }

                    $emailAddressesChangedExo = @()
                    $emailAddressesChangedExo += $onlyInCorrelatedAccount | ForEach-Object { [PSCustomObject]@{ InputObject = $_; SideIndicator = '<=' } }
                    $emailAddressesChangedExo += $onlyInActionContextData | ForEach-Object { [PSCustomObject]@{ InputObject = $_; SideIndicator = '=>' } }

                    if ($emailAddressesChangedExo) {
                        $actionList.Add('UpdateAccountExo')
                    }
                }
            }
        }
    }


    # Compare Manager Account
    if ($actionContext.Configuration.updateManagerOnUpdate) {
        $actionMessage = 'Compare EXO Manager Account'
        if ($previousManager.id -ne $actionContext.References.ManagerAccount) {
            if ($null -eq $actionContext.References.ManagerAccount) {
                $actionList.Add('ClearManager')
            }
            else {
                $actionList.Add('UpdateManager')
            }
        }
        else {
            $outputContext.PreviousData | Add-Member @{
                managerId = $null
            } -Force
        }
    }
    if ('UpdateAccountEntra' -notin $actionList -and ('UpdateAccountEXO' -notin $actionList)) {
        $actionList.Add('NoChanges')
        if (-not $actionContext.Configuration.exchangeOnlineIntegration -and $outputContext.Data.PSObject.Properties.name -contains 'exchangeOnline') {
            $outputContext.Data.PSObject.Properties.Remove('exchangeOnline')
        }
    }

    # Process
    Write-Information "Actions to be executed: $($actionList -join ', ')"
    foreach ($action in $actionList) {
        switch ($action) {
            'UpdateAccountEntra' {
                Write-Information "Entra Account property(s) required to update: $($propertiesChangedEntra.Name -join ', ')"
                $actionMessage = "Update Entra account with accountReference [$($actionContext.References.Account)]"
                $updateBodyEntra = ConvertTo-EntraUpdateBody -PropertiesChanged $propertiesChangedEntra -Data $actionContext.Data

                if (-not($actionContext.DryRun -eq $true)) {
                    Write-Information "Updating MS-Entra-Exo account with accountReference: [$($actionContext.References.Account)]"
                    $splatUpdateEntraAccount = @{
                        Uri         = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)"
                        Method      = 'PATCH'
                        Body        = ($updateBodyEntra | ConvertTo-Json -Depth 10)
                        ContentType = 'application/json; charset=utf-8'
                        Headers     = @{'Authorization' = "Bearer $($entraToken)" }
                    }
                    $null = Invoke-RestMethod @splatUpdateEntraAccount
                }
                else {
                    Write-Information "[DryRun] Update MS-Entra-Exo account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
                }
                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Update Entra account was successful, Account property(s) updated: [$($propertiesChangedEntra.name -join ',')]"
                        IsError = $false
                    })
                break
            }

            'UpdateAccountEXO' {
                Write-Information "EXO Account property(s) required to update: $($propertiesChangedExo.Name -join ', ')"
                $actionMessage = "Update EXO account with accountReference [$($actionContext.References.Account)]"
                $splatUpdateExoAccount = @{
                    Identity = $actionContext.References.Account
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
                if (-not($actionContext.DryRun -eq $true)) {
                    Write-Information "Updating MS-Entra-Exo account with accountReference: [$($actionContext.References.Account)]"
                    $null = Set-Mailbox @splatUpdateExoAccount -Verbose:$false -ErrorAction Stop
                }
                else {
                    Write-Information "[DryRun] Update MS-Entra-Exo account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
                }
                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Update EXO account was successful, Account property(s) updated: [$($propertiesChangedExo.name -join ',')]"
                        IsError = $false
                    })

            }

            'UpdateManager' {
                Write-Information "Updating MS-Entra-Exo account with manager: [$($actionContext.References.ManagerAccount)]"
                $actionMessage = "updating manager for created MS-Entra account with AccountReference [$($actionContext.References.Account)]"
                $bodySetManager = @{
                    '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.ManagerAccount)"
                }
                $splatSetEntraManager = @{
                    Uri         = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)/manager/`$ref"
                    Method      = 'PUT'
                    Body        = $bodySetManager | ConvertTo-Json -Depth 10
                    Headers     = @{'Authorization' = "Bearer $($entraToken)" }
                    ContentType = 'application/json;charset=utf-8'
                }
                if (-not($actionContext.DryRun -eq $true)) {
                    $null = Invoke-RestMethod @splatSetEntraManager
                }
                else {
                    Write-Information "[DryRun] Update MS-Entra-Exo account with manager: [$($actionContext.References.ManagerAccount)], will be executed during enforcement"
                }
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Set manager for Entra ID account with AccountReference: [$($actionContext.References.Account)] Manager: [$($actionContext.References.ManagerAccount)]"
                        IsError = $false
                    })
                $outputContext.Data | Add-Member @{
                    ManagerId = $($actionContext.References.ManagerAccount)
                } -Force
                break
            }

            'ClearManager' {
                Write-Information 'Clearing manager for MS-Entra-Exo account'
                $actionMessage = "clear manager for created MS-Entra account with AccountReference [$($actionContext.References.Account)]"
                $splatClearEntraManager = @{
                    Uri     = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)/manager/`$ref"
                    Method  = 'DELETE'
                    Headers = @{'Authorization' = "Bearer $($entraToken)" }
                }
                if (-not($actionContext.DryRun -eq $true)) {
                    $null = Invoke-RestMethod @splatClearEntraManager
                }
                else {
                    Write-Information '[DryRun] Clear manager for MS-Entra-Exo account, will be executed during enforcement'
                }
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Cleared manager for Entra ID account with AccountReference: [$($actionContext.References.Account)]"
                        IsError = $false
                    })
                $outputContext.Data | Add-Member @{
                    ManagerId = $null
                } -Force
                break
            }

            'NoChanges' {
                Write-Information "No changes to MS-Entra-Exo account with accountReference: [$($actionContext.References.Account)]"
                $outputContext.Success = $true
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = 'No changes will be made to the account during enforcement'
                        IsError = $false
                    })
                break
            }
        }
    }
}
catch {
    $outputContext.Success = $false
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
    # Convert string booleans to actual booleans
    $null = Convert-StringBooleanToBoolean -InputObject $outputContext.Data

    # Filling the None output context with values from the Entra and Exo accounts.
    foreach ($property in $outputContext.Data.PSObject.Properties) {
        if ($property.name -notin $actionContext.Data.PSObject.Properties.Name ) {
            $outputContext.Data.$($property.name) = $correlatedAccountEntra.$($property.name)
        }
    }

    if ($actionContext.Configuration.ExchangeOnlineIntegration -and $actionContext.Data.PSObject.Properties.Name -contains 'exchangeOnline') {
        foreach ($property in $outputContext.Data.ExchangeOnline.PSObject.Properties) {
            if ($property.name -notin $actionContext.Data.ExchangeOnline.PSObject.Properties.Name ) {
                $outputContext.Data.ExchangeOnline.$($property.name) = $correlatedAccountExo.$($property.name)
            }
        }
    }
}
