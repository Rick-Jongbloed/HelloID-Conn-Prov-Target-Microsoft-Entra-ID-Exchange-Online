#################################################
# HelloID-Conn-Prov-Target-MS-Entra-Exo-GuestInvite-Create
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
#endregion

try {
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'

    # Setup Connection with Entra/Exo
    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

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

    # Lookup manager Account
    if ($actionContext.Configuration.setManagerOnCreate -eq $true) {
        if (-not [String]::IsNullOrEmpty($personContext.Manager.ExternalId)) {
            $actionMessage = "querying MS-Entra-Exo Manager Account employeeId eq [$($personContext.Manager.ExternalId)]"
            $splatGetEntraManager = @{
                Uri     = "https://graph.microsoft.com/v1.0/users?`$filter=employeeId eq '$($personContext.Manager.ExternalId)'&`$select=id"
                Method  = 'GET'
                Headers = @{'Authorization' = "Bearer $($entraToken)" }
            }
            $managerId = (Invoke-RestMethod @splatGetEntraManager).value.id
            if ( [String]::IsNullOrEmpty($managerId)) {
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Set Manager on create is enabled, but no manager account is found in Entra based on employeeId eq [$($personContext.Manager.ExternalId)]. Skipping manager assignment."
                        IsError = $false
                    })
            }
        }
    }
    else {
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = 'Set Manager on create is enabled, but no manager externalId is found on the person object. Skipping manager assignment.'
                IsError = $false
            })
    }

    $actionList = [System.Collections.Generic.list[string]]::new()
    $actionMessage = "calculating action"
    if (($correlatedAccountEntra | Measure-Object).count -eq 1) {
        $actionList.Add('CorrelateAccount')
    }
    elseif (($correlatedAccountEntra | Measure-Object).count -eq 0) {
        $actionList.Add('GuestInvite')
        $actionList.Add('UpdateAccount')
        # Determine Manager actions
        if ($actionContext.Configuration.setManagerOnCreate -eq $true) {
            if (-not [String]::IsNullOrEmpty($managerId)) {
                $actionList.Add('SetManager')
            }
        }
    }
    
    # Process
    Write-Information "Actions to be executed: $($actionList -join ', ')"
    foreach ($action in $actionList) {
        switch ($action) {
            "GuestInvite" {
                # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/invitation-post?view=graph-rest-1.0&tabs=http
                $actionMessage = "creating invitation"

                # GuestInvite account with only required fields
                $requiredFields = @("invitedUserEmailAddress", "invitedUserDisplayName", "invitedUserMessageInfo", "inviteRedirectUrl", "sendInvitationMessage")
                $createInvitationBody = @{}
                foreach ($accountProperty in $actionContext.Data.PsObject.Properties | Where-Object { $null -ne $_.Value -and $_.Name -in $requiredFields }) {
                    [void]$createInvitationBody.Add($accountProperty.Name, $accountProperty.Value)
                }
            
                $createInvitationSplatParams = @{
                    Uri         = "https://graph.microsoft.com/v1.0/invitations"
                    Method      = "POST"
                    Body        = ($createInvitationBody | ConvertTo-Json -Depth 10)
                    Headers     = @{'Authorization' = "Bearer $($entraToken)" }
                    ContentType = 'application/json; charset=utf-8'
                    Verbose     = $false
                    ErrorAction = "Stop"
                }

                if (-not($actionContext.DryRun -eq $true)) {
                    $createdInvitation = Invoke-RestMethod @createInvitationSplatParams
                    $outputContext.AccountReference = "$($createdInvitation.invitedUser.id)"
                    $outputContext.Data | Add-Member @{ id = $($createdInvitation.invitedUser.id) } -Force

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Created invitation for user with displayName [$($createInvitationBody.invitedUserDisplayName)] and emailAddress [$($createInvitationBody.invitedUserEmailAddress)] with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)."
                            IsError = $false
                        })
                }
                else {
                    Write-Information "[DryRun] Would create invitation for user with displayName [$($createInvitationBody.invitedUserDisplayName)] and emailAddress [$($createInvitationBody.invitedUserEmailAddress)]."
                }     
                break       
            }
            
            'UpdateAccount' {
                # API docs: https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0&tabs=http
                $actionMessage = "updating created account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)"

                # Update account with all other fields than the required fields
                $updateAccountBody = [PSCustomObject]@{}
                foreach ($accountProperty in $actionContext.Data.PsObject.Properties | Where-Object { $null -ne $_.Value -and $_.Name -notin $requiredFields }) {
                    $updateAccountBody | Add-Member -MemberType NoteProperty -Name $accountProperty.Name -Value $accountProperty.Value -Force
                }

                $updateAccountSplatParams = @{
                    Uri         = "https://graph.microsoft.com/v1.0/users/$($outputContext.AccountReference)"
                    Method      = "PATCH"
                    Body        = ($updateAccountBody | ConvertTo-Json -Depth 10)
                    Headers     = @{'Authorization' = "Bearer $($entraToken)" }
                    ContentType = 'application/json; charset=utf-8'
                    Verbose     = $false
                    ErrorAction = "Stop"
                }

                if (-not($actionContext.DryRun -eq $true)) {
                    $null = Invoke-RestMethod @updateAccountSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Updated created account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json). Updated properties: $($updateAccountBody.PsObject.Properties.Name -join ', ')"
                            IsError = $false
                        })
                }
                else {
                    Write-Information "[DryRun] Would update created account. Updated properties [$($updateAccountBody | ConvertTo-Json)]."
                }
                break
            }

            'SetManager' {
                $actionMessage = "setting manager for created MS-Entra account with AccountReference [$($outputContext.AccountReference)]"
                $bodySetManager = @{
                    '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($managerId)"
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

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Message = "Set manager for Entra ID account with AccountReference: [$($outputContext.AccountReference)] Manager: [$($managerId)]"
                            IsError = $false
                        })
                    $outputContext.Data | Add-Member @{ ManagerId = $($managerId) } -Force
                }
                else {
                    Write-Information "[DryRun] Would set manager [$($managerId)] for created account."
                }
                break
            }

            "CorrelateAccount" {
                $actionMessage = "correlating to account"
                $outputContext.AccountReference = "$($correlatedAccountEntra.id)"
                $outputContext.Data = $correlatedAccountEntra | Select-Object -First 1
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "CorrelateAccount" # Optionally specify a different action for this audit log
                        Message = "Correlated to account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json) on [$($correlationField)] = [$($correlationValue)]."
                        IsError = $false
                    })

                $outputContext.AccountCorrelated = $true
                break
            }
        }
    }
}
catch {
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
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}