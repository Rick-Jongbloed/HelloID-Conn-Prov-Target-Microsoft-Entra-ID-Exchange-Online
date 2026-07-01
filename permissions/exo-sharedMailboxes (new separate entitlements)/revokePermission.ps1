#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-SharedMailboxes-Revoke
# Revoke shared mailbox permission (full access, send as, send on behalf)
# PowerShell V2
#####################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region Functions
function Get-MSGraphAuthorization {
    [CmdletBinding(DefaultParameterSetName = 'Resource')]
    param(
        [parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$TenantId,

        [parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$ClientId,

        [parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$ClientSecret,

        [parameter(ParameterSetName = 'Resource')]
        [string]$Resource = 'https://graph.microsoft.com',

        [parameter(ParameterSetName = 'Scope')]
        [string]$Scope = 'https://graph.microsoft.com/.default',

        [parameter()]
        [string]$GrantType = 'client_credentials',

        [parameter()]
        [switch]$AccessToken = $false
    )

    try {
        $createAccessTokenBody = @{
            grant_type    = $GrantType
            client_id     = $ClientId
            client_secret = $ClientSecret
        }

        switch ($PsCmdlet.ParameterSetName) {
            'Resource' {
                $createAccessTokenBody['resource'] = $Resource
            }
            default {
                $createAccessTokenBody['scope'] = $Scope
            }
        }

        $createAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
            Method      = 'POST'
            Body        = $createAccessTokenBody
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $graphAccessToken = (Invoke-RestMethod @createAccessTokenSplatParams).access_token

        if ($AccessToken -eq $true) {
            return $graphAccessToken
        }

        return @{
            Authorization  = "Bearer $($graphAccessToken)"
            'Content-Type' = 'application/json'
            Accept         = 'application/json'
        }
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
                $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message | ConvertFrom-Json
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
    if ($ActionContext.Configuration.ExO.Integration) {
        $ExOAuthorization = $ActionContext.Configuration | Get-MSGraphAuthorization -Resource 'https://outlook.office365.com'
        Write-Verbose -Verbose 'Successfully authenticated the Exchange Admin API'

        if (-not [String]::IsNullOrEmpty($ActionContext.Configuration.ExO.AnchorMailboxDomain)) {
            if ($ActionContext.Configuration.ExO.AnchorMailboxDomain -notlike '*onmicrosoft.com') {
                $Domain = $ActionContext.Configuration.ExO.AnchorMailboxDomain -split '.' | Select-Object -First 1
                $ActionContext.Configuration.ExO.AnchorMailboxDomain = "$($Domain).onmicrosoft.com"
            }

            $ExOAuthorization['X-AnchorMailbox'] = "APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$($ActionContext.Configuration.ExO.AnchorMailboxDomain.TrimStart('@').Trim())"
        }

        switch ($ActionContext.References.Permission.Permission) {
            'FullAccess' {
                $CmdletName = 'Remove-MailboxPermission'

                $Parameters = @{
                    Identity        = $ActionContext.References.Permission.Reference
                    User            = $ActionContext.References.Account
                    AccessRights    = 'FullAccess'
                    InheritanceType = 'All'
                    Confirm         = $false
                }
            }
            'SendAs' {
                $CmdletName = 'Remove-RecipientPermission'

                $Parameters = @{
                    Identity     = $ActionContext.References.Permission.Reference
                    Trustee      = $ActionContext.References.Account
                    AccessRights = 'SendAs'
                    Confirm      = $false
                }
            }
            'SendOnBehalf' {
                $CmdletName = 'Set-Mailbox'

                $Parameters = @{
                    Identity            = $ActionContext.References.Permission.Reference
                    GrantSendOnBehalfTo = @{
                        '@odata.type' = '#Exchange.GenericHashTable'
                        Remove        = $ActionContext.References.Account
                    }
                    Confirm             = $false
                }
            }
            default {
                throw "Unsupported permission type: [$($ActionContext.References.Permission.Permission)]"
            }
        }

        $RevokePermissionRequest = @{
            Uri         = "https://outlook.office365.com/adminapi/beta/$($ActionContext.Configuration.TenantId)/InvokeCommand"
            Method      = 'Post'
            Body        = @{
                CmdletInput = @{
                    CmdletName = $CmdletName
                    Parameters = $Parameters
                }
            }
            ContentType = 'application/json'
            Headers     = $ExOAuthorization
        }

        if ($ActionContext.DryRun -eq $false) {
            $RevokePermissionRequest.Body = [System.Text.Encoding]::UTF8.GetBytes(
                (ConvertTo-Json -InputObject $RevokePermissionRequest.Body -Depth 10 -Compress)
            )

            try {
                [void](Invoke-RestMethod @RevokePermissionRequest)
            }
            catch {
                $ResolvedError = $_ | Resolve-MS-Entra-ExoError
                $ResolvedErrorString = $ResolvedError | ConvertTo-Json -Depth 10

                if ($ResolvedErrorString -match 'ManagementObjectNotFoundException|wasn''t found|couldn''t be found|couldn''t find object') {
                    $OutputContext.AuditLogs.Add(
                        [PSCustomObject]@{
                            Action  = 'RevokePermission'
                            Message = "Skipped revoking permission '$($ActionContext.PermissionDisplayName)'. Reason: user or mailbox no longer exists."
                            IsError = $false
                        }
                    )

                    $OutputContext.Success = $true
                    return
                }

                throw $_
            }
        }
        else {
            Write-Verbose -Verbose ($RevokePermissionRequest | Select-Object -Property * -ExcludeProperty 'Headers' | ConvertTo-Json -Depth 10)
        }

        $OutputContext.AuditLogs.Add(
            [PSCustomObject]@{
                Message = "Revoked permission [$($ActionContext.PermissionDisplayName)] with id [$($ActionContext.References.Permission.Reference)] from account with AccountReference: $($ActionContext.References.Account)"
                IsError = $false
            }
        )
    }

    $OutputContext.Success = $true
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MS-Entra-ExoError -ExceptionResponse $ex

        if ($errorObj.ErrorDetails.error.code -eq 'Request_ResourceNotFound' -and $errorObj.ErrorDetails.error.message -like "*$($ActionContext.References.Permission.Reference)*") {
            $auditMessage = "Skipped revoking permission [$($ActionContext.PermissionDisplayName)] with id [$($ActionContext.References.Permission.Reference)] from account with AccountReference: $($ActionContext.References.Account | ConvertTo-Json). Reason: User is already no longer a member or the permission no longer exists."
            $auditError = $false
            $OutputContext.Success = $true
        }
        else {
            $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
            $auditError = $true
            Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            $OutputContext.Success = $false
        }
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $auditError = $true
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        $OutputContext.Success = $false
    }

    $OutputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $auditError
        })
}
#endregion script
