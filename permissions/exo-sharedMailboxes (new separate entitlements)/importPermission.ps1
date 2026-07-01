#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-SharedMailboxes-Import
# Correlate accounts to shared mailbox permissions
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

function ConvertTo-RequestBatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Object[]]$InputObject,

        [Parameter()]
        [int]$GroupSize = 20
    )

    $Batches = [Collections.Generic.List[Object[]]]::new()

    for ($i = 0; $i -lt $InputObject.Count; $i += $GroupSize) {
        $EndIndex = [Math]::Min($i + $GroupSize - 1, $InputObject.Count - 1)

        $Batches.Add(
            $InputObject[$i..$EndIndex]
        )
    }

    return $Batches
}

function Invoke-ExOBatchRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Object[]]$Body,

        [Parameter(Mandatory)]
        [String]$TenantId,

        [Parameter(Mandatory)]
        [Object]$Authorization
    )

    $BatchRequest = @{
        Uri         = "https://outlook.office365.com/adminapi/beta/$($TenantId)/`$batch"
        Method      = 'POST'
        Body        = @{
            requests = $Body
        }
        ContentType = 'application/json'
        Headers     = $Authorization
    }

    $BatchRequest.Body = [System.Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-Json -InputObject $BatchRequest.Body -Depth 10 -Compress)
    )

    $Responses = Invoke-RestMethod @BatchRequest | Select-Object -ExpandProperty 'responses'

    foreach ($Response in $Responses) {
        $Response.body | Add-Member -MemberType 'NoteProperty' -Name 'status' -Value $Response.Status
        $Response.body | Add-Member -MemberType 'NoteProperty' -Name 'id' -Value $Response.id

        $Response.body
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

        $GetSharedMailboxParameters = @{
            ResultSize           = 1000
            RecipientTypeDetails = 'SharedMailbox'
            SortBy               = 'Alias'
        }

        $LastSharedMailboxAlias = $Null

        $SharedMailboxes = do {
            if ($LastSharedMailboxAlias) {
                $GetSharedMailboxParameters['Filter'] = "Alias -gt '$($LastSharedMailboxAlias)'"
            }

            $ExOGetMailboxes = @{
                Uri         = "https://outlook.office365.com/adminapi/beta/$($ActionContext.Configuration.TenantId)/InvokeCommand"
                Method      = 'Post'
                Body        = @{
                    CmdletInput = @{
                        CmdletName = 'Get-Mailbox'
                        Parameters = $GetSharedMailboxParameters
                    }
                }
                ContentType = 'application/json'
                Headers     = $ExOAuthorization
            }

            $ExOGetMailboxes.Body = [System.Text.Encoding]::UTF8.GetBytes(
                (ConvertTo-Json -InputObject $ExOGetMailboxes.Body -Depth 10 -Compress)
            )

            $MailboxPage = Invoke-RestMethod @ExOGetMailboxes | Select-Object -ExpandProperty 'Value' | Select-Object -Property @(
                'Guid'
                'DisplayName'
                'PrimarySmtpAddress'
                'GrantSendOnBehalfTo'
                'Identity'
                'Alias'
            )

            if (($MailboxPage).Count -eq $GetSharedMailboxParameters.ResultSize) {
                $LastSharedMailboxAlias = $MailboxPage[-1].Alias
            }

            $MailboxPage

        } while ($MailboxPage.Count -eq $GetSharedMailboxParameters.ResultSize)

        Write-Information "Retrieved $(($SharedMailboxes | Measure-Object).Count) shared mailboxes."

        $ExOGetRecipientPermissions = @{
            Uri         = "https://outlook.office365.com/adminapi/beta/$($ActionContext.Configuration.TenantId)/InvokeCommand"
            Method      = 'Post'
            Body        = @{
                CmdletInput = @{
                    CmdletName = 'Get-RecipientPermission'
                    Parameters = @{
                        ResultSize = 'Unlimited'
                    }
                }
            }
            ContentType = 'application/json'
            Headers     = $ExOAuthorization
        }

        $ExOGetRecipientPermissions.Body = [System.Text.Encoding]::UTF8.GetBytes(
            (ConvertTo-Json -InputObject $ExOGetRecipientPermissions.Body -Depth 10 -Compress)
        )

        $RecipientPermissions = Invoke-RestMethod @ExOGetRecipientPermissions | Select-Object -ExpandProperty 'Value' | Where-Object {
            $_.Trustee -notin @(
                'NT AUTHORITY\SELF'
                'NULL SID'
            )
        } | Select-Object -Property @(
            'Trustee'
            'AccessRights'
            'IsInherited'
            'Identity'
        )

        $RecipientPermissions = $RecipientPermissions | Group-Object -Property 'Identity' -AsHashTable -AsString

        $Batches = ConvertTo-RequestBatches -InputObject $SharedMailboxes -GroupSize 10

        $MailboxPermissions = foreach ($Batch in $Batches) {
            $BatchRequestBody = $Batch.Guid | ForEach-Object {
                @{
                    id      = $_
                    method  = 'POST'
                    url     = "https://outlook.office365.com/adminapi/beta/$($ActionContext.Configuration.TenantId)/InvokeCommand"
                    body    = @{
                        CmdletInput = @{
                            CmdletName = 'Get-MailboxPermission'
                            Parameters = @{
                                Identity   = $_
                                ResultSize = 'Unlimited'
                            }
                        }
                    }
                    headers = @{
                        'Content-Type' = 'application/json'
                    }
                }
            }

            $BatchRequest = @{
                Body          = $BatchRequestBody
                TenantId      = $ActionContext.Configuration.TenantId
                Authorization = $ExOAuthorization
            }

            Invoke-ExOBatchRequest @BatchRequest
        }

        $Errors = $MailboxPermissions | Where-Object {
            $_.status -ne 200
        }

        if ($Errors.count -gt 0) {
            $ErrorMessage = $Errors.error | Select-Object -Property @(
                'code'
                'message'
            ) | Sort-Object -Unique

            throw $ErrorMessage
        }

        $MailboxPermissions = $MailboxPermissions | Where-Object {
            $_.User -notin @(
                'NT AUTHORITY\SELF'
                'NULL SID'
            )
        }

        $MailboxPermissions = $MailboxPermissions.value | Group-Object -Property 'Identity' -AsHashTable -AsString

        $LastAlias = $Null

        $GetMailboxParameters = @{
            ResultSize           = 1000
            RecipientTypeDetails = 'UserMailbox'
            SortBy               = 'Alias'
        }

        $Mailboxes = do {
            if ($LastAlias) {
                $GetMailboxParameters['Filter'] = "Alias -gt '$($LastAlias)'"
            }

            $ExOGetMailboxes = @{
                Uri         = "https://outlook.office365.com/adminapi/beta/$($ActionContext.Configuration.TenantId)/InvokeCommand"
                Method      = 'Post'
                Body        = @{
                    CmdletInput = @{
                        CmdletName = 'Get-Mailbox'
                        Parameters = $GetMailboxParameters
                    }
                }
                ContentType = 'application/json'
                Headers     = $ExOAuthorization
            }

            $ExOGetMailboxes.Body = [System.Text.Encoding]::UTF8.GetBytes(
                (ConvertTo-Json -InputObject $ExOGetMailboxes.Body -Depth 10 -Compress)
            )

            $MailboxPage = Invoke-RestMethod @ExOGetMailboxes | Select-Object -ExpandProperty 'Value' | Select-Object -Property @(
                'ExternalDirectoryObjectId'
                'UserPrincipalName'
                'Identity'
                'Alias'
            )

            if (($MailboxPage).Count -eq $GetMailboxParameters.ResultSize) {
                $LastAlias = $MailboxPage[-1].Alias
            }

            $MailboxPage

        } while ($MailboxPage.Count -eq $GetMailboxParameters.ResultSize)

        $Identities = $Mailboxes | Group-Object -Property 'Identity' -AsHashTable -AsString
        $Mailboxes = $Mailboxes | Group-Object -Property 'UserPrincipalName' -AsHashTable -AsString

        foreach ($SharedMailbox in $SharedMailboxes) {
            $SendAsPermissions = $RecipientPermissions[$SharedMailbox.Identity] | Where-Object {
                'SendAs' -in $_.AccessRights
            }

            $FullAccessPermissions = $MailboxPermissions[$SharedMailbox.Identity] | Where-Object {
                'FullAccess' -in $_.AccessRights
            }

            [Array]$FullAccessAccountReferences = $FullAccessPermissions.user | Where-Object {
                $Null -ne $_
            } | ForEach-Object {
                if ($Mailboxes.ContainsKey($_)) {
                    $Mailboxes[$_].ExternalDirectoryObjectId
                }
            }

            [Array]$SendAsAccountReferences = $SendAsPermissions.trustee | Where-Object {
                $Null -ne $_
            } | ForEach-Object {
                if ($Mailboxes.ContainsKey($_)) {
                    $Mailboxes[$_].ExternalDirectoryObjectId
                }
            }

            [Array]$SendOnBehalfToAccountReferences = $SharedMailbox.GrantSendOnBehalfTo | Where-Object {
                $Null -ne $_
            } | ForEach-Object {
                if ($Identities.ContainsKey($_)) {
                    $Identities[$_].ExternalDirectoryObjectId
                }
            }

            if (($FullAccessAccountReferences | Measure-Object).count) {
                $DisplayName = "$($SharedMailbox.DisplayName -replace ('(?s)^(.{80}).{4,}$', '$1...')) - Full Access ($($SharedMailbox.PrimarySmtpAddress))"

                Write-Output @{
                    PermissionReference = @{
                        Reference  = $SharedMailbox.Guid
                        Permission = 'FullAccess'
                    }
                    DisplayName         = $DisplayName -replace ('(?s)^(.{97}).{4,}$', '$1...')
                    Description         = $SharedMailbox.PrimarySmtpAddress -replace ('(?s)^(.{97}).{4,}$', '$1...')
                    AccountReferences   = [Array]$FullAccessAccountReferences
                }
            }

            if (($SendAsAccountReferences | Measure-Object).count) {
                $DisplayName = "$($SharedMailbox.DisplayName -replace ('(?s)^(.{80}).{4,}$', '$1...')) - Send As ($($SharedMailbox.PrimarySmtpAddress))"

                Write-Output @{
                    PermissionReference = @{
                        Reference  = $SharedMailbox.Guid
                        Permission = 'SendAs'
                    }
                    DisplayName         = $DisplayName -replace ('(?s)^(.{97}).{4,}$', '$1...')
                    Description         = $SharedMailbox.PrimarySmtpAddress -replace ('(?s)^(.{97}).{4,}$', '$1...')
                    AccountReferences   = [Array]$SendAsAccountReferences
                }
            }

            if (($SendOnBehalfToAccountReferences | Measure-Object).count) {
                $DisplayName = "$($SharedMailbox.DisplayName -replace ('(?s)^(.{80}).{4,}$', '$1...')) - Send On Behalf ($($SharedMailbox.PrimarySmtpAddress))"

                Write-Output @{
                    PermissionReference = @{
                        Reference  = $SharedMailbox.Guid
                        Permission = 'SendOnBehalf'
                    }
                    DisplayName         = $DisplayName -replace ('(?s)^(.{97}).{4,}$', '$1...')
                    Description         = $SharedMailbox.PrimarySmtpAddress -replace ('(?s)^(.{97}).{4,}$', '$1...')
                    AccountReferences   = [Array]$SendOnBehalfToAccountReferences
                }
            }
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
