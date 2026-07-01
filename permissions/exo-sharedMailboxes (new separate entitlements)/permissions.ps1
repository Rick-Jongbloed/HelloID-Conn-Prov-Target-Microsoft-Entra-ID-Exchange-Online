#####################################################
# HelloID-Conn-Prov-Target-MS-Entra-ExO-Permissions-SharedMailboxes-List
# List shared mailboxes as separate permissions
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
        Write-Verbose -Verbose 'Succesfully authenticated the Exchange Admin API'

        if (-not [String]::IsNullOrEmpty($ActionContext.Configuration.ExO.AnchorMailboxDomain)) {
            if ($ActionContext.Configuration.ExO.AnchorMailboxDomain -notlike '*onmicrosoft.com') {
                $Domain = $ActionContext.Configuration.ExO.AnchorMailboxDomain -split '.' | Select-Object -First 1
                $ActionContext.Configuration.ExO.AnchorMailboxDomain = "$($Domain).onmicrosoft.com"
            }

            $ExOAuthorization['X-AnchorMailbox'] = "APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$($ActionContext.Configuration.ExO.AnchorMailboxDomain.TrimStart('@').Trim())"
        }

        $GetMailboxParameters = @{
            ResultSize           = 1000
            RecipientTypeDetails = 'SharedMailbox'
            SortBy               = 'Alias'
        }

        $LastSharedMailboxAlias = $Null

        $SharedMailboxes = do {
            if ($LastSharedMailboxAlias) {
                $GetMailboxParameters['Filter'] = "Alias -gt '$($LastSharedMailboxAlias)'"
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
                'Guid'
                'DisplayName'
                'PrimarySmtpAddress'
                'Alias'
            )

            if (($MailboxPage).Count -eq $GetMailboxParameters.ResultSize) {
                $LastSharedMailboxAlias = $MailboxPage[-1].Alias
            }

            $MailboxPage

        } while ($MailboxPage.Count -eq $GetMailboxParameters.ResultSize)

        Write-Information "Retrieved $(($SharedMailboxes | Measure-Object).Count) shared mailboxes."

        foreach ($SharedMailbox in $SharedMailboxes) {
            foreach ($PermissionLevel in @('Full Access', 'Send As', 'Send On Behalf')) {
                $OutputContext.Permissions.Add(
                    @{
                        DisplayName    = "$($SharedMailbox.DisplayName -replace ('(?s)^(.{80}).{4,}$', '$1...')) - $($PermissionLevel) ($($SharedMailbox.PrimarySmtpAddress))" -replace ('(?s)^(.{97}).{4,}$', '$1...')
                        Identification = @{
                            Reference  = $SharedMailbox.Guid
                            Permission = $PermissionLevel -replace (' ', '')
                        }
                    }
                )
            }
        }

        $OutputContext.Success = $true
    }
}
catch {
    $OutputContext.Success = $false
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
