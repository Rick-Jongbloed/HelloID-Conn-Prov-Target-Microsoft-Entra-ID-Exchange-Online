#region Functions
function Connect-MSGraph {
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

    $AuthenticationBody = @{
        grant_type    = $GrantType
        client_id     = $ClientId
        client_secret = $ClientSecret
    }

    switch ($PsCmdlet.ParameterSetName) {
        'Resource' {
            $AuthenticationBody['resource'] = $Resource
        }
        default {
            $AuthenticationBody['scope'] = $Scope
        }
    }

    $AuthenticationRequest = @{
        Uri         = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
        Method      = 'POST'
        Body        = $AuthenticationBody
        ContentType = 'application/x-www-form-urlencoded'
    }

    $GraphAccessToken = (Invoke-RestMethod @AuthenticationRequest).access_token

    if ($AccessToken -eq $true) {
        return $GraphAccessToken
    }

    return @{
        Authorization  = "Bearer $($GraphAccessToken)"
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
    }
}

function Resolve-ExceptionDetails {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [parameter(Mandatory, ValueFromPipeline)]
        [System.Object]$ExceptionResponse
    )

    process {
        try {
            if ($ExceptionResponse.Exception -is [System.Net.WebException]) {
                Write-Verbose 'Resolving WebException'
                $StreamReader = [System.IO.StreamReader]::new(
                    $ExceptionResponse.Exception.Response.GetResponseStream()
                )

                $StreamReader.BaseStream.Position = 0
                $StreamReader.DiscardBufferedData()

                $JSONResponse = $StreamReader.ReadToEnd() 

                $ErrorObject = $JSONResponse | ConvertFrom-Json
            }
            elseif (-not [string]::IsNullOrEmpty($ExceptionResponse.ErrorDetails.Message)) {
                Write-Verbose 'Resolving ErrorDetails'
                $ErrorObject = $ExceptionResponse.ErrorDetails.Message | ConvertFrom-Json
            }

            if ($Null -ne $ErrorObject) {
                $ExceptionResponse.Exception.PSObject.Properties | Where-Object {
                    $_.Name -notin $ErrorObject.PSObject.Properties.Name
                } | ForEach-Object {
                    $ErrorObject | Add-Member -MemberType 'NoteProperty' -Name $_.Name -Value $_.Value
                }
            }
        }
        catch {
            Write-Verbose 'Resolving native Exception response'
        }

        if ($Null -eq $ErrorObject) {
            $ErrorObject = $ExceptionResponse.Exception
        }

        return $ErrorObject
    }
}
#endregion Functions

#region script
try {
    if ($ActionContext.Configuration.ExO.Integration) {
        $ExOAuthorization = $ActionContext.Configuration | Connect-MSGraph -Resource 'https://outlook.office365.com'
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
                $CmdletName = 'Add-MailboxPermission'

                $Parameters = @{
                    Identity        = $ActionContext.References.Permission.Reference
                    User            = $ActionContext.References.Account
                    AccessRights    = 'FullAccess'
                    InheritanceType = 'All'
                    Confirm         = $false
                }
            }
            'SendAs' {
                $CmdletName = 'Add-RecipientPermission'

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
                        Add           = $ActionContext.References.Account
                    }
                    Confirm             = $false
                }
            }
        }

        $GrantPermissionRequest = @{
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
            $GrantPermissionRequest.Body = [System.Text.Encoding]::UTF8.GetBytes(
                (ConvertTo-Json -InputObject $GrantPermissionRequest.Body -Depth 10 -Compress)
            )
            
            [void](Invoke-RestMethod @GrantPermissionRequest)
        }
        else {
            Write-Verbose -Verbose ($GrantPermissionRequest | Select-Object -Property * -ExcludeProperty 'Headers' | ConvertTo-Json -Depth 10)
        }

        $OutputContext.AuditLogs.add(
            [PSCustomObject]@{
                Action  = 'GrantPermission'
                Message = "Granted permission '$($ActionContext.PermissionDisplayName)' ($($ActionContext.References.Permission.Reference | ConvertTo-Json -Compress)) during $($ActionContext.Origin) ($($ActionContext.References.Account | ConvertTo-Json -Compress))."
                IsError = $false
            }
        )
    }

    $OutputContext.Success = $true
}
catch {
    #Handle Graph API errors, function exists because it needs a different handling when running locally compared to in the cloud
    $Exception = $_ | Resolve-ExceptionDetails

    if ('error' -in $Exception.PSObject.Properties.Name) {
        $Exception = $Exception.error | ConvertTo-Json -Compress -Depth 2
    }
 
    $ExceptionMessage = "An exception occured during $($ActionContext.Origin) while processing $($ActionContext.PermissionDisplayName) ($($ActionContext.References.Permission.Reference | ConvertTo-Json -Compress)) permission $($ActionContext.Operation) logic ($($ActionContext.References.Account | ConvertTo-Json -Compress)): `"$($Exception | Out-String)`""

    if ($ExceptionMessage.Length -gt 904) {
        $ExceptionMessage = $ExceptionMessage.Substring(0, 904)
    }

    $OutputContext.AuditLogs.Add(
        [PSCustomObject]@{
            Message = $ExceptionMessage
            IsError = $true
        }
    )
        
    Write-Warning ($Exception | Out-String)
}
#endregion script