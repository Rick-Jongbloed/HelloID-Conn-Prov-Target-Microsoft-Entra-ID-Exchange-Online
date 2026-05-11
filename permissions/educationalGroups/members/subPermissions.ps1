################################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-EducationalGroups-Members-SubPermissions
# PowerShell V2
################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{ }
foreach ($permission in $actionContext.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

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

function Remove-StringLatinCharacters {
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}

function Get-SanitizedGroupName {
    # The names of security principal objects can contain all Unicode characters except the special LDAP characters defined in RFC 2253.
    # This list of special characters includes: a leading space a trailing space and any of the following characters: # , + " \ < >
    # A group account cannot consist solely of numbers, periods (.), or spaces. Any leading periods or spaces are cropped.
    # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc776019(v=ws.10)?redirectedfrom=MSDN
    # https://www.ietf.org/rfc/rfc2253.txt
    param(
        [parameter(Mandatory = $true)][String]$Name
    )
    $newName = $name.trim()
    $newName = $newName -replace " - ", "_"
    $newName = $newName -replace "[`,~,!,#,$,%,^,&,*,(,),+,=,<,>,?,/,',`",,:,\,|,},{,.]", ""
    $newName = $newName -replace "\[", ""
    $newName = $newName -replace "]", ""
    $newName = $newName -replace " ", "_"
    $newName = $newName -replace "\.\.\.\.\.", "."
    $newName = $newName -replace "\.\.\.\.", "."
    $newName = $newName -replace "\.\.\.", "."
    $newName = $newName -replace "\.\.", "."

    # Remove diacritics
    $newName = Remove-StringLatinCharacters $newName

    return $newName
}

function Get-SchoolYear {
    # Calculate school year dependencies
    # School year definition in numbers of 4 or 2 digits
    $schoolYearLength = 2 # Length of school year used in the Teams name - e.g. 24-25 for 2 or 2024-2025 for 4
    $schoolYearSeperator = "" # Used in the Teams name - can be empty
    
    if ($schoolYearLength -eq 2) { $format = "yy" } else { $format = "yyyy" }
    
    $monthcurrent = (Get-Date).Month
    $yearcurrent = (Get-Date).ToString($format)
    $yearprevious = ([int]$yearcurrent - 1).ToString()
    $yearnext = ([int]$yearcurrent + 1).ToString()
    
    If ($monthcurrent -ge 8) {
        $schoolyear = $yearcurrent + $schoolYearSeperator + $yearnext
    }
    else {
        $schoolyear = $yearprevious + $schoolYearSeperator + $yearcurrent
    }
    return $schoolyear
}
#endregion functions

try {
    $actionMessage = "verifying account reference"
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference could not be found"
    }

    # Determine schoolyear
    $schoolyear = Get-SchoolYear

    # Setup Connection with Entra/Exo
    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    $headers.Add('Authorization', "Bearer $entraToken")
    $headers.Add('Accept', 'application/json')
    $headers.Add('Content-Type', 'application/json')
    # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
    $headers.Add('ConsistencyLevel', 'eventual')

    $actionMessage = "calculating desired permission"
    $desiredPermissions = @{}
    if (-Not($actionContext.Operation -eq "revoke")) {
        # Example: Contract Based Logic:
        foreach ($contract in $personContext.Person.Contracts) {
           

            $lesGroep = $contract.Department.ExternalId   
            $teamNamePrefix = $actionContext.Configuration.classTeamPrefix      
        
            #foreach ($lesGroep in $resource){
            $teamName = "$($teamNamePrefix)_$($lesGroep)"
        
            $teamName = Get-SanitizedGroupName -Name $teamName    
            $teamName = "$($teamName)_$($schoolyear)"

            $actionMessage = "querying Microsoft Entra ID group for resource: $($teamName | ConvertTo-Json)"
 
           
            Write-Information "Contract: $($contract.ExternalId). In condition: $($contract.Context.InConditions)"
            if ($contract.Context.InConditions -OR ($actionContext.DryRun -eq $true)) {
                # Get group to use objectGuid to avoid name change issues
                $correlationField = "displayName"

                # Example: department_<departmentname>
                $correlationValue = $teamName

                # Example: title_<titlename>
                # $correlationValue = "title_" + $contract.Title.Name

                # Sanitize group name, e.g. replace " - " with "_" or other sanitization actions
                $correlationValue = Get-SanitizedGroupName -Name $correlationValue

                $baseUri = "https://graph.microsoft.com/"
                $getMicrosoftEntraIDGroupSplatParams = @{
                    Uri         = "$baseUri/v1.0/groups?`$filter=$($correlationField)+eq+'$($correlationValue)'"
                    Headers     = $headers
                    Method      = "GET"
                    Verbose     = $false
                    ErrorAction = "Stop"
                }
                $group = $null

                $group = (Invoke-RestMethod @getMicrosoftEntraIDGroupSplatParams).Value

                if ($group.Id.count -eq 0) {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "No Group found where [$($correlationField)] = [$($correlationValue)]"
                            IsError = $true
                        })
                }
                elseif ($group.Id.count -gt 1) {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Multiple Groups found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the groups are unique."
                            IsError = $true
                        })
                }
                else {
                    # Add group to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
                    $desiredPermissions["$($group.id)"] = $group.displayName
                }
            }
        }
    }
    Write-Information ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))
    Write-Information ("Existing Permissions: {0}" -f ($actionContext.CurrentPermissions.DisplayName | ConvertTo-Json))

    $newCurrentPermissions = @{}
    foreach ($permission in $currentPermissions.GetEnumerator()) {
        if (-Not $desiredPermissions.ContainsKey($permission.Name) -AND $permission.Name -ne "No permissions defined") {
            # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/group-delete-members?view=graph-rest-1.0&tabs=http
            $actionMessage = "revoking group [$($permission.Value)] with id [$($permission.Name)] from account"

            $baseUri = "https://graph.microsoft.com/"
            $revokePermissionSplatParams = @{
                Uri         = "$($baseUri)/v1.0/groups/$($permission.Name)/members/$($actionContext.References.Account)/`$ref"
                Headers     = $headers
                Method      = "DELETE"
                Verbose     = $false
                ErrorAction = "Stop"
            }

            if (-Not($actionContext.DryRun -eq $true)) {
                try {
                    $null = Invoke-RestMethod @revokePermissionSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "RevokePermission"
                            Message = "Revoked group [$($permission.Value)] with id [$($permission.Name)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                            IsError = $false
                        })
                }
                catch {                    
                    $ex = $PSItem
                    if ($($ex.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or
                        $($ex.Exception.GetType().FullName -eq "System.Net.WebException")) {
                        $errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
                        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"                        
                    }                                   
                    # If already revoked the code should not stop but continue
                    if (($errorObj.ErrorDetails | ConvertFrom-Json).error.code -eq "Request_ResourceNotFound" -and ($errorObj.ErrorDetails | ConvertFrom-Json).error.message -like "*$($actionContext.References.Permission.id)*") {                        
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                Action  = "RevokePermission"
                                Message = "Skipped revoking group [$($permission.Value)] with id [$($permission.Name)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: User is already no longer a member or the group no longer exists."
                                IsError = $false
                            })
                    }
                    else {
                        throw $ex
                    }
                }
            }
            else {
                Write-Information "[DryRun] Would revoke group [$($permission.Value)] with id [$($permission.Name)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
            }
        }
        else {
            $newCurrentPermissions[$permission.Name] = $permission.Value
        }
    }

    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })

        if (-Not $currentPermissions.ContainsKey($permission.Name)) {
            # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http
            $actionMessage = "granting group [$($permission.Value)] with id [$($permission.Name)] to account"
            
            # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http
            $splatGrantPermission = @{
                Uri     = "https://graph.microsoft.com/v1.0/groups/$($permission.Name)/members/`$ref"
                Headers = $headers
                Method  = 'POST'
                Verbose = $false
                Body    = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)"
                } | ConvertTo-Json -Depth 10
            }

            if (-Not($actionContext.DryRun -eq $true)) {
                try {
                    $null = Invoke-RestMethod @splatGrantPermission
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Granted group [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                            IsError = $false
                        })
                }
                catch {
                    $ex = $PSItem
                    if ($($ex.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or
                        $($ex.Exception.GetType().FullName -eq "System.Net.WebException")) {
                        $errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
                        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
                    }
                    # If already granted the code should not stop but continue
                    if ($auditMessage -like "*One or more added object references already exist for the following modified properties: 'members'*") {
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                Action  = "GrantPermission"
                                Message = "Skipped granting group [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: User is already a member of the group."
                                IsError = $false
                            })
                    }
                    else {
                        throw $ex
                    }
                }
            }
            else {
                Write-Information "[DryRun] Would grant group [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
            }
        }
    }
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or
        $($ex.Exception.GetType().FullName -eq "System.Net.WebException")) {
        $errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage

    $outputContext.AuditLogs.Add([PSCustomObject]@{
            # Action  = "" # Optional
            Message = $auditMessage
            IsError = $true
        })
}
finally {
    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($actionContext.Operation -match "update|grant" -AND $outputContext.SubPermissions.count -eq 0) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = "No permissions defined"
                Reference   = [PSCustomObject]@{ Id = "No permissions defined" }
            })

        Write-Warning "Skipped granting permissions for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: No permissions defined."
    }

    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}