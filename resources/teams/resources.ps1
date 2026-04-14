#####################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Resources-Teams
# Creates teams dynamically based on HR data
# PowerShell V2
#####################################################

# Make sure the resourceContext data is unique. Fill in the required fields after -unique
# Example: department
$resourceData = $resourceContext.SourceData | Select-Object -Unique ExternalId, DisplayName
# Example: title
# $resourceData = $resourceContext.SourceData | Select-Object -Unique ExternalId, Name
# Define correlation
$correlationField = "displayName"
$correlationValue = "" # Defined later in script

# Hardcoded Object ID of EntraID User to set as owner of team
$ownerAccountId = "7dcbb7e7-ae5f-499e-b9d4-ad80c6eb097c"

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{ }
foreach ($permission in $actionContext.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

#region functions
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
#endregion functions

try {
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

    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/teams-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying Microsoft Entra ID Teams"

    $microsoftEntraIDTeams = [System.Collections.ArrayList]@()
    do {
        $baseUri = "https://graph.microsoft.com/"
        $getMicrosoftEntraIDTeamsSplatParams = @{
            Uri         = "$($baseUri)/v1.0/teams?`$top=999&`$count=true"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        if (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDTeamsResult.'@odata.nextLink')) {
            $getMicrosoftEntraIDTeamsSplatParams["Uri"] = $getMicrosoftEntraIDTeamsResult.'@odata.nextLink'
        }

        $getMicrosoftEntraIDTeamsResult = $null
        $getMicrosoftEntraIDTeamsResult = Invoke-RestMethod @getMicrosoftEntraIDTeamsSplatParams
    
        if ($getMicrosoftEntraIDTeamsResult.Value -is [array]) {
            [void]$microsoftEntraIDTeams.AddRange($getMicrosoftEntraIDTeamsResult.Value)
        }
        else {
            [void]$microsoftEntraIDTeams.Add($getMicrosoftEntraIDTeamsResult.Value)
        }
    } while (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDTeamsResult.'@odata.nextLink'))

    # Group on correlation property to check if group exists (as correlation property has to be unique for a group)
    $microsoftEntraIDTeamsGrouped = $microsoftEntraIDTeams | Group-Object $correlationField -AsHashTable -AsString

    Write-Information "Queried Microsoft Entra ID Teams. Result count: $(($microsoftEntraIDTeams | Measure-Object).Count)"

    foreach ($resource in $resourceData) {
        $actionMessage = "querying team for resource: $($resource | ConvertTo-Json)"
 
        # Example: department_<departmentname>
        $teamName = "department_" + $resource.DisplayName

        # Example: title_<titlename>
        # $teamName = "title_" + $resource.Name

        # Sanitize team name, e.g. replace " - " with "_" or other sanitization actions 
        $teamName = Get-SanitizedGroupName -Name $teamName

        $correlationValue = $teamName

        $correlatedResource = $null
        $correlatedResource = $microsoftEntraIDTeamsGrouped["$($correlationValue)"]
        
        if (($correlatedResource | Measure-Object).count -eq 0) {
            $actionResource = "CreateResource"
        }
        elseif (($correlatedResource | Measure-Object).count -eq 1) {
            $actionResource = "CorrelateResource"
        }

        #region Process
        switch ($actionResource) {
            "CreateResource" {
                # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/team-post?view=graph-rest-1.0&tabs=http
                $actionMessage = "creating team for resource: $($resource | ConvertTo-Json)"

                $createTeamBody = @{
                    "template@odata.bind" = "https://graph.microsoft.com/v1.0/teamsTemplates('standard')"
                    displayName           = $teamName
                    description           = "$($resource.ExternalId)"
                    visibility            = "Private"

                    members               = [System.Collections.ArrayList]@()
                }

                if (-not[string]::IsNullOrEmpty($ownerAccountId)) {
                    [void]$createTeamBody.members.add(
                        @{
                            "@odata.type"     = "#microsoft.graph.aadUserConversationMember"
                            roles             = @(
                                "owner"
                            )
                            "user@odata.bind" = "https://graph.microsoft.com/v1.0/users('$ownerAccountId')"
                        }
                    )
                }

                $baseUri = "https://graph.microsoft.com/"
                $createGroupSplatParams = @{
                    Uri         = "$($baseUri)/v1.0/teams"
                    Headers     = $headers
                    Method      = "POST"
                    Body        = ($createTeamBody | ConvertTo-Json -Depth 10)
                    Verbose     = $false
                    ErrorAction = "Stop"
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    $createdTeam = Invoke-RestMethod @createGroupSplatParams

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "CreateResource"
                            Message = "Created team with name [$($teamName)]."
                            IsError = $false
                        })
                }
                else {
                    Write-Information "[DryRun] Would create team with name [$($teamName)] for resource: $($resource | ConvertTo-Json)."
                }
                break
            }

            "CorrelateResource" {
                $actionMessage = "correlating to team"

                Write-Information "Correlated to team with id [$($correlatedResource.id)] on [$($correlationField)] = [$($correlationValue)]."
                break
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
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}