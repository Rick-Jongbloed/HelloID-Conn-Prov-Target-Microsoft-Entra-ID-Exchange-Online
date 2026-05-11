#####################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Resources-EducationalGroups-WithoutActivationButton
# PowerShell V2
#####################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region local variables
# Hardcoded Object ID of Azure AD User to set as owner of team
$ownerAccountId = $actionContext.Configuration.ownerGuid

$maximumAmountToCreatePerRun = 200
# Endregion local variables

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
#endregion functions

try {
    $resourceData = $resourceContext.SourceData | Where-Object { $_ -ne $null } | Where-Object { $_ -ne '[""]' } | Group-Object -Property externalId | ForEach-Object { $_.Group[0] }  # Select unique rows based on first column
    #$resourceData = $resourceContext.SourceData | Where-Object { $_ -ne $null } | Where-Object { $_.ExternalId -eq 'CLO-600' } | Select-Object -First 1

    # Define correlation
    $correlationField = "displayName"
    $correlationValue = "" # Defined later in script

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

    # Determine schoolyear
    $schoolyear = Get-SchoolYear
    $maxCreatedGroups = 0

    foreach ($resource in $resourceData) {
        $lesGroep = $resource.externalid  
        $teamNamePrefix = $actionContext.Configuration.lessonTeamPrefix      
        
        #foreach ($lesGroep in $resource){
        $teamName = "$($teamNamePrefix)_$($lesGroep)"
        
        $teamName = Get-SanitizedGroupName -Name $teamName    
        $teamName = "$($teamName)_$($schoolyear)"
        
        try {
            $actionMessage = "querying team for resource: $($teamName | ConvertTo-Json)"

            $correlatedResource = $microsoftEntraIDTeamsGrouped["$teamName"]

            #region Calulate action
            if (($correlatedResource | Measure-Object).count -eq 0) {                
                $actionResource = "CreateResource"
                #$description = "$teamName-TOUPGRADE"
            }
            elseif (($correlatedResource | Measure-Object).count -eq 1) {
                $actionResource = "CorrelateResource"                
            }
            #endregion Calulate action

            #region Process
            switch ($actionResource) {
                "CreateResource" {
                    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/team-post?view=graph-rest-1.0&tabs=http
                    $actionMessage = "creating team for resource: $($resource | ConvertTo-Json)"

                    $createTeamBody = @{
                        "template@odata.bind" = "https://graph.microsoft.com/v1.0/teamsTemplates('educationClass')"
                        displayName           = $teamName
                        description           = "$($resource.ExternalId)"
                        visibility            = "HiddenMembership"

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
        catch {
            throw $_
        }
        
        if ($maxCreatedGroups -ge $maximumAmountToCreatePerRun) {
            break
        }
    }
    $outputContext.Success = $true
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Action  = "CreateResource"
            Message = "Created [$maxCreatedGroups]."
            IsError = $false
        })
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