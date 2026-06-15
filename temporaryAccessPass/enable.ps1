#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Enable
# Correlate only + Temporary Access Pass
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
				$httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.error.details.message)"
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
		$derBytes = $Certificate.RawData

		$sha256 = [System.Security.Cryptography.SHA256]::Create()
		$hashBytes = $sha256.ComputeHash($derBytes)
		$base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

		$header = @{
			'alg'      = 'RS256'
			'typ'      = 'JWT'
			'x5t#S256' = $base64Thumbprint
		} | ConvertTo-Json
		$base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

		$currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

		$payload = [Ordered]@{
			'iss' = "$($actionContext.Configuration.AppId)"
			'sub' = "$($actionContext.Configuration.AppId)"
			'aud' = "https://login.microsoftonline.com/$($actionContext.Configuration.TenantID)/oauth2/token"
			'exp' = ($currentUnixTimestamp + 3600)
			'nbf' = ($currentUnixTimestamp - 300)
			'iat' = $currentUnixTimestamp
			'jti' = [Guid]::NewGuid().ToString()
		} | ConvertTo-Json
		$base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

		$rsaPrivate = $Certificate.PrivateKey
		$rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
		$rsa.ImportParameters($rsaPrivate.ExportParameters($true))

		$signatureInput = "$base64Header.$base64Payload"
		$signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
		$base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

		if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
			throw 'The certificate does not have a private key.'
		}

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
		$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
			$rawCertificate,
			$actionContext.Configuration.AppCertificatePassword,
			[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
		)
		Write-Output $certificate
	}
	catch {
		$PSCmdlet.ThrowTerminatingError($_)
	}
}
#endregion functions

try {
	if ([string]::IsNullOrEmpty($actionContext.References.Account)) {
		throw 'The account reference could not be found'
	}

	Write-Information 'Verifying if a Microsoft Entra account exists'
    

	$tapLifetimeInput = [string]$actionContext.Configuration.TemporaryAccesPassLifetime
	$tapLifetime = 0
	if (-not [int]::TryParse($tapLifetimeInput.Trim(), [ref]$tapLifetime) -or $tapLifetime -le 0) {
		throw "TemporaryAccesPassLifetime [$tapLifetimeInput] is not a valid positive number."
	}

	$bodyTAP = @{
		lifetimeInMinutes = $tapLifetime
		isUsableOnce      = $true
	}

	$actionMessage = 'creating Microsoft Entra access token'
	$certificate = Get-MSEntraCertificate
	$entraToken = Get-MSEntraAccessToken -Certificate $certificate

	$actionMessage = "verifying if the correlated account exists [$($actionContext.References.Account)]"
	$correlatedAccount = $null
	try {
		$splatGetEntraUser = @{
			Uri         = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)?`$select=id,accountEnabled"
			Method      = 'GET'
			Headers     = @{ 'Authorization' = "Bearer $entraToken" }
			ErrorAction = 'Stop'
		}
		$correlatedAccount = Invoke-RestMethod @splatGetEntraUser
	}
	catch {
		if ($_.Exception.Response.StatusCode -eq 404) {
			$correlatedAccount = $null
		}
		else {
			throw $_
		}
	}

	if ($null -ne $correlatedAccount) {
		$lifecycleProcess = 'EnableAccount'
	}
	else {
		$lifecycleProcess = 'NotFound'
	}

	# Process
	switch ($lifecycleProcess) {
		'EnableAccount' {
			$actionMessage = "setting Temporary Access Pass for account [$($actionContext.References.Account)]"
			$splatSetTemporaryAccessPass = @{
				Uri         = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)/authentication/temporaryAccessPassMethods"
				Method      = 'POST'
				Headers     = @{ 'Authorization' = "Bearer $entraToken" }
				Body        = ($bodyTAP | ConvertTo-Json -Depth 10)
				ContentType = 'application/json; charset=utf-8'
				ErrorAction = 'Stop'
			}

			if (-not($actionContext.DryRun -eq $true)) {
				Write-Information "Enabling Temporary Access Pass for account with accountReference: [$($actionContext.References.Account)]"
				$setTemporaryAccessPassResponse = Invoke-RestMethod @splatSetTemporaryAccessPass

				$startDateTimeUtc =	[datetime]$setTemporaryAccessPassResponse.startDateTime
				$validUntilDateTime = $startDateTimeUtc.AddMinutes($tapLifetime).ToLocalTime()

				$outputContext.Data.validUntil = $validUntilDateTime.ToString('dd-MM-yyyy HH:mm', [System.Globalization.CultureInfo]::GetCultureInfo('nl-NL'))
				$outputContext.Data.temporaryAccessPass = $setTemporaryAccessPassResponse.temporaryAccessPass

				$outputContext.Success = $true
				$outputContext.AuditLogs.Add([PSCustomObject]@{
						Message = "Successfully enabled Temporary Access Pass for accountReference [$($actionContext.References.Account)] with a validity of [$tapLifetime] minutes."
						IsError = $false
					})
			}
			else {
				Write-Information "[DryRun] Enable Temporary Access Pass for account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
				$outputContext.Success = $true
				$outputContext.AuditLogs.Add([PSCustomObject]@{
						Message = "[DryRun] Would enable Temporary Access Pass for accountReference [$($actionContext.References.Account)] with a validity of [$tapLifetime] minutes."
						IsError = $false
					})
			}

			break
		}

		'NotFound' {
			Write-Information "Microsoft Entra account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
			$outputContext.Success = $false
			$outputContext.AuditLogs.Add([PSCustomObject]@{
					Message = "Account with accountReference [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted."
					IsError = $true
				})

			break
		}
	}
}
catch {
	$outputContext.Success = $false
	$ex = $PSItem

	if ($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException' -or
		$ex.Exception.GetType().FullName -eq 'System.Net.WebException') {
		$errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
		$auditMessage = "Failed to enable Temporary Access Pass for accountReference [$($actionContext.References.Account)] during [$actionMessage]. Error: $($errorObj.FriendlyMessage)"
		Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
	}
	else {
		$auditMessage = "Failed to enable Temporary Access Pass for accountReference [$($actionContext.References.Account)] during [$actionMessage]. Error: $($ex.Exception.Message)"
		Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
	}

	$outputContext.AuditLogs.Add([PSCustomObject]@{
			Message = $auditMessage
			IsError = $true
		})
}
