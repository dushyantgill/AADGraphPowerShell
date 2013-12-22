function Load-ActiveDirectoryAuthenticationLibrary(){
  $mydocuments = [environment]::getfolderpath("mydocuments")
  if(-not (Test-Path ($mydocuments+"\Nugets"))) {New-Item -Path ($mydocuments+"\Nugets") -ItemType "Directory" | out-null}
  $adalPackageDirectories = (Get-ChildItem -Path ($mydocuments+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)
  if($adalPackageDirectories.Length -eq 0){
    Write-Host "Active Directory Authentication Library Nuget doesn't exist. Downloading now ..." -ForegroundColor Yellow
    if(-not(Test-Path ($mydocuments + "\Nugets\nuget.exe")))
    {
      Write-Host "nuget.exe not found. Downloading from http://www.nuget.org/nuget.exe ..." -ForegroundColor Yellow
      $wc = New-Object System.Net.WebClient
      $wc.DownloadFile("http://www.nuget.org/nuget.exe",$mydocuments + "\Nugets\nuget.exe");
    }
    $nugetDownloadExpression = $mydocuments + "\Nugets\nuget.exe install Microsoft.IdentityModel.Clients.ActiveDirectory -OutputDirectory " + $mydocuments + "\Nugets | out-null"
    #write-host $nugetDownloadExpression
    Invoke-Expression $nugetDownloadExpression
  }
  $adalPackageDirectories = (Get-ChildItem -Path ($mydocuments+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)
  $ADAL_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)
  $ADAL_WindowsForms_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)
  if($ADAL_Assembly.Length -gt 0 -and $ADAL_WindowsForms_Assembly.Length -gt 0){
    Write-Host "Loading ADAL Assemblies ..." -ForegroundColor Green
    [System.Reflection.Assembly]::LoadFrom($ADAL_Assembly.FullName) | out-null
    [System.Reflection.Assembly]::LoadFrom($ADAL_WindowsForms_Assembly.FullName) | out-null
    return $true
  }
  else{
    Write-Host "Fixing Active Directory Authentication Library package directories ..." -ForegroundColor Yellow
    $adalPackageDirectories | Remove-Item -Recurse -Force | Out-Null
    Write-Host "Not able to load ADAL assembly. Delete the Nugets folder in MyDocuments, restart PowerShell session and try again ..."
    return $false
  }
}

function Get-AuthenticationResult(){
  $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
  $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
  $resourceClientId = "00000002-0000-0000-c000-000000000000"
  $resourceAppIdURI = "https://graph.windows.net"
  $authority = "https://login.windows.net/common"
  
  $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority,$false
  $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri)
  return $authResult
}

function Get-AADObject([string]$type) {
  $objects = $null
  if($authenticationResult -ne $null){
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}?api-version=2013-04-05",$authenticationResult.TenantId, $type)
    Write-Host HTTP GET $uri -ForegroundColor Cyan
    $result = Invoke-RestMethod -Method Get -Uri $uri -Headers @{"Authorization"=$header;"Content-Type"="application/json"}
    if ($result -ne $null) {
      $objects = $result.Value
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
  return $objects
}

function Get-AADObjectById([string]$type, [string]$id) {
  $object = $null
  if($global:authenticationResult -ne $null){
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}?api-version=2013-04-05",$authenticationResult.TenantId, $type.Trim(), $id.Trim())
    Write-Host HTTP GET $uri -ForegroundColor Cyan
    $object = Invoke-RestMethod -Method Get -Uri $uri -Headers @{"Authorization"=$header;"Content-Type"="application/json"}
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
  return $object
}

function New-AADObject([string]$type, [object]$object) {
  $newObject = $null
  if($global:authenticationResult -ne $null) {
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}?api-version=2013-04-05",$authenticationResult.TenantId, $type)
    Write-Host HTTP POST $uri -ForegroundColor Cyan
    $enc = New-Object "System.Text.ASCIIEncoding"
    $body = ConvertTo-Json -InputObject $object
    $byteArray = $enc.GetBytes($body)
    $contentLength = $byteArray.Length
    $headers = @{"Authorization"=$header;"Content-Type"="application/json";"Content-Length"=$contentLength}
    #Write-Host $body
    $newObject = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD."
  }
  return $newObject
}

function Set-AADObject([string]$type, [string]$id, [object]$object) {
  $updatedObject = $null
  if($global:authenticationResult -ne $null) {
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}?api-version=2013-04-05",$authenticationResult.TenantId, $type, $id)
    Write-Host HTTP PATCH $uri -ForegroundColor Cyan
    $enc = New-Object "System.Text.ASCIIEncoding"
    $body = ConvertTo-Json -InputObject $object
    $byteArray = $enc.GetBytes($body)
    $contentLength = $byteArray.Length
    $headers = @{"Authorization"=$header;"Content-Type"="application/json";"Content-Length"=$contentLength}
    #Write-Host $body
    $newObject = Invoke-RestMethod -Method Patch -Uri $uri -Headers $headers -Body $body
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
  return $updatedObject
}

function Remove-AADObject([string]$type, [string]$id) {
  $deleteResult = $null
  if($global:authenticationResult -ne $null) {
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}?api-version=2013-04-05",$authenticationResult.TenantId, $type, $id)
    Write-Host HTTP DELETE $uri -ForegroundColor Cyan
    $headers = @{"Authorization"=$header;"Content-Type"="application/json"}
    $deleteResult = Invoke-RestMethod -Method Delete -Uri $uri -Headers $headers
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
  return $deleteResult
}

function Get-AADLinkedObject([string]$type, [string] $id, [string]$relationship, [bool]$linksOnly) {
  $objects = $null
  if($global:authenticationResult -ne $null){
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = ""
    if($linksOnly) {$uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}/$links/{3}?api-version=2013-04-05",$authenticationResult.TenantId, $type, $id, $relationship)}
    else {$uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}/{3}?api-version=2013-04-05",$authenticationResult.TenantId, $type, $id, $relationship)}
    Write-Host HTTP GET $uri -ForegroundColor Cyan
    $result = Invoke-RestMethod -Method Get -Uri $uri -Headers @{"Authorization"=$header;"Content-Type"="application/json"}
    if ($result -ne $null) {
      $objects = $result.Value
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
  return $objects
}

###############################
#  Exported Cmdlets Start     #
###############################

function Connect-AAD {
  PROCESS {
    $global:authenticationResult = $null
    if(Load-ActiveDirectoryAuthenticationLibrary)
    {
      $global:authenticationResult = Get-AuthenticationResult
    }
  }
}

function Get-AADUser {
  [CmdletBinding()]
  param (
      [parameter(Mandatory=$false,
      ValueFromPipeline=$true,
      HelpMessage="Either the ObjectId or the UserPrincipalName of the User.")]
      [string]
      $Id
  )
  PROCESS {
    if($Id -ne "") {
      Get-AADObjectById -Type "users" -Id $id
    }
    else {
      Get-AADObject -Type "users"
    }
  }
}

Export-ModuleMember –function Connect-AAD, Get-AADUser
