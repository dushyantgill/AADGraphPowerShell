##################################################################################################
#                                        Index                                                   #
# Private Functions -----------------------------------------------------------------  Line 7    #
# Exported "Script Cmdlets" Functions -----------------------------------------------  Line 161  #
##################################################################################################

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

function New-AADUser {
  [CmdletBinding()]
  param (
    [parameter(Mandatory=$false,
    HelpMessage="Controls whether the new user account is created enabled or disabled. The default value is true.")]
    [string]
    $accountEnabled = $true, 
    
    [parameter(Mandatory=$true,
    HelpMessage="The name displayed in the address book for the user.")]
    [string]
    $displayName, 
    
    [parameter(Mandatory=$true,
    HelpMessage="The email alias of the new user.")]
    [string]
    $mailNickname, 
    
    [parameter(Mandatory=$true,
    HelpMessage="This is the user name that the new user will use for login. By convention, this should map to the user's email name. The general format is alias@domain, where domain must be present in the tenant’s collection of verified domains.")]
    [string]
    $userPrincipalName, 
    
    [parameter(Mandatory=$true,
    HelpMessage="The display name of the new user.")]
    [string]
    $password, 

    [parameter(Mandatory=$false,
    HelpMessage="Controls whether the new user will be required to change their password at the next interactive login. The default value is true.")]
    [string]
    $forceChangePasswordNextLogin = $true,
    
    [parameter(Mandatory=$false,
    HelpMessage="The city in which the user is located.")]
    [string]
    $city,
    
    [parameter(Mandatory=$false,
    HelpMessage="The country/region in which the user is located.")]
    [string]
    $country,
    
    [parameter(Mandatory=$false,
    HelpMessage="The name for the department in which the user works.")]
    [string]
    $department,
    
    [parameter(Mandatory=$false,
    HelpMessage="Indicates whether this object was synced from the on-premises directory.")]
    [bool]
    $dirSyncEnabled,
    
    [parameter(Mandatory=$false,
    HelpMessage="The telephone number of the user's business fax machine.")]
    [alias("Fax")]
    [string]
    $facsimileTelephoneNumber,
    
    [parameter(Mandatory=$false,
    HelpMessage="The given name of the user.")]
    [alias("FirstName")]
    [string]
    $givenName,
    
    [parameter(Mandatory=$false,
    HelpMessage="The user’s job title.")]
    [string]
    $jobTitle,
    
    [parameter(Mandatory=$false,
    HelpMessage="The emailaddress for the user, for example, 'jeff@contoso.onmicrosoft.com'.")]
    [alias("Email","EmailAddress")]
    [string]
    $mail,
    
    [parameter(Mandatory=$false,
    HelpMessage="The primary cellular telephone number for the user.")]
    [string]
    $mobile,
    
    [parameter(Mandatory=$false,
    HelpMessage="A list of additional email addresses for the user.")]
    [string[]]
    $otherMails,
    
    [parameter(Mandatory=$false,
    HelpMessage="Specifies password policies for the user, with one possible value being 'DisableStrongPassword', which allows weaker passwords than the default policy to be specified.")]
    [ValidateSet("DisableStrongPassword")] 
    [string]
    $passwordPolicies,

    [parameter(Mandatory=$false,
    HelpMessage="The office location in the user's place of business.")]
    [alias("Office")]
    [string]
    $physicalDeliveryOfficeName,
    
    [parameter(Mandatory=$false,
    HelpMessage="The postal code in the user's postal address.")]
    [alias("ZipCode")]
    [string]
    $postalCode,
    
    [parameter(Mandatory=$false,
    HelpMessage="The preferred language for the user.")]
    [string]
    $preferredLanguage,
    
    [parameter(Mandatory=$false,
    HelpMessage="The state or province in the user's postal address.")]
    [string]
    $state,      

    [parameter(Mandatory=$false,
    HelpMessage="The street address in the user's postal address.")]
    [string]
    $streetAddress,
    
    [parameter(Mandatory=$false,
    HelpMessage="The user's surname (family name or last name).")]
    [alias("LastName","FamilyName")]
    [string]
    $surname,
    
    [parameter(Mandatory=$false,
    HelpMessage="The telephone number of the user.")]
    [string]
    $telephoneNumber,
    
    [parameter(Mandatory=$false,
    HelpMessage="A thumbnail photo to be displayed for the user.")]
    [alias("Photo")]
    [byte[]]
    $thumbnailPhoto,

    [parameter(Mandatory=$false,
    HelpMessage="Not sure what this is :).")]
    [string]
    $usageLocation
  )
  PROCESS {
    # Mandatory properties of a new User
    $newUserPasswordProfile = "" | Select password, forceChangePasswordNextLogin
    $newUserPasswordProfile.password = $password
    $newUserPasswordProfile.forceChangePasswordNextLogin = $forceChangePasswordNextLogin
    
    $newUser = "" | Select accountEnabled, displayName, mailNickname, passwordProfile, userPrincipalName
    $newUser.accountEnabled = $accountEnabled
    $newUser.displayName = $displayName
    $newUser.mailNickname = $mailNickname
    $newUser.passwordProfile = $newUserPasswordProfile
    $newUser.userPrincipalName = $userPrincipalName
           
    #Optional parameters/properties
    foreach($psbp in $PSBoundParameters.GetEnumerator()){
      $key = $psbp.Key
      $value = $psbp.Value
      if($key -eq "city" -or $key -eq "country" -or $key -eq "department" -or $key -eq "dirSyncEnabled" -or $key -eq "facsimileTelephoneNumber" -or `
      $key -eq "givenName" -or $key -eq "jobTitle" -or $key -eq "mail" -or $key -eq "mobile" -or $key -eq "otherMails" -or `
      $key -eq "passwordPolicies" -or $key -eq "physicalDeliveryOfficeName" -or $key -eq "postalCode" -or $key -eq "preferredLanguage" -or `
      $key -eq "state" -or $key -eq "streetAddress" -or $key -eq "surname" -or $key -eq "telephoneNumber"  -or $key -eq "thumbnailPhoto" -or $key -eq "usageLocation") {
        Add-Member -InputObject $newUser –MemberType NoteProperty –Name $key –Value $value
      }
    }
    
    New-AADObject -Type users -Object $newUser
  }
}

function Remove-AADUser {
  [CmdletBinding()]
  param (
    [parameter(Mandatory=$true,
    ValueFromPipeline=$true,
    HelpMessage="Either the ObjectId or the UserPrincipalName of the User.")]
    [string]
    $Id
  )
  PROCESS {
    Remove-AADObject -Type "users" -Id $id
  }
}

function Set-AADUser {
  [CmdletBinding()]
  param (
    [parameter(Mandatory=$true,
    ValueFromPipeline=$true,
    HelpMessage="Either the ObjectId or the UserPrincipalName of the User.")]
    [string]
    $Id,
    
    [parameter(Mandatory=$false, 
    HelpMessage="Controls whether the user account is enabled or disabled. The default value is true.")]
    [string]
    $accountEnabled, 
    
    [parameter(Mandatory=$false,
    HelpMessage="The name displayed in the address book for the user. DisplayName can't be cleared on update.")]
    [string]
    $displayName, 
    
    [parameter(Mandatory=$false,
    HelpMessage="The email alias of the user.")]
    [string]
    $mailNickname, 
    
    [parameter(Mandatory=$false,
    HelpMessage="This is the user name that the user will use for login. By convention, this should map to the user's email name. The general format is alias@domain, where domain must be present in the tenant's collection of verified domains.")]
    [string]
    $userPrincipalName, 
    
    [parameter(Mandatory=$false,
    HelpMessage="The password of the user account.")]
    [string]
    $password, 

    [parameter(Mandatory=$false,
    HelpMessage="If a new password is specified, this parameter controls whether the user will be required to change their password at the next interactive login. The default value is true.")]
    [string]
    $forceChangePasswordNextLogin = $true,
    
    [parameter(Mandatory=$false,
    HelpMessage="The city in which the user is located.")]
    [string]
    $city,
    
    [parameter(Mandatory=$false,
    HelpMessage="The country/region in which the user is located.")]
    [string]
    $country,
    
    [parameter(Mandatory=$false,
    HelpMessage="The name for the department in which the user works.")]
    [string]
    $department,
    
    [parameter(Mandatory=$false,
    HelpMessage="Indicates whether this object was synced from the on-premises directory.")]
    [bool]
    $dirSyncEnabled,
    
    [parameter(Mandatory=$false,
    HelpMessage="The telephone number of the user's business fax machine.")]
    [alias("Fax")]
    [string]
    $facsimileTelephoneNumber,
    
    [parameter(Mandatory=$false,
    HelpMessage="The given name of the user.")]
    [alias("FirstName")]
    [string]
    $givenName,
    
    [parameter(Mandatory=$false,
    HelpMessage="The user's job title.")]
    [string]
    $jobTitle,
    
    [parameter(Mandatory=$false,
    HelpMessage="The emailaddress for the user, for example, 'jeff@contoso.onmicrosoft.com'.")]
    [alias("Email","EmailAddress")]
    [string]
    $mail,
    
    [parameter(Mandatory=$false,
    HelpMessage="The primary cellular telephone number for the user.")]
    [string]
    $mobile,
    
    [parameter(Mandatory=$false,
    HelpMessage="A list of additional email addresses for the user.")]
    [string[]]
    $otherMails,
    
    [parameter(Mandatory=$false,
    HelpMessage="Specifies password policies for the user, with one possible value being 'DisableStrongPassword', which allows weaker passwords than the default policy to be specified.")]
    [ValidateSet("DisableStrongPassword")] 
    [string]
    $passwordPolicies,

    [parameter(Mandatory=$false,
    HelpMessage="The office location in the user's place of business.")]
    [alias("Office")]
    [string]
    $physicalDeliveryOfficeName,
    
    [parameter(Mandatory=$false,
    HelpMessage="The postal code in the user's postal address.")]
    [alias("ZipCode")]
    [string]
    $postalCode,
    
    [parameter(Mandatory=$false,
    HelpMessage="The preferred language for the user.")]
    [string]
    $preferredLanguage,
    
    [parameter(Mandatory=$false,
    HelpMessage="The state or province in the user's postal address.")]
    [string]
    $state,      

    [parameter(Mandatory=$false,
    HelpMessage="The street address in the user's postal address.")]
    [string]
    $streetAddress,
    
    [parameter(Mandatory=$false,
    HelpMessage="The user's surname (family name or last name).")]
    [alias("LastName","FamilyName")]
    [string]
    $surname,
    
    [parameter(Mandatory=$false,
    HelpMessage="The telephone number of the user.")]
    [string]
    $telephoneNumber,
    
    [parameter(Mandatory=$false,
    HelpMessage="A thumbnail photo to be displayed for the user.")]
    [alias("Photo")]
    [byte[]]
    $thumbnailPhoto,

    [parameter(Mandatory=$false,
    HelpMessage="Not sure what this is :).")]
    [string]
    $usageLocation
  )
  PROCESS {
    # Mandatory properties of a new User
    #$newUserPasswordProfile = "" | Select password, forceChangePasswordNextLogin
    #$newUserPasswordProfile.password = $password
    #$newUserPasswordProfile.forceChangePasswordNextLogin = $forceChangePasswordNextLogin
    
    $updatedUser = "" | Select accountEnabled, displayName, mailNickname, userPrincipalName
    $updatedUser.accountEnabled = $accountEnabled
    $updatedUser.displayName = $displayName
    $updatedUser.mailNickname = $mailNickname
    $updatedUser.passwordProfile = $newUserPasswordProfile
    $updatedUser.userPrincipalName = $userPrincipalName
           
    #Optional parameters/properties
    foreach($psbp in $PSBoundParameters.GetEnumerator()){
      $key = $psbp.Key
      $value = $psbp.Value
      if($key -eq "accountEnabled" -or $key -eq "displayName" -or $key -eq "mailNickname" -or $key -eq "userPrincipalName" -or `
      $key -eq "city" -or $key -eq "country" -or $key -eq "department" -or $key -eq "dirSyncEnabled" -or $key -eq "facsimileTelephoneNumber" -or `
      $key -eq "givenName" -or $key -eq "jobTitle" -or $key -eq "mail" -or $key -eq "mobile" -or $key -eq "otherMails" -or `
      $key -eq "passwordPolicies" -or $key -eq "physicalDeliveryOfficeName" -or $key -eq "postalCode" -or $key -eq "preferredLanguage" -or `
      $key -eq "state" -or $key -eq "streetAddress" -or $key -eq "surname" -or $key -eq "telephoneNumber"  -or $key -eq "thumbnailPhoto" -or $key -eq "usageLocation") {
        Add-Member -InputObject $newUser -MemberType NoteProperty -Name $key -Value $value
      }
    }
    if($PSBoundParameters.ContainsKey('password'){
      $updatedUserPasswordProfile = "" | Select password, forceChangePasswordNextLogin
      $updatedUserPasswordProfile.password = $PSBoundParameters['password'].Value
      $updatedUserPasswordProfile.forceChangePasswordNextLogin = $forceChangePasswordNextLogin
      $updatedUser.passwordProfile = $updatedUserPasswordProfile
    }
    
    Set-AADObject -Type users -Id $Id -Object $updatedUser
}

Export-ModuleMember -function Connect-AAD, Get-AADUser, New-AADUser, Remove-AADUser, Set-AADUser
