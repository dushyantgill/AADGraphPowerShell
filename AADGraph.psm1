function Load-ActiveDirectoryAuthenticationLibrary(){
  $moduleDirPath = ($ENV:PSModulePath -split ';')[0]
  $modulePath = $moduleDirPath + "\AADGraph"
  if(-not (Test-Path ($modulePath+"\Nugets"))) {New-Item -Path ($modulePath+"\Nugets") -ItemType "Directory" | out-null}
  $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)
  if($adalPackageDirectories.Length -eq 0){
    Write-Host "Active Directory Authentication Library Nuget doesn't exist. Downloading now ..." -ForegroundColor Yellow
    if(-not(Test-Path ($modulePath + "\Nugets\nuget.exe")))
    {
      Write-Host "nuget.exe not found. Downloading from http://www.nuget.org/nuget.exe ..." -ForegroundColor Yellow
      $wc = New-Object System.Net.WebClient
      $wc.DownloadFile("http://www.nuget.org/nuget.exe",$modulePath + "\Nugets\nuget.exe");
    }
    $nugetDownloadExpression = $modulePath + "\Nugets\nuget.exe install Microsoft.IdentityModel.Clients.ActiveDirectory -OutputDirectory " + $modulePath + "\Nugets | out-null"
    Invoke-Expression $nugetDownloadExpression
  }
  $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)
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
    Write-Host "Not able to load ADAL assembly. Delete the Nugets folder under" $modulePath ", restart PowerShell session and try again ..."
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

function Connect-AAD {
  PROCESS {
    $global:authenticationResult = $null
    $global:authenticationResult = Get-AuthenticationResult
  }
}

Load-ActiveDirectoryAuthenticationLibrary