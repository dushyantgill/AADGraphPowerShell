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
    Write-Host $body -ForegroundColor Cyan
    $byteArray = $enc.GetBytes($body)
    $contentLength = $byteArray.Length
    $headers = @{"Authorization"=$header;"Content-Type"="application/json";"Content-Length"=$contentLength}
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
    Write-Host $body -ForegroundColor Cyan
    $byteArray = $enc.GetBytes($body)
    $contentLength = $byteArray.Length
    $headers = @{"Authorization"=$header;"Content-Type"="application/json";"Content-Length"=$contentLength}
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