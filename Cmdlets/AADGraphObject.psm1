function Get-AADObject([string]$type) {
  $objects = $null
  if($authenticationResult -ne $null){
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}?api-version=2013-04-05",$authenticationResult.TenantId, $type)
    Write-Host HTTP GET $uri -ForegroundColor Cyan
    $result = Invoke-WebRequest -Method Get -Uri $uri -Headers @{"Authorization"=$header;"Content-Type"="application/json"}
    if($result.StatusCode -eq 200)
    {
      Write-Host "Get succeeded." -ForegroundColor Cyan
      $json = (ConvertFrom-Json $result.Content)
      if($json -ne $null){$objects = $json.value}
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
    $result = Invoke-WebRequest -Method Get -Uri $uri -Headers @{"Authorization"=$header;"Content-Type"="application/json"}
    if($result.StatusCode -eq 200)
    {
      Write-Host "Get succeeded." -ForegroundColor Cyan
      $object = (ConvertFrom-Json $result.Content)
    }
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
    $result = Invoke-WebRequest -Method Post -Uri $uri -Headers $headers -Body $body
    if($result.StatusCode -eq 201)
    {
      Write-Host "Create succeeded." -ForegroundColor Cyan
      $newObject = (ConvertFrom-Json $result.Content)
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD."
  }
  return $newObject
}

function Set-AADObject([string]$type, [string]$id, [object]$object) {
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
    $result = Invoke-WebRequest -Method Patch -Uri $uri -Headers $headers -Body $body
    if($result.StatusCode -eq 204)
    {
      Write-Host "Update succeeded." -ForegroundColor Cyan
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
}

function Remove-AADObject([string]$type, [string]$id) {
  if($global:authenticationResult -ne $null) {
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}?api-version=2013-04-05",$authenticationResult.TenantId, $type, $id)
    Write-Host HTTP DELETE $uri -ForegroundColor Cyan
    $headers = @{"Authorization"=$header;"Content-Type"="application/json"}
    $result = Invoke-WebRequest -Method Delete -Uri $uri -Headers $headers
    if($result.StatusCode -eq 204)
    {
      Write-Host "Delete succeeded." -ForegroundColor Cyan
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
}

function Get-AADLinkedObject([string]$type, [string] $id, [string]$relationship, [bool]$getLinksOnly) {
  $objects = $null
  if($global:authenticationResult -ne $null){
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = $null
    if($getLinksOnly) {$uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}/$links/{3}?api-version=2013-04-05",$authenticationResult.TenantId, $type, $id, $relationship)}
    else {$uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}/{3}?api-version=2013-04-05",$authenticationResult.TenantId, $type, $id, $relationship)}
    Write-Host HTTP GET $uri -ForegroundColor Cyan
    $result = Invoke-WebRequest -Method Get -Uri $uri -Headers @{"Authorization"=$header;"Content-Type"="application/json"}
    if($result.StatusCode -eq 200)
    {
      Write-Host "Get succeeded." -ForegroundColor Cyan
      $json = (ConvertFrom-Json $result.Content)
      if($json -ne $null){$objects = $json.value}
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
  return $objects
}

function Set-AADObjectProperty([string]$type, [string] $id, [string]$property, [object]$value, [bool]$isLinked, [string]$contentType) {
  if($global:authenticationResult -ne $null) {
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = $null
    if($isLinked) {$uri = [string]::Format('https://graph.windows.net/{0}/{1}/{2}/$links/{3}?api-version=2013-04-05',$authenticationResult.TenantId, $type, $id, $property)}
    else {$uri = [string]::Format('https://graph.windows.net/{0}/{1}/{2}/{3}?api-version=2013-04-05',$authenticationResult.TenantId, $type, $id, $property)}
    Write-Host HTTP PUT $uri -ForegroundColor Cyan

    $body = $null
    $byteArray = $null
    
    if($contentType.Trim() -eq "" -or $contentType -eq $null -or $contentType.ToLower() -eq "application/json") {
      $contentType = "application/json"
      $enc = New-Object "System.Text.ASCIIEncoding"
      $body = ConvertTo-Json -InputObject $value
      $byteArray = $enc.GetBytes($body)
      Write-Host $body -ForegroundColor Cyan
    }
    elseif ($contentType.ToLower() -eq "image/jpeg" -or $contentType.ToLower() -eq "image/png" -or $contentType.ToLower() -eq "image/gif") {
      $contentType = $contentType.ToLower()
      $body = $value
      $byteArray = $value
      Write-Host "Body of the request is binary data." -ForegroundColor Cyan
    }
    $contentLength = $byteArray.Length
    $headers = @{"Authorization"=$header;"Content-Type"=$contentType;"Content-Length"=$contentLength}
    $result = Invoke-WebRequest -Method Put -Uri $uri -Headers $headers -Body $body
    if($result.StatusCode -eq 204)
    {
      Write-Host "Update succeeded." -ForegroundColor Cyan
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
}