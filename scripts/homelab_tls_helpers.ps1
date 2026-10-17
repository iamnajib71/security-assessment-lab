
# TLS adapter: explicit lab CA validation without global certificate bypasses.
function Invoke-LabWebRequest {
    param([string]$Uri, [string]$Method='GET', [string]$Body, [string]$ContentType, $Headers, $WebSession, [switch]$UseBasicParsing, [int]$TimeoutSec=30, [switch]$AllowError)
    $r = @{url=$Uri; method=$Method; body=$Body; content_type=$ContentType; headers=$Headers; cookie_jar=$null}
    if ($WebSession) { $r.cookie_jar = $WebSession.CookieJar }
    $inputJson = $r | ConvertTo-Json -Depth 5 -Compress
    $raw = $inputJson | & python (Join-Path $PSScriptRoot 'tls_http.py')
    if ($LASTEXITCODE -ne 0) { throw 'TLS request failed; no insecure fallback is allowed' }
    $response = $raw | ConvertFrom-Json
    if (-not $AllowError -and $response.StatusCode -ge 400) { throw ('HTTP ' + $response.StatusCode) }
    return $response
}
function Invoke-LabRestMethod {
    param([string]$Uri, [string]$Method='GET', [string]$Body, [string]$ContentType, $WebSession)
    $response = Invoke-LabWebRequest -Uri $Uri -Method $Method -Body $Body -ContentType $ContentType -WebSession $WebSession
    if ($response.Content) { return ($response.Content | ConvertFrom-Json) }
}
