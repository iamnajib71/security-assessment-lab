#Requires -RunAsAdministrator
# Two-hour, local-only helper. No arbitrary command, VM, path or script requests.
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
if($repo -ne 'H:\My Projects - IT\security-assessment-lab') {throw 'Owned workspace guard failed.'}
$private=Join-Path $repo 'private\monitoring'
$null=New-Item -ItemType Directory -Path $private -Force
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$acl=Get-Acl -LiteralPath $private
$acl.SetAccessRuleProtection($true,$false)
foreach($account in @($identity,'BUILTIN\Administrators','NT AUTHORITY\SYSTEM')) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -LiteralPath $private -AclObject $acl
$allowed=@('Inspect','Start','StartDC','StartClient','SaveDC','SaveClient','Firewall','Enroll','PrepareExercises','Exercise','Export','Cleanup')
$deadline=(Get-Date).AddHours(2)
[ordered]@{ready=$true;expires=$deadline.ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content (Join-Path $private 'worker-status.json')
while((Get-Date) -lt $deadline -and -not(Test-Path (Join-Path $private 'worker-stop.flag'))) {
    $request=Join-Path $private 'request.json'
    if(-not(Test-Path $request)) {Start-Sleep -Seconds 2; continue}
    $job=$null
    try {
        $job=Get-Content -LiteralPath $request -Raw | ConvertFrom-Json
        $id=[guid]::Parse([string]$job.id).ToString()
        if($job.action -notin $allowed -or $job.PSObject.Properties.Count -gt 2) {throw 'Unsupported request.'}
        & (Join-Path $PSScriptRoot 'monitoring-host.ps1') -Action $job.action
        [ordered]@{success=$true;action=$job.action;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content (Join-Path $private "$id.json")
    } catch {
        if($job -and $job.id) {
            $safe=[guid]::Empty
            if([guid]::TryParse([string]$job.id,[ref]$safe)) {
                [ordered]@{success=$false;error=$_.Exception.Message;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content (Join-Path $private "$safe.json")
            }
        }
    } finally {Remove-Item -LiteralPath $request -ErrorAction SilentlyContinue}
}
[ordered]@{ready=$false;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content (Join-Path $private 'worker-status.json')
