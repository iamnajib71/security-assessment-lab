#Requires -RunAsAdministrator
# Fixed CLIENT01 console test controls. No host keyboard, shell text or password search.
[CmdletBinding()]
param([ValidateSet('Snapshot','SAS','Tab','Acknowledge','OtherUser','TypeUser','TypeWrong','Submit')][string]$Step='Snapshot')
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$private=Join-Path $repo 'private\monitoring'
$vm=Get-VM -Name CLIENT01
if($vm.State -ne 'Running') {throw 'CLIENT01 must be running.'}
$nic=@(Get-VMNetworkAdapter -VM $vm)
if($nic.Count -ne 1 -or $nic[0].SwitchName -ne 'WindowsADLab-Internal') {throw 'Console target outside the owned lab.'}
$system=Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -Filter "Name='$($vm.Id)'"
$keyboards=@(Get-CimAssociatedInstance -InputObject $system -ResultClassName Msvm_Keyboard)
if($keyboards.Count -ne 1) {throw 'Ambiguous virtual keyboard.'}
$keyboard=$keyboards[0]
function Send-Key([string]$Method,[hashtable]$Arguments=@{}) {
    $result=Invoke-CimMethod -InputObject $keyboard -MethodName $Method -Arguments $Arguments
    if($result.ReturnValue -ne 0) {throw "Virtual keyboard failed: $Method"}
}
switch($Step) {
    'Snapshot' {}
    'SAS' {Send-Key TypeCtrlAltDel}
    'Tab' {Send-Key TypeKey @{keyCode=[uint32]9}}
    {$_ -in @('OtherUser','Acknowledge')} {
        $mouse=@(Get-CimAssociatedInstance -InputObject $system -ResultClassName Msvm_SyntheticMouse)
        if($mouse.Count -ne 1) {throw 'Expected one virtual mouse.'}
        $metadata=Get-CimClass -Namespace root/virtualization/v2 -ClassName Msvm_SyntheticMouse
        $metadata.CimClassMethods | ForEach-Object { [ordered]@{name=$_.Name;parameters=@($_.Parameters.Keys)} } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $private 'mouse-methods.json')
        $display=@(Get-CimAssociatedInstance -InputObject $system -ResultClassName Msvm_SyntheticDisplayController)
        if($display.Count -ne 1) {throw 'Ambiguous virtual display.'}
        $heads=@(Get-CimAssociatedInstance -InputObject $display[0] -ResultClassName Msvm_VideoHead)
        if($heads.Count -ne 1) {throw 'Ambiguous virtual framebuffer size.'}
        $width=[int]$heads[0].CurrentHorizontalResolution;$height=[int]$heads[0].CurrentVerticalResolution
        if($width -lt 640 -or $height -lt 480) {throw 'Invalid virtual display resolution.'}
        $x=if($Step -eq 'Acknowledge'){512}else{130}
        $y=if($Step -eq 'Acknowledge'){528}else{710}
        $position=Invoke-CimMethod -InputObject $mouse[0] -MethodName SetAbsolutePosition -Arguments @{horizontalPosition=[int]($x*$width/1024);verticalPosition=[int]($y*$height/768)}
        if($position.ReturnValue -ne 0) {throw 'Virtual pointer positioning failed.'}
        $click=Invoke-CimMethod -InputObject $mouse[0] -MethodName ClickButton -Arguments @{buttonIndex=[uint32]1}
        if($click.ReturnValue -ne 0) {throw 'Virtual tile selection failed.'}
    }
    'TypeUser' {Send-Key TypeText @{asciiText='CORP\soc.lockout'}}
    'TypeWrong' {Send-Key TypeText @{asciiText='Intentional-SOC-Lab-Wrong-Value!'}}
    'Submit' {
        $counter=Join-Path $private 'console-submissions.txt'
        $count=if(Test-Path $counter){[int](Get-Content $counter -Raw)}else{0}
        if($count -ge 5) {throw 'Five-submission cap reached. No further failed sign-ins are permitted.'}
        ($count+1) | Set-Content $counter
        Send-Key TypeKey @{keyCode=[uint32]13}
    }
}
Start-Sleep -Milliseconds 800
$id=[guid]::NewGuid().ToString()
$capture=Join-Path $private "$id-console.png"
& 'H:\My Projects - IT\windows-ad-lab\scripts\host\Export-LabConsole.ps1' -VMName CLIENT01 -OutputPath $capture -Confirm:$false | Out-Null
[ordered]@{step=$Step;vm='CLIENT01';source='Hyper-V framebuffer and virtual keyboard';capture=$capture;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content (Join-Path $private 'console-result.json')
