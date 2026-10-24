#Requires -RunAsAdministrator
[CmdletBinding()]
param([ValidateSet('Inspect','Start','StartDC','StartClient','SaveDC','SaveClient','Firewall','Enroll','PrepareExercises','Exercise','Export','Cleanup')][string]$Action='Inspect')
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$private=Join-Path $repo 'private\monitoring'
$null=New-Item -ItemType Directory -Path $private -Force
$scope=Get-Content (Join-Path $repo 'monitoring\scope.json') -Raw | ConvertFrom-Json
$result=Join-Path $private "$Action-result.json"
try {
    # No arbitrary VM, domain, account, target address or script input is accepted.
    if($scope.adlab_path -ne 'H:\My Projects - IT\windows-ad-lab' -or $scope.domain -ne 'corp.lab' -or $scope.hyperv_switch -ne 'WindowsADLab-Internal') {throw 'Pinned ownership contract changed.'}
    $vms=@(Get-VM -Name DC01,CLIENT01)
    if($vms.Count -ne 2) {throw 'Both named owned VMs are required.'}
    foreach($vm in $vms) {
        $nics=@(Get-VMNetworkAdapter -VM $vm)
        if($nics.Count -ne 1 -or $nics[0].SwitchName -ne 'WindowsADLab-Internal') {throw 'VM network outside owned internal switch.'}
        foreach($disk in @(Get-VMHardDiskDrive -VM $vm)) {
            if($disk.Path -notlike 'E:\WindowsADLab\*' -and $disk.Path -notlike 'H:\My Projects - IT\windows-ad-lab\.lab\*') {throw 'VM disk outside owned lab storage.'}
        }
    }
    if((Get-VMSwitch -Name WindowsADLab-Internal).SwitchType -ne 'Internal') {throw 'Lab switch must be internal.'}
    if(-not(Get-NetIPAddress -IPAddress 192.168.77.1 -ErrorAction SilentlyContinue)) {throw 'Missing pinned manager interface.'}
    if($Action -eq 'Inspect') {
        $guestChecks=@()
        $storedInspect=Import-Clixml (Join-Path $scope.adlab_path '.lab\credentials\dc.xml')
        $inspectCred=[pscredential]::new('CORP\Administrator',$storedInspect.Password)
        foreach($vm in @($vms | Where-Object State -eq 'Running')) {
            $guestChecks+=Invoke-Command -VMName $vm.Name -Credential $inspectCred {
                $network=[Net.Sockets.TcpClient]::new()
                $connected=$false
                try {$attempt=$network.BeginConnect('192.168.77.1',1514,$null,$null); if($attempt.AsyncWaitHandle.WaitOne(3000)) {$network.EndConnect($attempt);$connected=$network.Connected}} catch {} finally {$network.Dispose()}
                [ordered]@{computer=$env:COMPUTERNAME;manager_tcp=$connected;agent_log=if(Test-Path 'C:\Program Files (x86)\ossec-agent\ossec.log'){@(Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 18 | ForEach-Object {[string]$_})}else{@()}} | ConvertTo-Json -Depth 4 | Set-Content C:\SocLab\connection-inspection.json
                $agent=Get-Service WazuhSvc -ErrorAction SilentlyContinue
                $sysmon=Get-Service Sysmon64 -ErrorAction SilentlyContinue
                [ordered]@{computer=$env:COMPUTERNAME;agent=if($agent){$agent.Status.ToString()}else{'Absent'};sysmon=if($sysmon){$sysmon.Status.ToString()}else{'Absent'};key_staged=(Test-Path C:\SocLab\agent.key);binary_created=if(Test-Path 'C:\Program Files (x86)\ossec-agent\wazuh-agent.exe'){(Get-Item 'C:\Program Files (x86)\ossec-agent\wazuh-agent.exe').CreationTimeUtc.ToString('o')}else{$null};agent_service_events=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue | Where-Object Message -Match '(?i)wazuh' | Select-Object TimeCreated,Id,Message)}
            }
        }
        $guestChecks | ConvertTo-Json -Depth 7 | Set-Content (Join-Path $private 'guest-inspection.json')
        foreach($vm in @($vms | Where-Object State -eq 'Running')) {
            $connection=Invoke-Command -VMName $vm.Name -Credential $inspectCred {Get-Content C:\SocLab\connection-inspection.json -Raw}
            $connection | Set-Content (Join-Path $private "$($vm.Name)-connection.json")
        }
        [ordered]@{success=$true;action=$Action;vms=@($vms | Select-Object Name,State,MemoryAssigned);free_memory_bytes=(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory*1KB;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $result
        return
    }
    if($Action -in @('SaveDC','SaveClient')) {
        $name=if($Action -eq 'SaveDC') {'DC01'} else {'CLIENT01'}
        if((Get-VM $name).State -eq 'Running') {Save-VM -Name $name}
        [ordered]@{success=$true;action=$Action;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $result
        return
    }
    if($Action -in @('Start','StartDC','StartClient')) {
        $names=if($Action -eq 'StartDC') {@('DC01')} elseif($Action -eq 'StartClient') {@('CLIENT01')} else {@('DC01','CLIENT01')}
        & (Join-Path $scope.adlab_path 'scripts\host\Start-Lab.ps1') -VMName $names -Confirm:$false
        if($Action -eq 'StartClient') {
            $consoleRequest=Join-Path $private 'console-request.json'
            $step='Snapshot'
            if(Test-Path $consoleRequest) {$step=(Get-Content $consoleRequest -Raw | ConvertFrom-Json).step}
            & (Join-Path $PSScriptRoot 'monitoring-console.ps1') -Step $step
            Remove-Item -LiteralPath $consoleRequest -ErrorAction SilentlyContinue
        }
        [ordered]@{success=$true;action=$Action;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $result
        return
    }
    $stored=Import-Clixml (Join-Path $scope.adlab_path '.lab\credentials\dc.xml')
    $credential=[pscredential]::new('CORP\Administrator',$stored.Password)
    $sessions=@{}
    try {
        $running=@($vms | Where-Object State -eq 'Running')
        if(-not $running.Count) {throw 'Start a named owned VM with the guarded Start action first.'}
        foreach($vm in $running) {
            $sessions[$vm.Name]=New-PSSession -VMName $vm.Name -Credential $credential
            Invoke-Command -Session $sessions[$vm.Name] {
                $cs=Get-CimInstance Win32_ComputerSystem
                if($env:COMPUTERNAME -notin @('DC01','CLIENT01') -or $cs.Domain -ne 'corp.lab') {throw 'Guest identity mismatch.'}
                Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
            }
        }
        if($Action -eq 'Firewall') {
            $lease=Invoke-Command -Session $sessions.CLIENT01 { @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -Like '192.168.77.*').IPAddress }
            if(@($lease).Count -ne 1 -or [int]($lease.Split('.')[-1]) -lt 100 -or [int]($lease.Split('.')[-1]) -gt 150) {throw 'CLIENT01 address outside owned DHCP scope.'}
            $allowed=@('192.168.77.10',[string]$lease)
            $inventory=[ordered]@{DC01='192.168.77.10';CLIENT01=[string]$lease;switch='WindowsADLab-Internal';domain='corp.lab';time=(Get-Date).ToUniversalTime().ToString('o')}
            $inventory | ConvertTo-Json | Set-Content (Join-Path $private 'inventory.json')
            # Explicit block ranges defeat broader Docker allow rules. Port 1515 is never published.
            $last=[int]($lease.Split('.')[-1])
            $blocked=@('0.0.0.0-192.168.77.9',("192.168.77.11-192.168.77.$($last-1)"),("192.168.77.$($last+1)-255.255.255.255"))
            Get-NetFirewallRule -Group 'SOC owned lab' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            New-NetFirewallRule -DisplayName 'SOC owned lab agents' -Group 'SOC owned lab' -Direction Inbound -Action Allow -Protocol TCP -LocalAddress 192.168.77.1 -LocalPort 1514 -RemoteAddress $allowed | Out-Null
            New-NetFirewallRule -DisplayName 'SOC refuse all other sources' -Group 'SOC owned lab' -Direction Inbound -Action Block -Protocol TCP -LocalAddress 192.168.77.1 -LocalPort 1514 -RemoteAddress $blocked | Out-Null
            [ordered]@{success=$true;action=$Action;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $result
            return
        }
        if($Action -eq 'Enroll') {
            foreach($name in @('DC01','CLIENT01') | Where-Object {$sessions.ContainsKey($_)}) {
                $session=$sessions[$name]
                Invoke-Command -Session $session { New-Item -ItemType Directory C:\SocLab -Force | Out-Null }
                Copy-Item (Join-Path $private 'downloads\wazuh-agent.msi') -Destination C:\SocLab\wazuh-agent.msi -ToSession $session
                Copy-Item (Join-Path $private 'downloads\Sysmon64.exe') -Destination C:\SocLab\Sysmon64.exe -ToSession $session
                Copy-Item (Join-Path $repo 'monitoring\sysmon.xml') -Destination C:\SocLab\sysmon.xml -ToSession $session
                Copy-Item (Join-Path $private "$name.key") -Destination C:\SocLab\agent.key -ToSession $session
                $agentConf=Get-Content (Join-Path $repo 'monitoring\windows-agent.conf') -Raw
                Invoke-Command -Session $session -ArgumentList $name,$agentConf {
                    param($name,$agentConf)
                    foreach($file in @('C:\SocLab\wazuh-agent.msi','C:\SocLab\Sysmon64.exe')) {
                        $sig=Get-AuthenticodeSignature -FilePath $file
                        $publisher=if($file -like '*.msi') {'Wazuh'} else {'Microsoft Windows Publisher'}
                        if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch $publisher) {throw 'Installer signature invalid.'}
                    }
                    $agentHome='C:\Program Files (x86)\ossec-agent'
                    if((Get-Service WazuhSvc -ErrorAction SilentlyContinue) -and (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
                        $expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content C:\SocLab\agent.key -Raw).Trim())).Trim()
                        $current=(Get-Content "$agentHome\client.keys" -Raw).Trim()
                        if($current -ne $expected -or (Get-Content "$agentHome\ossec.conf" -Raw) -notmatch '<address>192.168.77.1</address>') {throw 'Existing installation differs from this lab enrolment; refusing overwrite.'}
                        Remove-Item -LiteralPath C:\SocLab\agent.key
                        [ordered]@{computer=$env:COMPUTERNAME;agent=(Get-Service WazuhSvc).Status.ToString();sysmon=(Get-Service Sysmon64).Status.ToString();resumed=$true}
                        return
                    }
                    if(Get-Service WazuhSvc -ErrorAction SilentlyContinue) {
                        # Resume only our freshly installed, not-yet-enrolled lab MSI.
                        $recentInstall=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue | Where-Object Message -Match '(?i)ossec-agent\\wazuh-agent\.exe')
                        if(-not(Test-Path C:\SocLab\agent.key) -or $recentInstall.Count -ne 1 -or (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {throw 'Existing agent: inspect and migrate manually; refusing overwrite.'}
                    } else {
                        $p=Start-Process msiexec.exe -ArgumentList '/i C:\SocLab\wazuh-agent.msi /qn /norestart' -PassThru -Wait
                        if($p.ExitCode -notin @(0,3010)) {throw "MSI failed: $($p.ExitCode)"}
                    }
                    Stop-Service WazuhSvc -ErrorAction SilentlyContinue
                    $key=(Get-Content C:\SocLab\agent.key -Raw).Trim()
                    'y' | & "$agentHome\manage_agents.exe" -i $key | Out-Null
                    if($LASTEXITCODE -ne 0) {throw 'Agent key import failed.'}
                    if(-not((Get-Content "$agentHome\client.keys" -Raw) -match "(?m)^\d+ $name any [0-9a-f]+")) {throw 'Imported key identity does not match the named lab VM.'}
                    Remove-Item -LiteralPath C:\SocLab\agent.key
                    $config=[xml]('<ossec_config><client><server><address>192.168.77.1</address><port>1514</port><protocol>tcp</protocol></server><enrollment><enabled>no</enabled></enrollment></client><active-response><disabled>yes</disabled></active-response></ossec_config>')
                    $shared=[xml]$agentConf
                    foreach($lf in @($shared.agent_config.localfile)) {$null=$config.DocumentElement.AppendChild($config.ImportNode($lf,$true))}
                    $config.Save("$agentHome\ossec.conf")
                    if(Get-Service Sysmon64 -ErrorAction SilentlyContinue) {throw 'Existing Sysmon: inspect and merge configuration manually.'}
                    $sysmonProcess=Start-Process -FilePath C:\SocLab\Sysmon64.exe -ArgumentList '-accepteula -i C:\SocLab\sysmon.xml' -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput C:\SocLab\sysmon-install.stdout -RedirectStandardError C:\SocLab\sysmon-install.stderr
                    if($sysmonProcess.ExitCode -ne 0) {throw 'Sysmon installation failed; inspect guest private installer logs.'}
                    Start-Service WazuhSvc
                    [ordered]@{computer=$env:COMPUTERNAME;agent=(Get-Service WazuhSvc).Status.ToString();sysmon=(Get-Service Sysmon64).Status.ToString()}
                } | ConvertTo-Json | Set-Content (Join-Path $private "$name-enrollment.json")
            }
        } else {
            $guestScript=Join-Path $repo 'scripts\monitoring-guest.ps1'
            foreach($name in @('DC01','CLIENT01') | Where-Object {$sessions.ContainsKey($_)}) {
                Invoke-Command -Session $sessions[$name] { New-Item -ItemType Directory C:\SocLab -Force | Out-Null }
                Copy-Item $guestScript -Destination C:\SocLab\monitoring-guest.ps1 -ToSession $sessions[$name]
                if($Action -eq 'Cleanup') {
                    Copy-Item (Join-Path $repo 'monitoring\sysmon.xml') -Destination C:\SocLab\sysmon.xml -ToSession $sessions[$name]
                    Invoke-Command -Session $sessions[$name] {
                        $p=Start-Process C:\SocLab\Sysmon64.exe -ArgumentList '-c C:\SocLab\sysmon.xml' -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput C:\SocLab\sysmon-update.stdout -RedirectStandardError C:\SocLab\sysmon-update.stderr
                        if($p.ExitCode -ne 0) {throw 'Sysmon configuration update failed.'}
                        $configPath='C:\Program Files (x86)\ossec-agent\ossec.conf'
                        $config=[xml](Get-Content $configPath -Raw)
                        $lf=@($config.ossec_config.localfile | Where-Object location -eq 'Microsoft-Windows-Sysmon/Operational')
                        if($lf.Count -ne 1) {throw 'Unexpected Sysmon collector configuration.'}
                        $query=$config.CreateElement('query');$query.InnerText='Event/System[EventID=1 or EventID=4 or EventID=11 or EventID=16]'
                        $oldQuery=$lf[0].SelectSingleNode('query');if($oldQuery){$null=$lf[0].RemoveChild($oldQuery)}
                        $null=$lf[0].AppendChild($query);$config.Save($configPath)
                        Restart-Service WazuhSvc
                    }
                }
                $password=$null
                if($Action -in @('PrepareExercises','Exercise')) {
                    $line=Get-Content (Join-Path $repo '.env') | Where-Object {$_ -like 'LAB_ACCOUNT_PASSWORD=*'}
                    $password=ConvertTo-SecureString $line.Substring('LAB_ACCOUNT_PASSWORD='.Length) -AsPlainText -Force
                }
                Invoke-Command -Session $sessions[$name] -ArgumentList $Action,$password {param($action,$password) & C:\SocLab\monitoring-guest.ps1 -Action $action -AccountPassword $password}
                if($Action -eq 'Cleanup') {Copy-Item C:\SocLab\cleanup-checks.json -Destination (Join-Path $private "$name-cleanup-checks.json") -FromSession $sessions[$name]}
                if($Action -eq 'Export') {
                    foreach($file in @('events.jsonl','actions.jsonl','prepared.txt')) {
                        Copy-Item "C:\SocLab\$file" -Destination (Join-Path $private "$name-$file") -FromSession $sessions[$name]
                    }
                    if($name -eq 'DC01') {
                        Copy-Item C:\SocLab\lockout-policy.json -Destination (Join-Path $private 'lockout-policy.json') -FromSession $sessions[$name]
                        Copy-Item C:\SocLab\account-state.json -Destination (Join-Path $private 'account-state.json') -FromSession $sessions[$name]
                    }
                }
            }
        }
    } finally {foreach($s in $sessions.Values) {Remove-PSSession $s}}
    [ordered]@{success=$true;action=$Action;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $result
} catch {
    [ordered]@{success=$false;action=$Action;error=$_.Exception.Message;position=$_.InvocationInfo.PositionMessage;stack=$_.ScriptStackTrace;time=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $result
    throw
}
