# Run only through monitoring-host.ps1 / PowerShell Direct in the two owned guests.
[CmdletBinding()]
param([ValidateSet('PrepareExercises','Exercise','Export','Cleanup')][string]$Action,[securestring]$AccountPassword)
$ErrorActionPreference='Stop'
$cs=Get-CimInstance Win32_ComputerSystem
if($env:COMPUTERNAME -notin @('DC01','CLIENT01') -or $cs.Domain -ne 'corp.lab') {throw 'Owned guest/domain guard failed.'}
$root='C:\SocLab'
$null=New-Item -ItemType Directory -Path $root -Force
$accounts=@('soc.privilege','soc.lockout','soc.disabled','soc.share')
function Record-Action([string]$Name,[string]$Result) {
    [ordered]@{time=(Get-Date).ToUniversalTime().ToString('o');computer=$env:COMPUTERNAME;action=$Name;result=$Result} | ConvertTo-Json -Compress | Add-Content -LiteralPath "$root\actions.jsonl"
}
if($Action -eq 'PrepareExercises') {
    if(Test-Path "$root\prepared.txt") {
        if(-not(Test-Path "$root\audit-original.csv")) {throw 'Prepared marker without audit backup; inspect manually.'}
        if($env:COMPUTERNAME -eq 'DC01') {
            Import-Module ActiveDirectory
            foreach($account in $accounts) {
                $existing=Get-ADUser $account -Properties Description
                if($existing.DistinguishedName -notlike 'CN=*,OU=SOC Lab,DC=corp,DC=lab' -or $existing.Description -ne 'Fictional SOC lab account; no real person') {throw 'Prepared resources differ; refusing to change them.'}
            }
        }
        Record-Action 'prepare-resume' 'Existing owned preparation retained without resetting its audit baseline'
        return
    }
    & auditpol.exe /backup /file:C:\SocLab\audit-original.csv | Out-Null
    if($LASTEXITCODE -ne 0) {throw 'Audit backup failed.'}
    foreach($subcategory in @('Logon','User Account Management','Security Group Management','Security System Extension','Other Object Access Events','Audit Policy Change','Detailed File Share')) {
        & auditpol.exe /set "/subcategory:$subcategory" /success:enable /failure:enable | Out-Null
        if($LASTEXITCODE -ne 0) {throw "Audit configuration failed: $subcategory"}
    }
    if($env:COMPUTERNAME -eq 'DC01') {
        Import-Module ActiveDirectory
        if(-not $AccountPassword) {throw 'Fictional account password is required through SecureString.'}
        $ou='OU=SOC Lab,DC=corp,DC=lab'
        if(Get-ADOrganizationalUnit -Filter 'Name -eq "SOC Lab"') {throw 'SOC Lab OU already exists; refusing unrelated changes.'}
        foreach($account in $accounts) {if(Get-ADUser -Filter "SamAccountName -eq '$account'") {throw 'Fictional exercise name already exists.'}}
        New-ADOrganizationalUnit -Name 'SOC Lab' -Path 'DC=corp,DC=lab' -ProtectedFromAccidentalDeletion $false -Description 'Disposable fictional SOC detection exercises'
        foreach($account in $accounts) {
            New-ADUser -Name $account -SamAccountName $account -UserPrincipalName "$account@corp.lab" -Path $ou -AccountPassword $AccountPassword -Enabled ($account -in @('soc.lockout','soc.share')) -Description 'Fictional SOC lab account; no real person'
        }
        Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold,LockoutDuration,LockoutObservationWindow | ConvertTo-Json | Set-Content "$root\lockout-policy.json"
        if((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold -eq 0) {throw 'No lockout policy: owner must configure one; script will not weaken/change domain policy.'}
        if(Get-SmbShare -Name SocRestricted -ErrorAction SilentlyContinue) {throw 'Exercise share already exists.'}
        $null=New-Item -ItemType Directory "$root\Restricted" -Force
        'Fictional SOC lab document. No customer data.' | Set-Content "$root\Restricted\example.txt"
        New-SmbShare -Name SocRestricted -Path "$root\Restricted" -FullAccess 'CORP\Domain Admins' | Out-Null
    }
    (Get-Date).ToUniversalTime().ToString('o') | Set-Content "$root\prepared.txt"
    Record-Action 'prepare' 'Audit baseline saved; fictional resources prepared'
}
if($Action -eq 'Exercise') {
    if(-not(Test-Path "$root\prepared.txt")) {throw 'Prepare first.'}
    if($env:COMPUTERNAME -eq 'DC01') {
        Import-Module ActiveDirectory
        if((Test-Path "$root\actions.jsonl") -and (Select-String -LiteralPath "$root\actions.jsonl" -SimpleMatch '"action":"share-success-baseline"' -Quiet)) {
            if((Get-Service SocLabDemo -ErrorAction SilentlyContinue) -or (Get-ScheduledTask -TaskName SocLabDemo -ErrorAction SilentlyContinue)) {throw 'Exercise resources remain; inspect cleanup before resuming.'}
            Record-Action 'exercise-resume' 'Completed server exercises retained; no duplicate changes generated'
            return
        }
        $probe=Get-ADUser soc.privilege -Properties Enabled,DistinguishedName
        if($probe.Enabled -or $probe.DistinguishedName -notlike 'CN=soc.privilege,OU=SOC Lab,DC=corp,DC=lab') {throw 'Only the disabled fictional probe may receive temporary privilege.'}
        $admins=Get-ADGroup -Identity "$((Get-ADDomain).DomainSID.Value)-512"
        try {
            Add-ADGroupMember -Identity $admins -Members $probe
            Record-Action 'privileged-group' 'Disabled fictional soc.privilege added to Domain Admins'
        } finally {Remove-ADGroupMember -Identity $admins -Members $probe -Confirm:$false}
        if(Get-Service SocLabDemo -ErrorAction SilentlyContinue) {throw 'Exercise service already exists.'}
        try {
            New-Service -Name SocLabDemo -BinaryPathName 'C:\Windows\System32\cmd.exe /c exit 0' -StartupType Manual -Description 'SOC lab registration only; never started' | Out-Null
            Record-Action 'service' 'Demand-start SocLabDemo registered; never started'
            & sc.exe query SocLabDemo | Out-Null
        } finally {& sc.exe delete SocLabDemo | Out-Null}
        if(Get-ScheduledTask -TaskName SocLabDemo -ErrorAction SilentlyContinue) {throw 'Exercise task already exists.'}
        try {
            $taskAction=New-ScheduledTaskAction -Execute 'C:\Windows\System32\whoami.exe'
            $trigger=New-ScheduledTaskTrigger -Once -At ([datetime]'2099-01-01T12:00:00')
            Register-ScheduledTask -TaskName SocLabDemo -Action $taskAction -Trigger $trigger -User SYSTEM -Description 'SOC lab registration only; future task immediately removed' | Out-Null
            Record-Action 'task' 'SocLabDemo task registered with future trigger; never run'
        } finally {Unregister-ScheduledTask -TaskName SocLabDemo -Confirm:$false -ErrorAction SilentlyContinue}
        $auditExercise=Join-Path $root ('audit-exercise-'+[guid]::NewGuid().ToString()+'.csv')
        & auditpol.exe /backup "/file:$auditExercise" | Out-Null
        if($LASTEXITCODE -ne 0) {throw 'Exercise audit backup failed.'}
        try {
            # Add auditing only; restoration puts the exact prior policy back.
            & auditpol.exe /set '/subcategory:Other Logon/Logoff Events' /success:enable /failure:enable | Out-Null
            if($LASTEXITCODE -ne 0) {throw 'Audit exercise failed.'}
            Record-Action 'audit-policy' 'Enabled Other Logon/Logoff Events auditing'
        } finally {& auditpol.exe /restore "/file:$auditExercise" | Out-Null}
        # Real successful share accesses provide a noise baseline; no fake records.
        1..5 | ForEach-Object {Get-Content '\\DC01.corp.lab\SocRestricted\example.txt' | Out-Null}
        Record-Action 'share-success-baseline' 'Five ordinary authorised reads'
    } else {
        & whoami.exe | Out-Null  # Narrow Sysmon collection heartbeat.
        Record-Action 'client-context' 'whoami executed for Sysmon collection check'
        if(-not $AccountPassword) {throw 'Known fictional password required; no guessing is permitted.'}
        # One attempt with the known password: ordinary Run As against a disabled
        # fictional account. This is not a password guess or an authentication loop.
        if(-not(Select-String -LiteralPath "$root\actions.jsonl" -SimpleMatch '"action":"disabled-sign-in"' -Quiet)) {
            $disabled=[pscredential]::new('CORP\soc.disabled',$AccountPassword)
            try {
                $process=Start-Process -FilePath C:\Windows\System32\whoami.exe -Credential $disabled -WindowStyle Hidden -PassThru -Wait
                throw 'Disabled-account process unexpectedly started; inspect account state.'
            } catch {
                if($_.Exception.Message -like '*unexpectedly started*') {throw}
                Record-Action 'disabled-sign-in' $_.Exception.Message
            }
        }
        # One standard PowerShell mapping/read with the known valid fictional account.
        # No interactive/batch-logon rights or folder ACLs are changed.
        $shareCred=[pscredential]::new('CORP\soc.share',$AccountPassword)
        if(Get-PSDrive SocDeniedProbe -ErrorAction SilentlyContinue) {throw 'Probe drive already exists.'}
        try {
            New-PSDrive -Name SocDeniedProbe -PSProvider FileSystem -Root '\\DC01.corp.lab\SocRestricted' -Credential $shareCred -ErrorAction Stop | Out-Null
            Get-Content 'SocDeniedProbe:\example.txt' -ErrorAction Stop | Out-Null
            throw 'Restricted share unexpectedly allowed the fictional account.'
        } catch {
            if($_.Exception.Message -notmatch '(?i)access.*denied') {throw}
            Record-Action 'share-denied' 'One mapping/read as CORP\soc.share denied; permissions retained'
        } finally {if(Get-PSDrive SocDeniedProbe -ErrorAction SilentlyContinue) {Remove-PSDrive SocDeniedProbe}}

    }
    Write-Output 'Console lockout is a separate owner-authorised, five-submission test. Disabled-account Run As and the denied share read use known fictional passwords. No password search is provided.'
}
if($Action -eq 'Export') {
    if(-not(Test-Path "$root\prepared.txt")) {throw 'No exercise start marker.'}
    $start=[datetime](Get-Content "$root\prepared.txt" -Raw)
    $output=@()
    if($env:COMPUTERNAME -eq 'DC01') {
        Import-Module ActiveDirectory
        @('soc.lockout','alex.morgan','soc.disabled','soc.privilege','soc.share') | ForEach-Object {Get-ADUser $_ -Properties LockedOut,badPwdCount,LastBadPasswordAttempt | Select-Object SamAccountName,Enabled,LockedOut,badPwdCount,LastBadPasswordAttempt} | ConvertTo-Json | Set-Content "$root\account-state.json"
    }
    foreach($log in @('Security','System','Microsoft-Windows-Sysmon/Operational')) {
        $events=@(Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=$start} -ErrorAction SilentlyContinue)
        foreach($event in $events) {
            if(($log -eq 'Security' -and $event.Id -in @(4728,4732,4756,4740,4625,4771,4697,4698,4719,5136,5145)) -or ($log -eq 'System' -and $event.Id -eq 7045) -or $log -like '*Sysmon*') {
                $output += ([ordered]@{computer=$env:COMPUTERNAME;event_id=$event.Id;record_id=$event.RecordId;xml=$event.ToXml()} | ConvertTo-Json -Compress)
            }
        }
    }
    [IO.File]::WriteAllLines("$root\events.jsonl",[string[]]$output,[Text.UTF8Encoding]::new($false))
    Record-Action 'export' "Saved $($output.Count) actual Windows events; review privately before publication"
}
if($Action -eq 'Cleanup') {
    if($env:COMPUTERNAME -eq 'DC01') {
        Import-Module ActiveDirectory
        foreach($account in $accounts) {
            $user=Get-ADUser -Filter "SamAccountName -eq '$account'"
            if($user -and $user.DistinguishedName -like 'CN=*,OU=SOC Lab,DC=corp,DC=lab') {Remove-ADUser -Identity $user -Confirm:$false}
        }
        if(Get-SmbShare SocRestricted -ErrorAction SilentlyContinue) {
            if((Get-SmbShare SocRestricted).Path -ne 'C:\SocLab\Restricted') {throw 'Share path changed; refusing cleanup.'}
            Remove-SmbShare SocRestricted -Force
        }
        $ou=Get-ADOrganizationalUnit -Filter 'Name -eq "SOC Lab"'
        if($ou -and -not(Get-ADObject -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Filter *)) {Remove-ADOrganizationalUnit $ou -Confirm:$false}
    }
    # Retain the required monitoring audits; the original backup is an explicit
    # rollback option. The audit exercise already restored its own snapshot.
    $checks=[ordered]@{computer=$env:COMPUTERNAME;domain=(Get-CimInstance Win32_ComputerSystem).Domain;agent=(Get-Service WazuhSvc).Status.ToString();sysmon=(Get-Service Sysmon64).Status.ToString();monitoring_audits_retained=$true}
    if($env:COMPUTERNAME -eq 'DC01') {
        $checks.exercise_accounts_absent=@(Get-ADUser -Filter * -SearchBase 'DC=corp,DC=lab' | Where-Object SamAccountName -In $accounts).Count -eq 0
        $checks.exercise_share_absent=-not [bool](Get-SmbShare SocRestricted -ErrorAction SilentlyContinue)
        $checks.exercise_service_absent=-not [bool](Get-Service SocLabDemo -ErrorAction SilentlyContinue)
        $checks.exercise_task_absent=-not [bool](Get-ScheduledTask -TaskName SocLabDemo -ErrorAction SilentlyContinue)
        $checks.alex_enabled=(Get-ADUser alex.morgan).Enabled
        $checks.alex_unlocked=-not(Get-ADUser alex.morgan -Properties LockedOut).LockedOut
        $checks.client_membership_retained=(Get-ADComputer CLIENT01).DistinguishedName -eq 'CN=CLIENT01,OU=Computers,OU=Lab,DC=corp,DC=lab'
        $checks.department_shares_retained=@('Finance','HR','IT','Homes' | Where-Object {-not(Get-SmbShare $_ -ErrorAction SilentlyContinue)}).Count -eq 0
        foreach($key in @('exercise_accounts_absent','exercise_share_absent','exercise_service_absent','exercise_task_absent','alex_enabled','alex_unlocked','client_membership_retained','department_shares_retained')) {if(-not $checks[$key]) {throw "Post-cleanup check failed: $key"}}
    }
    $checks | ConvertTo-Json | Set-Content "$root\cleanup-checks.json"
    Record-Action 'cleanup' 'Fictional accounts/share removed; required monitoring audits and agents retained; postchecks passed'
}
