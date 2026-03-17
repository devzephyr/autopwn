#Requires -RunAsAdministrator
# adminws.ps1 — Provisioner for adminws.neutron.local (172.16.10.20)
# VM: Windows 10 | IP: 172.16.10.20 | VLAN10
#
# Role: Domain-joined admin workstation
#   - Joined to neutron.local domain
#   - hradmin (Domain Admin) is logged in / has profile
#   - WinRM enabled (port 5985) — credential attack surface
#   - Intentional postex findings in hradmin's profile
#
# Vagrant calls this script twice:
#   Pass 1 (PROVISION_PASS=1): static IP + join domain
#   Pass 2 (PROVISION_PASS=2): run never — post-join configuration
#     Invoke: vagrant provision adminws --provision-with adminws-join
#
# Attack chains:
#   1. Credential reuse (WinRM) — hradmin/HrAdmin2024! from jumpbox finding
#   2. WinRM → whoami → kiwi/secretsdump → domain hash dump

$ErrorActionPreference = "Continue"

function Write-Step { param([string]$m)
    Write-Host ""; Write-Host "==> [$(Get-Date -Format 'HH:mm:ss')] $m" -ForegroundColor Cyan }
function Write-OK   { param([string]$m) { Write-Host "    [OK]  $m" -ForegroundColor Green } }
function Write-SKIP { param([string]$m) { Write-Host "    [SKIP] $m" -ForegroundColor Yellow } }
function Write-ERR  { param([string]$m) { Write-Host "    [ERR]  $m" -ForegroundColor Red } }

$pass = if ($env:PROVISION_PASS) { [int]$env:PROVISION_PASS } else { 1 }

Write-Host ""
Write-Host "########################################################" -ForegroundColor Magenta
Write-Host "  adminws.ps1  —  Provision pass $pass" -ForegroundColor Magenta
Write-Host "########################################################" -ForegroundColor Magenta

# Read env vars supplied by Vagrantfile
$myIp      = if ($env:HOST_IP)   { $env:HOST_IP }   else { "172.16.10.20" }
$gateway   = if ($env:VLAN10_GW) { $env:VLAN10_GW } else { "172.16.10.1" }
$dcIp      = if ($env:DC_IP)     { $env:DC_IP }     else { "172.16.10.10" }
$domain    = "neutron.local"
$netbios   = "NEUTRON"
$domainAdminUser = "NEUTRON\Administrator"
$domainAdminPass = "NeutronAdmin2024!"

# ===========================================================================
# PASS 1: Static IP + domain join
# ===========================================================================
if ($pass -eq 1) {

    # -----------------------------------------------------------------------
    # Step 1 — Static IP
    # -----------------------------------------------------------------------
    Write-Step "Step 1: Configuring static IP $myIp/24"

    try {
        $nic = Get-NetAdapter -Physical |
               Where-Object { $_.Status -eq "Up" } |
               ForEach-Object {
                   $addr = (Get-NetIPAddress -InterfaceIndex $_.ifIndex `
                            -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
                   [PSCustomObject]@{ Adapter=$_; Addr=$addr }
               } |
               Where-Object { $_.Addr -ne $null -and $_.Addr -notlike "10.0.2.*" } |
               Select-Object -First 1 -ExpandProperty Adapter

        if (-not $nic) {
            $nic = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" } |
                   Sort-Object ifIndex | Select-Object -Skip 1 -First 1
        }

        $ifIdx = $nic.ifIndex
        Write-Host "    Target NIC: $($nic.Name) (index $ifIdx)"

        $existing = Get-NetIPAddress -InterfaceIndex $ifIdx -AddressFamily IPv4 `
                    -ErrorAction SilentlyContinue
        foreach ($ip in $existing) {
            Remove-NetIPAddress -InputObject $ip -Confirm:$false -ErrorAction SilentlyContinue
        }
        Get-NetRoute -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        New-NetIPAddress `
            -InterfaceIndex $ifIdx `
            -IPAddress      $myIp `
            -PrefixLength   24 `
            -DefaultGateway $gateway | Out-Null

        Set-DnsClientServerAddress `
            -InterfaceIndex $ifIdx `
            -ServerAddresses @($dcIp, "8.8.8.8")

        Write-OK "Static IP set to $myIp/24, gateway $gateway, DNS $dcIp"
    }
    catch { Write-ERR "Step 1 failed: $_" }

    # -----------------------------------------------------------------------
    # Step 2 — Set hostname
    # -----------------------------------------------------------------------
    Write-Step "Step 2: Setting hostname to adminws"

    try {
        $currentName = $env:COMPUTERNAME
        if ($currentName -ne "adminws") {
            Rename-Computer -NewName "adminws" -Force -ErrorAction Stop
            Write-OK "Hostname set to adminws (requires reboot)"
        } else {
            Write-SKIP "Hostname already adminws"
        }
    }
    catch { Write-ERR "Step 2 failed: $_" }

    # -----------------------------------------------------------------------
    # Step 3 — Join domain
    # -----------------------------------------------------------------------
    Write-Step "Step 3: Joining domain $domain"

    $domainStatus = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
    if ($domainStatus) {
        Write-SKIP "Already joined to a domain — skipping"
    } else {
        try {
            $secPass = ConvertTo-SecureString $domainAdminPass -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential($domainAdminUser, $secPass)

            Add-Computer `
                -DomainName   $domain `
                -Credential   $cred `
                -OUPath       "CN=Computers,DC=neutron,DC=local" `
                -Force        `
                -ErrorAction  Stop

            Write-OK "Domain join initiated — rebooting to complete"
            Start-Sleep -Seconds 5
            Restart-Computer -Force
        }
        catch {
            Write-ERR "Domain join failed: $_"
            Write-ERR "Ensure DC01 is online and the domain admin password is correct."
        }
    }

    Write-Host "==> Pass 1 complete." -ForegroundColor Magenta
    exit 0
}

# ===========================================================================
# PASS 2: Post-join configuration (run: never — invoke manually after reboot)
# ===========================================================================
if ($pass -eq 2) {

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    # -----------------------------------------------------------------------
    # Step 4 — Enable WinRM
    # -----------------------------------------------------------------------
    Write-Step "Step 4: Enabling WinRM"

    try {
        Enable-PSRemoting -Force -ErrorAction Stop
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
        Set-WSManInstance -ResourceURI winrm/config/listener `
            -SelectorSet @{Address="*"; Transport="HTTP"} `
            -ValueSet @{Port="5985"} -ErrorAction SilentlyContinue | Out-Null

        # Allow WinRM through Windows Firewall
        Enable-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" `
            -ErrorAction SilentlyContinue

        Start-Service WinRM
        Set-Service WinRM -StartupType Automatic

        Write-OK "WinRM enabled on port 5985 (HTTP)"
    }
    catch { Write-ERR "Step 4 failed: $_" }

    # -----------------------------------------------------------------------
    # Step 5 — Enable RDP
    # -----------------------------------------------------------------------
    Write-Step "Step 5: Enabling RDP"

    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
            -Name fDenyTSConnections -Value 0 -ErrorAction Stop

        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

        Write-OK "RDP enabled on port 3389"
    }
    catch { Write-ERR "Step 5 failed: $_" }

    # -----------------------------------------------------------------------
    # Step 6 — Disable Windows Firewall (lab convenience)
    # -----------------------------------------------------------------------
    Write-Step "Step 6: Disabling Windows Firewall (lab)"

    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
        Write-OK "Windows Firewall disabled"
    }
    catch { Write-ERR "Step 6 failed: $_" }

    # -----------------------------------------------------------------------
    # Step 7 — Create hradmin local profile + postex findings
    # -----------------------------------------------------------------------
    Write-Step "Step 7: Creating hradmin profile and postex findings"

    try {
        # Create hradmin's Documents folder
        $hrHome = "C:\Users\hradmin"
        $hrDocs = "$hrHome\Documents"
        New-Item -ItemType Directory -Force -Path $hrDocs | Out-Null
        New-Item -ItemType Directory -Force -Path "$hrHome\Desktop" | Out-Null

        # Sensitive file: department password spreadsheet
        Set-Content -Path "$hrDocs\HR-Passwords-2024.txt" -Value @"
HR Department Credential Reference — CONFIDENTIAL
==================================================
System              Username            Password
------              --------            --------
Domain              hradmin             HrAdmin2024!
Domain              administrator       NeutronAdmin2024!
Payroll DB (esite)  dbadmin             Dbp@ss2024
File Share          files_admin         FilePass99
VPN                 vpnuser             Vpn`$ecure1
Nextcloud           admin               password
SNMP read           -                   public

Last audit: 2024-10-01
Contact IT: it-helpdesk@neutron.local
"@

        # Desktop shortcut note
        Set-Content -Path "$hrHome\Desktop\Quick-Notes.txt" -Value @"
Admin Workstation — hradmin
============================
Domain: NEUTRON (neutron.local)
DC: 172.16.10.10

Remoting to servers:
  Enter-PSSession -ComputerName dc01 -Credential NEUTRON\Administrator
  Enter-PSSession -ComputerName containers -Credential NEUTRON\Administrator

NFS mount:
  mount -o anon \\172.16.20.10\files Z:

Odoo ERP: http://172.16.20.10:8069  (admin/admin)
Nextcloud: http://172.16.20.10:9000 (admin/password)
"@

        # PowerShell history
        $psHistPath = "$hrHome\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
        New-Item -ItemType Directory -Force -Path $psHistPath | Out-Null
        Set-Content -Path "$psHistPath\ConsoleHost_history.txt" -Value @"
Enter-PSSession -ComputerName dc01 -Credential NEUTRON\Administrator
Get-ADUser -Filter * -Properties * | Select-Object SamAccountName,MemberOf
Invoke-WebRequest http://172.16.20.10:8069
net use Z: \\172.16.20.10\files /persistent:yes
"@

        Write-OK "Postex findings planted in hradmin profile"
    }
    catch { Write-ERR "Step 7 failed: $_" }

    # -----------------------------------------------------------------------
    # Step 8 — Summary
    # -----------------------------------------------------------------------
    Write-Step "Step 8: Summary"
    Write-OK  "adminws.neutron.local configuration complete"
    Write-Host ""
    Write-Host "Attack surfaces:" -ForegroundColor Yellow
    Write-Host "  WinRM :5985 — NEUTRON\hradmin / HrAdmin2024!"
    Write-Host "  RDP   :3389 — NEUTRON\hradmin / HrAdmin2024!"
    Write-Host ""
    Write-Host "Postex findings:" -ForegroundColor Yellow
    Write-Host "  C:\Users\hradmin\Documents\HR-Passwords-2024.txt"
    Write-Host "  C:\Users\hradmin\Desktop\Quick-Notes.txt"
    Write-Host "  C:\Users\hradmin\AppData\...\ConsoleHost_history.txt"

    exit 0
}
