#Requires -RunAsAdministrator
# userws.ps1 — Provisioner for userws.neutron.local (172.16.10.21)
# VM: Windows 10 | IP: 172.16.10.21 | VLAN10
#
# Role: Domain-joined standard user workstation
#   - Joined to neutron.local domain
#   - jsmith (Domain User) is logged in / has profile
#   - WinRM and RDP enabled
#   - Intentional postex findings: VPN config, web browser saved creds
#
# Vagrant calls this script twice:
#   Pass 1 (PROVISION_PASS=1): static IP + hostname + domain join
#   Pass 2 (PROVISION_PASS=2): run never — post-join config (profiles, findings)
#     Invoke: vagrant provision userws --provision-with userws-join

$ErrorActionPreference = "Continue"

function Write-Step { param([string]$m)
    Write-Host ""; Write-Host "==> [$(Get-Date -Format 'HH:mm:ss')] $m" -ForegroundColor Cyan }
function Write-OK   { param([string]$m) { Write-Host "    [OK]  $m" -ForegroundColor Green } }
function Write-SKIP { param([string]$m) { Write-Host "    [SKIP] $m" -ForegroundColor Yellow } }
function Write-ERR  { param([string]$m) { Write-Host "    [ERR]  $m" -ForegroundColor Red } }

$pass = if ($env:PROVISION_PASS) { [int]$env:PROVISION_PASS } else { 1 }

Write-Host ""
Write-Host "########################################################" -ForegroundColor Magenta
Write-Host "  userws.ps1  —  Provision pass $pass" -ForegroundColor Magenta
Write-Host "########################################################" -ForegroundColor Magenta

$myIp      = if ($env:HOST_IP)   { $env:HOST_IP }   else { "172.16.10.21" }
$gateway   = if ($env:VLAN10_GW) { $env:VLAN10_GW } else { "172.16.10.1" }
$dcIp      = if ($env:DC_IP)     { $env:DC_IP }     else { "172.16.10.10" }
$domain    = "neutron.local"
$domainAdminUser = "NEUTRON\Administrator"
$domainAdminPass = "NeutronAdmin2024!"

# ===========================================================================
# PASS 1: Static IP + hostname + domain join
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
    Write-Step "Step 2: Setting hostname to userws"

    try {
        if ($env:COMPUTERNAME -ne "userws") {
            Rename-Computer -NewName "userws" -Force -ErrorAction Stop
            Write-OK "Hostname set to userws (requires reboot)"
        } else {
            Write-SKIP "Hostname already userws"
        }
    }
    catch { Write-ERR "Step 2 failed: $_" }

    # -----------------------------------------------------------------------
    # Step 3 — Join domain
    # -----------------------------------------------------------------------
    Write-Step "Step 3: Joining domain $domain"

    $domainStatus = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
    if ($domainStatus) {
        Write-SKIP "Already domain-joined"
    } else {
        try {
            $secPass = ConvertTo-SecureString $domainAdminPass -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential($domainAdminUser, $secPass)

            Add-Computer `
                -DomainName  $domain `
                -Credential  $cred `
                -OUPath      "CN=Computers,DC=neutron,DC=local" `
                -Force       `
                -ErrorAction Stop

            Write-OK "Domain join initiated — rebooting"
            Start-Sleep -Seconds 5
            Restart-Computer -Force
        }
        catch {
            Write-ERR "Domain join failed: $_"
        }
    }

    Write-Host "==> Pass 1 complete." -ForegroundColor Magenta
    exit 0
}

# ===========================================================================
# PASS 2: Post-join configuration
# ===========================================================================
if ($pass -eq 2) {

    # -----------------------------------------------------------------------
    # Step 4 — Enable WinRM + RDP
    # -----------------------------------------------------------------------
    Write-Step "Step 4: Enabling WinRM and RDP"

    try {
        Enable-PSRemoting -Force -ErrorAction Stop
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
        Start-Service WinRM
        Set-Service WinRM -StartupType Automatic
        Enable-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" `
            -ErrorAction SilentlyContinue
        Write-OK "WinRM enabled on port 5985"
    }
    catch { Write-ERR "WinRM failed: $_" }

    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
            -Name fDenyTSConnections -Value 0
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        Write-OK "RDP enabled on port 3389"
    }
    catch { Write-ERR "RDP failed: $_" }

    # Disable firewall for lab
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Write-OK "Windows Firewall disabled"

    # -----------------------------------------------------------------------
    # Step 5 — jsmith profile and postex findings
    # -----------------------------------------------------------------------
    Write-Step "Step 5: Creating jsmith profile and postex findings"

    try {
        $jsHome = "C:\Users\jsmith"
        $jsDesktop = "$jsHome\Desktop"
        $jsDocs    = "$jsHome\Documents"
        New-Item -ItemType Directory -Force -Path $jsDesktop | Out-Null
        New-Item -ItemType Directory -Force -Path $jsDocs    | Out-Null

        # Finding 1: Saved VPN config reference
        Set-Content -Path "$jsDesktop\VPN-Info.txt" -Value @"
Work VPN Setup — jsmith
========================
VPN Server: vpn.neutron.local (172.16.30.30)
Port: 1194 UDP
Client cert bundle: on vpn server at /home/vagrant/vpn-client/

My credentials:
  Domain: NEUTRON\jsmith / Password123
  VPN:    Uses certificate auth (no password)

Connect from home:
  openvpn --config ~/Downloads/client1.ovpn

After connect: all internal resources accessible
  Odoo:      http://172.16.20.10:8069  (admin/admin)
  Files:     \\172.16.20.10\files (no auth needed)
  Nextcloud: http://172.16.20.10:9000  (my login: jsmith/Password123)
"@

        # Finding 2: PowerShell command history
        $psHistPath = "$jsHome\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
        New-Item -ItemType Directory -Force -Path $psHistPath | Out-Null
        Set-Content -Path "$psHistPath\ConsoleHost_history.txt" -Value @"
net use Z: \\172.16.20.10\files /persistent:yes
Invoke-WebRequest http://172.16.20.10:8069/web/login
Start-Process "C:\Program Files\OpenVPN\bin\openvpn.exe" --config client1.ovpn
$env:userprofile
"@

        # Finding 3: Browser saved creds note (simulates browser dump)
        $chromeProfile = "$jsHome\AppData\Local\Google\Chrome\User Data\Default"
        New-Item -ItemType Directory -Force -Path $chromeProfile | Out-Null
        Set-Content -Path "$chromeProfile\Bookmarks.note" -Value @"
# Chrome saved login note (readable via Mimikatz DPAPI)
# Simulates Chrome saved passwords — decrypt with: mimikatz dpapi::chrome
http://172.16.20.10:8069   jsmith  Password123
http://172.16.20.10:9000   jsmith  Password123
http://172.16.20.10:8080   jsmith  Password123
"@

        Write-OK "jsmith postex findings planted"
    }
    catch { Write-ERR "Step 5 failed: $_" }

    # -----------------------------------------------------------------------
    # Step 6 — Summary
    # -----------------------------------------------------------------------
    Write-Step "Step 6: Summary"
    Write-OK  "userws.neutron.local configuration complete"
    Write-Host ""
    Write-Host "Attack surfaces:" -ForegroundColor Yellow
    Write-Host "  WinRM :5985 — NEUTRON\jsmith / Password123"
    Write-Host "  RDP   :3389 — NEUTRON\jsmith / Password123"
    Write-Host ""
    Write-Host "Postex findings:" -ForegroundColor Yellow
    Write-Host "  C:\Users\jsmith\Desktop\VPN-Info.txt"
    Write-Host "  C:\Users\jsmith\AppData\...\ConsoleHost_history.txt"
    Write-Host "  Chrome profile (DPAPI-encrypted saved passwords)"

    exit 0
}
