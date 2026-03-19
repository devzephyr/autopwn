#Requires -RunAsAdministrator
# dc.ps1 — Standalone provisioning script for dc.neutron.local
# Real SPR500 topology: 172.16.12.10/27 | VLAN30 | Windows Server 2022
#
# Run directly on the DC (no Vagrant). Two-pass execution:
#   Pass 1: .\dc.ps1 -Pass 1   — network + AD DS install (triggers reboot)
#   Pass 2: .\dc.ps1 -Pass 2   — DNS records, users, ADCS, certs, IIS
#
# Safe to re-run (idempotent).

param(
    [ValidateSet(1, 2)]
    [int]$Pass = 1
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Real SPR500 IP constants
# ---------------------------------------------------------------------------
$DC_IP      = "172.16.12.10"
$PREFIX     = 27
$GATEWAY    = "172.16.12.1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step { param([string]$m); Write-Host ""; Write-Host "==> [$(Get-Date -Format 'HH:mm:ss')] $m" -ForegroundColor Cyan }
function Write-OK   { param([string]$m); Write-Host "    [OK]   $m" -ForegroundColor Green }
function Write-SKIP { param([string]$m); Write-Host "    [SKIP] $m" -ForegroundColor Yellow }
function Write-ERR  { param([string]$m); Write-Host "    [ERR]  $m" -ForegroundColor Red }

Write-Host ""
Write-Host "########################################################" -ForegroundColor Magenta
Write-Host "  dc.ps1  —  Provision pass $Pass  (real SPR500 topology)" -ForegroundColor Magenta
Write-Host "########################################################" -ForegroundColor Magenta

# ===========================================================================
# PASS 1: Static IP + AD DS forest install + reboot
# ===========================================================================
if ($Pass -eq 1) {

    # -----------------------------------------------------------------------
    # Step 1 — Static IP
    # -----------------------------------------------------------------------
    Write-Step "Step 1: Configuring static IP $DC_IP/$PREFIX on VLAN30"

    try {
        # Find the non-NAT NIC (skip loopback and any 10.0.2.x NIC Vagrant adds)
        $nic = Get-NetAdapter -Physical |
               Where-Object { $_.Status -eq "Up" } |
               ForEach-Object {
                   $addr = (Get-NetIPAddress -InterfaceIndex $_.ifIndex `
                            -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
                   [PSCustomObject]@{ Adapter = $_; Addr = $addr }
               } |
               Where-Object { $_.Addr -ne $null -and $_.Addr -notlike "10.0.2.*" } |
               Select-Object -First 1 -ExpandProperty Adapter

        if (-not $nic) {
            $nic = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" } |
                   Sort-Object ifIndex | Select-Object -First 1
        }

        if (-not $nic) { throw "Cannot identify target NIC." }

        $ifIdx = $nic.ifIndex
        Write-Host "    Target NIC: $($nic.Name) (index $ifIdx)"

        # Clear existing config
        Get-NetIPAddress -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        New-NetIPAddress `
            -InterfaceIndex $ifIdx `
            -IPAddress      $DC_IP `
            -PrefixLength   $PREFIX `
            -DefaultGateway $GATEWAY | Out-Null

        Set-DnsClientServerAddress `
            -InterfaceIndex $ifIdx `
            -ServerAddresses @("127.0.0.1", "8.8.8.8")

        Write-OK "Static IP $DC_IP/$PREFIX, gateway $GATEWAY, DNS 127.0.0.1 / 8.8.8.8"
    }
    catch {
        Write-ERR "Step 1 failed: $_"
    }

    # -----------------------------------------------------------------------
    # Step 2 — Install AD DS + promote to forest root DC
    # -----------------------------------------------------------------------
    Write-Step "Step 2: Installing AD Domain Services and promoting forest"

    $alreadyDc = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4
    if ($alreadyDc) {
        Write-SKIP "Already a domain controller — skipping promotion."
    }
    else {
        try {
            $feat = Install-WindowsFeature -Name AD-Domain-Services `
                        -IncludeManagementTools -WarningAction SilentlyContinue
            if (-not $feat.Success) { throw "Feature install failed: $($feat.ExitCode)" }
            Write-OK "AD-Domain-Services feature installed."

            Import-Module ADDSDeployment -ErrorAction Stop

            Write-Host "    Promoting to forest root DC for neutron.local  (reboot follows)..."
            Install-ADDSForest `
                -DomainName                  "neutron.local" `
                -DomainNetbiosName           "NEUTRON" `
                -DomainMode                  "WinThreshold" `
                -ForestMode                  "WinThreshold" `
                -SafeModeAdministratorPassword (
                    ConvertTo-SecureString "Passw0rd123!" -AsPlainText -Force
                ) `
                -InstallDns                  `
                -NoRebootOnCompletion:$false `
                -Force                       `
                -WarningAction SilentlyContinue

            Write-OK "Forest promotion initiated — reboot in progress."
        }
        catch {
            Write-ERR "Step 2 failed: $_"
            exit 1
        }
    }

    Write-Host ""
    Write-Host "==> Pass 1 complete.  After reboot run:  .\dc.ps1 -Pass 2" -ForegroundColor Magenta
    exit 0
}

# ===========================================================================
# PASS 2: DNS records, users, ADCS, certificates, IIS
# ===========================================================================
if ($Pass -eq 2) {

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    Import-Module DnsServer       -ErrorAction SilentlyContinue

    # -----------------------------------------------------------------------
    # Step 3 — DNS A records (real SPR500 IPs)
    # -----------------------------------------------------------------------
    Write-Step "Step 3: Adding DNS A records for real SPR500 topology"

    $zone = "neutron.local"

    $records = @{
        # VLAN30 — 172.16.12.0/27
        "dc"          = "172.16.12.10"
        "privdns"     = "172.16.12.11"
        "files"       = "172.16.12.12"
        "erp"         = "172.16.12.12"
        "mail"        = "172.16.12.10"

        # DMZ — 172.16.10.32/28
        "pubdns"      = "172.16.10.35"
        "shop"        = "172.16.10.36"
        "corp"        = "172.16.10.36"
        "www"         = "172.16.10.36"
        "vpn"         = "172.16.10.40"
        "remote"      = "172.16.10.40"
        "jumpbox"     = "172.16.10.41"

        # External — 172.16.21.0/26
        "kali"        = "172.16.21.11"
        "remoteuser"  = "172.16.21.20"
    }

    foreach ($name in $records.Keys) {
        try {
            $existing = Get-DnsServerResourceRecord -ZoneName $zone -Name $name `
                            -RRType A -ErrorAction SilentlyContinue
            if ($existing) {
                Write-SKIP "A record exists: $name -> $($records[$name])"
            }
            else {
                Add-DnsServerResourceRecordA -ZoneName $zone -Name $name `
                    -IPv4Address $records[$name] -ErrorAction Stop
                Write-OK "Added: $name.$zone -> $($records[$name])"
            }
        }
        catch { Write-ERR "DNS record '$name': $_" }
    }

    # -----------------------------------------------------------------------
    # Step 4 — AD users
    # -----------------------------------------------------------------------
    Write-Step "Step 4: Creating AD lab users"

    $ouPath = "CN=Users,DC=neutron,DC=local"

    $users = @(
        @{
            SamAccountName    = "jsmith"
            DisplayName       = "John Smith"
            Password          = "Password123"
            Groups            = @()
            NoPreauthRequired = $false
            SPN               = $null
        },
        @{
            SamAccountName    = "svc_backup"
            DisplayName       = "Backup Service Account"
            Password          = "Backup2024!"
            Groups            = @()
            NoPreauthRequired = $true          # AS-REP roastable
            SPN               = $null
        },
        @{
            SamAccountName    = "svc_web"
            DisplayName       = "Web Service Account"
            Password          = "WebSvc2024!"
            Groups            = @()
            NoPreauthRequired = $false
            SPN               = "HTTP/corp.neutron.local"  # Kerberoastable
        },
        @{
            SamAccountName    = "svc_sql"
            DisplayName       = "SQL Service Account"
            Password          = "SqlSvc2024!"
            Groups            = @()
            NoPreauthRequired = $false
            SPN               = "MSSQLSvc/files.neutron.local:1433"  # Kerberoastable
        },
        @{
            SamAccountName    = "hradmin"
            DisplayName       = "HR Administrator"
            Password          = "HrAdmin2024!"
            Groups            = @("Domain Admins")
            NoPreauthRequired = $false
            SPN               = $null
        }
    )

    foreach ($u in $users) {
        try {
            $existing = Get-ADUser -Filter { SamAccountName -eq $u.SamAccountName } `
                            -ErrorAction SilentlyContinue

            if ($existing) {
                Write-SKIP "User exists: $($u.SamAccountName)"
            }
            else {
                New-ADUser `
                    -SamAccountName       $u.SamAccountName `
                    -UserPrincipalName    "$($u.SamAccountName)@neutron.local" `
                    -Name                 $u.DisplayName `
                    -DisplayName          $u.DisplayName `
                    -AccountPassword      (ConvertTo-SecureString $u.Password -AsPlainText -Force) `
                    -Enabled              $true `
                    -PasswordNeverExpires $true `
                    -Path                 $ouPath `
                    -ErrorAction Stop
                Write-OK "Created: $($u.SamAccountName)"
            }

            if ($u.NoPreauthRequired) {
                $uac = (Get-ADUser -Identity $u.SamAccountName -Properties UserAccountControl).UserAccountControl
                if (-not ($uac -band 0x400000)) {
                    Set-ADAccountControl -Identity $u.SamAccountName -DoesNotRequirePreAuth $true
                    Write-OK "DONT_REQ_PREAUTH set on $($u.SamAccountName)"
                }
                else { Write-SKIP "DONT_REQ_PREAUTH already set on $($u.SamAccountName)" }
            }

            if ($u.SPN) {
                $spns = (Get-ADUser -Identity $u.SamAccountName -Properties ServicePrincipalNames).ServicePrincipalNames
                if ($spns -contains $u.SPN) {
                    Write-SKIP "SPN already set on $($u.SamAccountName)"
                }
                else {
                    Set-ADUser -Identity $u.SamAccountName -ServicePrincipalNames @{ Add = $u.SPN }
                    Write-OK "SPN set on $($u.SamAccountName): $($u.SPN)"
                }
            }

            foreach ($grp in $u.Groups) {
                try {
                    Add-ADGroupMember -Identity $grp -Members $u.SamAccountName -ErrorAction Stop
                    Write-OK "Added $($u.SamAccountName) -> $grp"
                }
                catch { Write-ERR "Group add $grp: $_" }
            }
        }
        catch { Write-ERR "User '$($u.SamAccountName)': $_" }
    }

    # -----------------------------------------------------------------------
    # Step 5 — ADCS (Enterprise Root CA + Web Enrollment)
    # -----------------------------------------------------------------------
    Write-Step "Step 5: Installing Active Directory Certificate Services"

    try {
        $f = Get-WindowsFeature -Name ADCS-Cert-Authority
        if ($f.Installed) { Write-SKIP "ADCS-Cert-Authority already installed." }
        else {
            Install-WindowsFeature -Name ADCS-Cert-Authority, ADCS-Web-Enrollment `
                -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
            Write-OK "ADCS features installed."
        }
    }
    catch { Write-ERR "ADCS feature install: $_" }

    try {
        $svc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-SKIP "Certificate Authority already running."
        }
        else {
            Import-Module AdcsDeployment -ErrorAction Stop
            Install-AdcsCertificationAuthority `
                -CAType              EnterpriseRootCa `
                -CACommonName        "Neutron-Root-CA" `
                -KeyLength           2048 `
                -HashAlgorithmName   SHA256 `
                -ValidityPeriod      Years `
                -ValidityPeriodUnits 10 `
                -Force -ErrorAction Stop | Out-Null
            Start-Service CertSvc -ErrorAction SilentlyContinue
            Write-OK "Enterprise Root CA 'Neutron-Root-CA' installed."
        }
    }
    catch { Write-ERR "CA install: $_" }

    try {
        Import-Module AdcsDeployment -ErrorAction SilentlyContinue
        Install-AdcsWebEnrollment -Force -ErrorAction Stop | Out-Null
        Write-OK "ADCS Web Enrollment configured."
    }
    catch { Write-ERR "Web Enrollment: $_" }

    # -----------------------------------------------------------------------
    # Step 6 — Issue TLS certificates for real lab hosts
    # -----------------------------------------------------------------------
    Write-Step "Step 6: Issuing TLS certificates for lab hosts"

    $certDir = "C:\Certs"
    if (-not (Test-Path $certDir)) { New-Item -ItemType Directory -Path $certDir | Out-Null }

    # Export CA root cert
    try {
        $caRootDest = "$certDir\neutron-root-ca.cer"
        if (Test-Path $caRootDest) { Write-SKIP "CA root cert already exported." }
        else {
            certutil -ca.cert "$caRootDest" 2>&1 | Out-Null
            if (-not (Test-Path $caRootDest)) {
                $rootCert = Get-ChildItem Cert:\LocalMachine\Root |
                            Where-Object { $_.Subject -like "*Neutron-Root-CA*" } |
                            Select-Object -First 1
                if ($rootCert) {
                    Export-Certificate -Cert $rootCert -FilePath $caRootDest -Type CERT | Out-Null
                    Write-OK "CA root cert exported (fallback): $caRootDest"
                }
                else { Write-ERR "CA root cert not found in store — retry after CA initialises." }
            }
            else { Write-OK "CA root cert exported: $caRootDest" }
        }
    }
    catch { Write-ERR "CA root cert export: $_" }

    $pfxPass = ConvertTo-SecureString "CertPass123" -AsPlainText -Force

    $certHosts = @(
        "corp.neutron.local",
        "shop.neutron.local",
        "files.neutron.local",
        "erp.neutron.local",
        "vpn.neutron.local"
    )

    foreach ($fqdn in $certHosts) {
        $short   = ($fqdn -split "\.")[0]
        $pfxPath = "$certDir\$short.pfx"
        try {
            if (Test-Path $pfxPath) { Write-SKIP "Cert already exported: $pfxPath"; continue }

            $cert = New-SelfSignedCertificate `
                -DnsName           @($fqdn, $short) `
                -Subject           "CN=$fqdn, O=Neutron Lab, C=CA" `
                -CertStoreLocation "Cert:\LocalMachine\My" `
                -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
                -KeyUsage DigitalSignature, KeyEncipherment `
                -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
                -NotAfter (Get-Date).AddYears(5) `
                -FriendlyName "Neutron Lab — $fqdn" `
                -ErrorAction Stop

            Export-PfxCertificate `
                -Cert "Cert:\LocalMachine\My\$($cert.Thumbprint)" `
                -FilePath $pfxPath -Password $pfxPass -Force | Out-Null

            Export-Certificate `
                -Cert "Cert:\LocalMachine\My\$($cert.Thumbprint)" `
                -FilePath "$certDir\$short.cer" -Type CERT | Out-Null

            Write-OK "Issued: $pfxPath"
        }
        catch { Write-ERR "Cert for $fqdn : $_" }
    }

    # -----------------------------------------------------------------------
    # Step 7 — IIS: serve certs over HTTP
    # -----------------------------------------------------------------------
    Write-Step "Step 7: Installing IIS and publishing certificates"

    try {
        $iis = Get-WindowsFeature -Name Web-Server
        if ($iis.Installed) { Write-SKIP "IIS already installed." }
        else {
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools `
                -WarningAction SilentlyContinue | Out-Null
            Write-OK "IIS installed."
        }
    }
    catch { Write-ERR "IIS install: $_" }

    try {
        $certsVdir = "C:\inetpub\wwwroot\certs"
        if (-not (Test-Path $certsVdir)) { New-Item -ItemType Directory -Path $certsVdir | Out-Null }

        Get-ChildItem -Path $certDir -File -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination (Join-Path $certsVdir $_.Name) -Force
            Write-OK "Published: $($_.Name)"
        }

        Start-Service W3SVC -ErrorAction SilentlyContinue
        Write-OK "IIS started.  Certs at http://$DC_IP/certs/"
    }
    catch { Write-ERR "IIS publish: $_" }

    # -----------------------------------------------------------------------
    # Step 8 — Windows Firewall rules
    # -----------------------------------------------------------------------
    Write-Step "Step 8: Opening Windows Firewall for lab services"

    $rules = @(
        @{ Name = "Allow-LDAP";           Proto = "TCP"; Port = 389  },
        @{ Name = "Allow-LDAPS";          Proto = "TCP"; Port = 636  },
        @{ Name = "Allow-Kerberos-TCP";   Proto = "TCP"; Port = 88   },
        @{ Name = "Allow-Kerberos-UDP";   Proto = "UDP"; Port = 88   },
        @{ Name = "Allow-DNS-TCP";        Proto = "TCP"; Port = 53   },
        @{ Name = "Allow-DNS-UDP";        Proto = "UDP"; Port = 53   },
        @{ Name = "Allow-SMB";            Proto = "TCP"; Port = 445  },
        @{ Name = "Allow-RPC";            Proto = "TCP"; Port = 135  },
        @{ Name = "Allow-HTTP";           Proto = "TCP"; Port = 80   },
        @{ Name = "Allow-HTTPS";          Proto = "TCP"; Port = 443  },
        @{ Name = "Allow-WinRM";          Proto = "TCP"; Port = 5985 },
        @{ Name = "Allow-ADCS-Enroll";    Proto = "TCP"; Port = 8080 }
    )

    foreach ($r in $rules) {
        try {
            if (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue) {
                Write-SKIP "Rule exists: $($r.Name)"
            }
            else {
                New-NetFirewallRule -DisplayName $r.Name -Direction Inbound `
                    -Protocol $r.Proto -LocalPort $r.Port -Action Allow -Enabled True | Out-Null
                Write-OK "Rule created: $($r.Name) ($($r.Proto)/$($r.Port))"
            }
        }
        catch { Write-ERR "Firewall rule '$($r.Name)': $_" }
    }

    Write-Host ""
    Write-Host "########################################################" -ForegroundColor Magenta
    Write-Host "  dc.ps1 Pass 2 complete." -ForegroundColor Magenta
    Write-Host "  neutron.local DC ready at $DC_IP" -ForegroundColor Magenta
    Write-Host "  Certs: http://$DC_IP/certs/" -ForegroundColor Magenta
    Write-Host "########################################################" -ForegroundColor Magenta
}
