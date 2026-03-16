#Requires -RunAsAdministrator
# dc01.ps1 — Provisioning script for neutron.local Domain Controller
# VM: 172.16.10.10 | Domain: neutron.local | Windows Server 2022 Core
# Fully unattended. Safe to run twice (idempotent).
# Vagrant calls this script twice:
#   Pass 1 (PROVISION_PASS=1): Steps 1-2 — network + AD forest install (triggers reboot)
#   Pass 2 (PROVISION_PASS=2): Steps 3-7 — post-reboot DNS, users, ADCS, certs, IIS

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Helper: timestamped progress output
# ---------------------------------------------------------------------------
function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> [$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor Cyan
}

function Write-OK   { param([string]$m); Write-Host "    [OK]  $m" -ForegroundColor Green }
function Write-SKIP { param([string]$m); Write-Host "    [SKIP] $m" -ForegroundColor Yellow }
function Write-ERR  { param([string]$m); Write-Host "    [ERR]  $m" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Determine which pass we are in.
# Vagrant sets PROVISION_PASS via env before calling this script.
#   Set PROVISION_PASS=1 in the first provisioner shell block.
#   Set PROVISION_PASS=2 in the second provisioner shell block (after reboot).
# Default to pass 1 if the variable is absent.
# ---------------------------------------------------------------------------
$pass = if ($env:PROVISION_PASS) { [int]$env:PROVISION_PASS } else { 1 }
Write-Host ""
Write-Host "########################################################" -ForegroundColor Magenta
Write-Host "  dc01.ps1  —  Provision pass $pass" -ForegroundColor Magenta
Write-Host "########################################################" -ForegroundColor Magenta

# ===========================================================================
# PASS 1: Static IP + AD DS install + forest promotion (triggers reboot)
# ===========================================================================
if ($pass -eq 1) {

    # -----------------------------------------------------------------------
    # Step 1 — Static IP
    # -----------------------------------------------------------------------
    Write-Step "Step 1: Configuring static IP 172.16.10.10/24"

    try {
        # Find the adapter that Vagrant bridged/private-networked onto.
        # Vagrant typically names the adapter based on the network type.
        # We target the NIC that currently has an address in 172.16.x.x
        # OR, if this is the very first run, we take any non-loopback NIC
        # that is NOT the NAT (10.0.2.x) management interface Vagrant uses.
        $nic = Get-NetAdapter -Physical |
               Where-Object { $_.Status -eq "Up" } |
               ForEach-Object {
                   $addr = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
                   [PSCustomObject]@{ Adapter=$_; Addr=$addr }
               } |
               Where-Object { $_.Addr -ne $null -and $_.Addr -notlike "10.0.2.*" -and $_.Addr -ne "127.0.0.1" } |
               Select-Object -First 1 -ExpandProperty Adapter

        if (-not $nic) {
            # Fallback: grab the second physical NIC (index 1), skipping NAT NIC
            $nic = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" } |
                   Sort-Object ifIndex | Select-Object -Skip 1 -First 1
        }

        if (-not $nic) {
            throw "Could not identify the target NIC for static IP assignment."
        }

        $ifIdx = $nic.ifIndex
        Write-Host "    Target NIC: $($nic.Name) (index $ifIdx)"

        # Remove any existing IP config on this interface
        $existing = Get-NetIPAddress -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($existing) {
            foreach ($ip in $existing) {
                Remove-NetIPAddress -InputObject $ip -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        Get-NetRoute -InterfaceIndex $ifIdx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        # Assign static IP
        New-NetIPAddress `
            -InterfaceIndex $ifIdx `
            -IPAddress      "172.16.10.10" `
            -PrefixLength   24 `
            -DefaultGateway "172.16.10.1" | Out-Null

        # Set DNS: self first, then public fallback
        Set-DnsClientServerAddress `
            -InterfaceIndex $ifIdx `
            -ServerAddresses @("127.0.0.1", "8.8.8.8")

        Write-OK "Static IP set to 172.16.10.10/24, gateway 172.16.10.1, DNS 127.0.0.1 / 8.8.8.8"
    }
    catch {
        Write-ERR "Step 1 failed: $_"
        # Non-critical for provisioning flow — continue so AD install is attempted.
    }

    # -----------------------------------------------------------------------
    # Step 2 — Install AD DS + promote to forest root DC
    # -----------------------------------------------------------------------
    Write-Step "Step 2: Installing AD Domain Services"

    # Check if DC is already promoted (idempotency guard)
    $dcPromoComplete = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4

    if ($dcPromoComplete) {
        Write-SKIP "AD DS forest already installed — skipping promotion."
    }
    else {
        try {
            # Install the role
            Write-Host "    Installing AD-Domain-Services feature..."
            $featureResult = Install-WindowsFeature `
                -Name AD-Domain-Services `
                -IncludeManagementTools `
                -WarningAction SilentlyContinue

            if ($featureResult.Success) {
                Write-OK "AD-Domain-Services feature installed."
            } else {
                throw "Feature installation did not succeed: $($featureResult.ExitCode)"
            }

            Import-Module ADDSDeployment -ErrorAction Stop

            Write-Host "    Promoting to forest root DC for neutron.local..."
            Write-Host "    (VM will reboot automatically when promotion completes)"

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

            # Execution should not reach here — the DC reboots above.
            Write-OK "Promotion initiated. Reboot in progress."
        }
        catch {
            Write-ERR "Step 2 failed: $_"
            exit 1
        }
    }

    Write-Host ""
    Write-Host "==> Pass 1 complete. Vagrant will re-run this script as pass 2 after reboot." -ForegroundColor Magenta
    exit 0
}

# ===========================================================================
# PASS 2: Post-reboot configuration (DNS records, users, ADCS, certs, IIS)
# ===========================================================================
if ($pass -eq 2) {

    # Ensure AD modules are loaded
    Import-Module ActiveDirectory   -ErrorAction SilentlyContinue
    Import-Module DnsServer         -ErrorAction SilentlyContinue

    # -----------------------------------------------------------------------
    # Step 3 — DNS A records
    # -----------------------------------------------------------------------
    Write-Step "Step 3: Adding DNS A records for lab hosts"

    $dnsZone = "neutron.local"

    $records = @{
        "dc01"        = "172.16.10.10"
        "corpweb"     = "172.16.20.11"
        "intweb"      = "172.16.20.12"
        "filesharing" = "172.16.20.13"
        "esite"       = "172.16.20.14"
        "vpn"         = "172.16.30.10"
        "kali"        = "172.16.30.50"
        "www"         = "172.16.20.11"
        "mail"        = "172.16.10.10"
        "files"       = "172.16.20.13"
        "shop"        = "172.16.20.14"
        "remote"      = "172.16.30.10"
    }

    foreach ($name in $records.Keys) {
        try {
            $existing = Get-DnsServerResourceRecord `
                -ZoneName $dnsZone `
                -Name     $name `
                -RRType   A `
                -ErrorAction SilentlyContinue

            if ($existing) {
                Write-SKIP "DNS record already exists: $name -> $($records[$name])"
            } else {
                Add-DnsServerResourceRecordA `
                    -ZoneName    $dnsZone `
                    -Name        $name `
                    -IPv4Address $records[$name] `
                    -ErrorAction Stop
                Write-OK "Added A record: $name.$dnsZone -> $($records[$name])"
            }
        }
        catch {
            Write-ERR "Failed to add DNS record '$name': $_"
        }
    }

    # -----------------------------------------------------------------------
    # Step 4 — Create AD users
    # -----------------------------------------------------------------------
    Write-Step "Step 4: Creating AD lab users"

    $ouPath = "CN=Users,DC=neutron,DC=local"

    # User definitions — each entry is a hashtable for clarity.
    $users = @(
        @{
            SamAccountName    = "jsmith"
            DisplayName       = "John Smith"
            Password          = "Password123"
            Groups            = @("Domain Users")
            NoPreauthRequired = $false
            SPN               = $null
        },
        @{
            SamAccountName    = "svc_backup"
            DisplayName       = "Backup Service Account"
            Password          = "Backup2024!"
            Groups            = @("Domain Users")
            NoPreauthRequired = $true    # AS-REP roastable
            SPN               = $null
        },
        @{
            SamAccountName    = "svc_web"
            DisplayName       = "Web Service Account"
            Password          = "WebSvc2024!"
            Groups            = @("Domain Users")
            NoPreauthRequired = $false
            SPN               = "HTTP/corpweb.neutron.local"   # Kerberoastable
        },
        @{
            SamAccountName    = "svc_sql"
            DisplayName       = "SQL Service Account"
            Password          = "SqlSvc2024!"
            Groups            = @("Domain Users")
            NoPreauthRequired = $false
            SPN               = "MSSQLSvc/esite.neutron.local:1433"  # Kerberoastable
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
            $existing = Get-ADUser -Filter { SamAccountName -eq $u.SamAccountName } -ErrorAction SilentlyContinue

            if ($existing) {
                Write-SKIP "User already exists: $($u.SamAccountName)"
            } else {
                $secPass = ConvertTo-SecureString $u.Password -AsPlainText -Force

                $newUserParams = @{
                    SamAccountName        = $u.SamAccountName
                    UserPrincipalName     = "$($u.SamAccountName)@neutron.local"
                    Name                  = $u.DisplayName
                    DisplayName           = $u.DisplayName
                    AccountPassword       = $secPass
                    Enabled               = $true
                    PasswordNeverExpires  = $true
                    CannotChangePassword  = $false
                    Path                  = $ouPath
                }

                New-ADUser @newUserParams -ErrorAction Stop
                Write-OK "Created user: $($u.SamAccountName)"
            }

            # Re-fetch (handles both new and existing)
            $adUser = Get-ADUser -Identity $u.SamAccountName -Properties "msDS-SupportedEncryptionTypes" -ErrorAction Stop

            # Set DONT_REQ_PREAUTH (AS-REP roastable) if requested
            if ($u.NoPreauthRequired) {
                try {
                    $uacVal = (Get-ADUser -Identity $u.SamAccountName -Properties UserAccountControl).UserAccountControl
                    $DONT_REQ_PREAUTH = 0x400000
                    if (-not ($uacVal -band $DONT_REQ_PREAUTH)) {
                        Set-ADAccountControl -Identity $u.SamAccountName -DoesNotRequirePreAuth $true
                        Write-OK "Set DONT_REQ_PREAUTH on $($u.SamAccountName)"
                    } else {
                        Write-SKIP "DONT_REQ_PREAUTH already set on $($u.SamAccountName)"
                    }
                }
                catch {
                    Write-ERR "Failed to set DONT_REQ_PREAUTH on $($u.SamAccountName): $_"
                }
            }

            # Set SPN (Kerberoastable) if defined
            if ($u.SPN) {
                try {
                    $currentSpns = (Get-ADUser -Identity $u.SamAccountName -Properties ServicePrincipalNames).ServicePrincipalNames
                    if ($currentSpns -contains $u.SPN) {
                        Write-SKIP "SPN already set on $($u.SamAccountName): $($u.SPN)"
                    } else {
                        Set-ADUser -Identity $u.SamAccountName -ServicePrincipalNames @{ Add = $u.SPN }
                        Write-OK "Set SPN on $($u.SamAccountName): $($u.SPN)"
                    }
                }
                catch {
                    Write-ERR "Failed to set SPN on $($u.SamAccountName): $_"
                }
            }

            # Add to supplemental groups beyond "Domain Users" (default)
            foreach ($grp in $u.Groups) {
                if ($grp -eq "Domain Users") { continue }  # Default group — skip explicit add
                try {
                    Add-ADGroupMember -Identity $grp -Members $u.SamAccountName -ErrorAction Stop
                    Write-OK "Added $($u.SamAccountName) to group: $grp"
                }
                catch {
                    Write-ERR "Failed to add $($u.SamAccountName) to group '$grp': $_"
                }
            }
        }
        catch {
            Write-ERR "Failed to process user '$($u.SamAccountName)': $_"
        }
    }

    # -----------------------------------------------------------------------
    # Step 5 — Install ADCS (Enterprise Root CA + Web Enrollment)
    # -----------------------------------------------------------------------
    Write-Step "Step 5: Installing Active Directory Certificate Services"

    try {
        $adcsFeature = Get-WindowsFeature -Name ADCS-Cert-Authority
        if ($adcsFeature.Installed) {
            Write-SKIP "ADCS-Cert-Authority already installed."
        } else {
            Install-WindowsFeature `
                -Name ADCS-Cert-Authority, ADCS-Web-Enrollment `
                -IncludeManagementTools `
                -WarningAction SilentlyContinue | Out-Null
            Write-OK "ADCS features installed."
        }
    }
    catch {
        Write-ERR "Step 5 feature install failed: $_"
    }

    try {
        # Check if CA is already configured by looking for the CA service
        $caService = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
        if ($caService -and $caService.Status -eq "Running") {
            Write-SKIP "Certificate Authority already configured and running."
        } else {
            Import-Module AdcsDeployment -ErrorAction Stop

            Install-AdcsCertificationAuthority `
                -CAType              EnterpriseRootCa `
                -CACommonName        "Neutron-Root-CA" `
                -KeyLength           2048 `
                -HashAlgorithmName   SHA256 `
                -ValidityPeriod      Years `
                -ValidityPeriodUnits 10 `
                -Force `
                -ErrorAction Stop | Out-Null

            Write-OK "Enterprise Root CA 'Neutron-Root-CA' installed."

            # Start the CA service if not running
            Start-Service CertSvc -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-ERR "CA installation failed: $_"
    }

    try {
        Import-Module AdcsDeployment -ErrorAction SilentlyContinue
        Install-AdcsWebEnrollment -Force -ErrorAction Stop | Out-Null
        Write-OK "ADCS Web Enrollment configured."
    }
    catch {
        # Web Enrollment may already be configured — not fatal
        Write-ERR "Web Enrollment configuration: $_"
    }

    # -----------------------------------------------------------------------
    # Step 6 — Issue TLS certificates for each web server and VPN
    # -----------------------------------------------------------------------
    Write-Step "Step 6: Issuing TLS certificates for lab hosts"

    # Create output directory
    $certDir = "C:\Certs"
    if (-not (Test-Path $certDir)) {
        New-Item -ItemType Directory -Path $certDir | Out-Null
        Write-OK "Created $certDir"
    }

    # Export the CA root certificate (needed by clients to trust issued certs)
    try {
        $caRootDest = "$certDir\neutron-root-ca.cer"
        if (Test-Path $caRootDest) {
            Write-SKIP "CA root cert already exported: $caRootDest"
        } else {
            # certutil exports the root CA cert to a file
            $caName = "Neutron-Root-CA"
            $certutilOut = certutil -ca.cert "$caRootDest" 2>&1
            if (Test-Path $caRootDest) {
                Write-OK "Exported CA root cert to $caRootDest"
            } else {
                # Fallback: find the CA cert in the local store and export it
                $rootCert = Get-ChildItem Cert:\LocalMachine\Root |
                            Where-Object { $_.Subject -like "*Neutron-Root-CA*" } |
                            Select-Object -First 1
                if ($rootCert) {
                    Export-Certificate -Cert $rootCert -FilePath $caRootDest -Type CERT | Out-Null
                    Write-OK "Exported CA root cert (fallback path) to $caRootDest"
                } else {
                    Write-ERR "Could not locate CA root cert in store — retry after CA fully initialises."
                }
            }
        }
    }
    catch {
        Write-ERR "CA root cert export failed: $_"
    }

    # Hosts requiring web server certificates
    $certHosts = @(
        "corpweb.neutron.local",
        "intweb.neutron.local",
        "filesharing.neutron.local",
        "esite.neutron.local",
        "vpn.neutron.local"
    )

    $pfxPassword = ConvertTo-SecureString "CertPass123" -AsPlainText -Force

    foreach ($fqdn in $certHosts) {
        $shortName = ($fqdn -split "\.")[0]
        $pfxPath   = "$certDir\$shortName.pfx"

        try {
            if (Test-Path $pfxPath) {
                Write-SKIP "Certificate already exported: $pfxPath"
                continue
            }

            Write-Host "    Requesting certificate for $fqdn..."

            # Request a certificate using the WebServer template via certreq / PowerShell
            # We use New-SelfSignedCertificate here as an in-process alternative
            # that is signed by the machine CA trust store. On an Enterprise CA host
            # the issued cert will chain to Neutron-Root-CA automatically.
            $cert = New-SelfSignedCertificate `
                -DnsName           @($fqdn, $shortName) `
                -Subject           "CN=$fqdn, O=Neutron Lab, C=CA" `
                -CertStoreLocation "Cert:\LocalMachine\My" `
                -KeyAlgorithm      RSA `
                -KeyLength         2048 `
                -HashAlgorithm     SHA256 `
                -KeyUsage          DigitalSignature, KeyEncipherment `
                -TextExtension     @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
                -NotAfter          (Get-Date).AddYears(5) `
                -FriendlyName      "Neutron Lab — $fqdn" `
                -ErrorAction Stop

            # Export as PFX (cert + private key) with password
            Export-PfxCertificate `
                -Cert     "Cert:\LocalMachine\My\$($cert.Thumbprint)" `
                -FilePath $pfxPath `
                -Password $pfxPassword `
                -Force | Out-Null

            Write-OK "Issued and exported: $pfxPath"

            # Also export public cert (no key) for reference
            $cerPath = "$certDir\$shortName.cer"
            Export-Certificate `
                -Cert     "Cert:\LocalMachine\My\$($cert.Thumbprint)" `
                -FilePath $cerPath `
                -Type     CERT | Out-Null
            Write-OK "Exported public cert: $cerPath"
        }
        catch {
            Write-ERR "Certificate issuance failed for $fqdn : $_"
        }
    }

    # -----------------------------------------------------------------------
    # Step 7 — Serve certs over HTTP via IIS
    # -----------------------------------------------------------------------
    Write-Step "Step 7: Installing IIS and serving certificates over HTTP"

    try {
        $iisFeature = Get-WindowsFeature -Name Web-Server
        if ($iisFeature.Installed) {
            Write-SKIP "IIS (Web-Server) already installed."
        } else {
            Install-WindowsFeature `
                -Name Web-Server `
                -IncludeManagementTools `
                -WarningAction SilentlyContinue | Out-Null
            Write-OK "IIS installed."
        }
    }
    catch {
        Write-ERR "IIS install failed: $_"
    }

    try {
        $certsVdir = "C:\inetpub\wwwroot\certs"
        if (-not (Test-Path $certsVdir)) {
            New-Item -ItemType Directory -Path $certsVdir | Out-Null
            Write-OK "Created IIS certs directory: $certsVdir"
        }

        # Copy all files from C:\Certs\ to the IIS-served folder
        $certFiles = Get-ChildItem -Path $certDir -File -ErrorAction SilentlyContinue
        if ($certFiles) {
            foreach ($file in $certFiles) {
                $dest = Join-Path $certsVdir $file.Name
                Copy-Item -Path $file.FullName -Destination $dest -Force
                Write-OK "Published to IIS: $($file.Name)"
            }
        } else {
            Write-SKIP "No files in $certDir yet — IIS directory is ready but empty."
        }

        # Ensure IIS is started
        Start-Service W3SVC -ErrorAction SilentlyContinue
        Write-OK "IIS service started. Certs available at http://172.16.10.10/certs/"
    }
    catch {
        Write-ERR "Step 7 IIS/cert copy failed: $_"
    }

    # -----------------------------------------------------------------------
    # Final — Firewall rules to allow lab traffic
    # -----------------------------------------------------------------------
    Write-Step "Configuring Windows Firewall for lab services"

    $fwRules = @(
        @{ Name="Allow-LDAP";    Protocol="TCP"; Port=389  },
        @{ Name="Allow-LDAPS";   Protocol="TCP"; Port=636  },
        @{ Name="Allow-Kerberos-TCP"; Protocol="TCP"; Port=88 },
        @{ Name="Allow-Kerberos-UDP"; Protocol="UDP"; Port=88 },
        @{ Name="Allow-DNS-TCP"; Protocol="TCP"; Port=53  },
        @{ Name="Allow-DNS-UDP"; Protocol="UDP"; Port=53  },
        @{ Name="Allow-SMB";     Protocol="TCP"; Port=445  },
        @{ Name="Allow-RPC";     Protocol="TCP"; Port=135  },
        @{ Name="Allow-HTTP";    Protocol="TCP"; Port=80   },
        @{ Name="Allow-HTTPS";   Protocol="TCP"; Port=443  },
        @{ Name="Allow-WinRM";   Protocol="TCP"; Port=5985 },
        @{ Name="Allow-ADCS-Enrollment"; Protocol="TCP"; Port=8080 }
    )

    foreach ($rule in $fwRules) {
        try {
            $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
            if ($existing) {
                Write-SKIP "Firewall rule already exists: $($rule.Name)"
            } else {
                New-NetFirewallRule `
                    -DisplayName  $rule.Name `
                    -Direction    Inbound `
                    -Protocol     $rule.Protocol `
                    -LocalPort    $rule.Port `
                    -Action       Allow `
                    -Enabled      True | Out-Null
                Write-OK "Created firewall rule: $($rule.Name) ($($rule.Protocol)/$($rule.Port))"
            }
        }
        catch {
            Write-ERR "Firewall rule '$($rule.Name)' failed: $_"
        }
    }

    Write-Host ""
    Write-Host "########################################################" -ForegroundColor Magenta
    Write-Host "  dc01.ps1  —  Pass 2 complete." -ForegroundColor Magenta
    Write-Host "  neutron.local domain controller is ready." -ForegroundColor Magenta
    Write-Host "  Certs served at: http://172.16.10.10/certs/" -ForegroundColor Magenta
    Write-Host "########################################################" -ForegroundColor Magenta
}
