# AUTOPWN TEST ENVIRONMENT - SETUP AND VERIFICATION GUIDE
# ─────────────────────────────────────────────────────────────────────────────

## Directory structure required

```
autopwn-test/
├── docker-compose.yml
├── wp_setup.sh
└── ldap_seed/
    └── users.ldif
```

## Step 1: Start the environment

```bash
# Start all containers
docker compose up -d

# Check all are running
docker compose ps

# Watch startup logs
docker compose logs -f
```

## Step 2: WordPress initial setup (run once, ~60 seconds after compose up)

```bash
chmod +x wp_setup.sh
./wp_setup.sh
```

## Step 3: Verify each target manually before running the script

### SSH target (172.28.0.10)
```bash
# Should connect with password: password123
ssh root@172.28.0.10 -o StrictHostKeyChecking=no
# password: password123
```

### MySQL target (172.28.0.11)
```bash
# Should connect with empty root password
mysql -h 172.28.0.11 -u root -e "SHOW DATABASES;"
```

### Redis target (172.28.0.12)
```bash
# Should respond without auth
redis-cli -h 172.28.0.12 PING
redis-cli -h 172.28.0.12 CONFIG GET maxmemory
```

### FTP target (172.28.0.13)
```bash
# Should allow anonymous login
ftp 172.28.0.13
# Login: anonymous
# Password: (blank or any email)
```

### SNMP target (172.28.0.14)
```bash
# Should respond to community string "public"
snmpwalk -v2c -c public 172.28.0.14
```

### DVWA target (172.28.0.21)
```bash
# Should load DVWA login page
curl -s http://172.28.0.21 | grep -i "dvwa"
# Browser: http://localhost:8080
# Login: admin / password
```

### WordPress target (172.28.0.31)
```bash
# Should load WordPress login page
curl -s http://172.28.0.31/wp-login.php | grep -i "login"
# Browser: http://localhost:8081
# Login: admin / password
```

### LDAP target (172.28.0.40)
```bash
# Should return users with anonymous bind
ldapsearch -x -H ldap://172.28.0.40 \
    -b "dc=neutron,dc=local" \
    "(objectClass=inetOrgPerson)" \
    uid mail
```

## Step 4: Run autopwn against the test CIDR

```bash
# From your autopwn/ directory
python3 autopwn.py --target 172.28.0.0/24 --dry-run

# Full run once dry-run looks correct
python3 autopwn.py --target 172.28.0.0/24
```

## Step 5: Module-by-module testing

Test each module independently against the containers.
Use the sample services.json from CLAUDE.md or generate one by running
discovery and enrichment against the Docker network first.

### Test ad_enum.py in isolation
```bash
# Feed it a minimal services.json pointing at the LDAP container
python3 -c "
import json, pathlib
data = {
    'hosts': [{
        'ip': '172.28.0.40',
        'hostname': 'ldap-target',
        'os_guess': 'Linux',
        'ports': [
            {'port': 389, 'protocol': 'tcp', 'state': 'open',
             'service': 'ldap', 'version': '', 'nse_results': {}},
        ],
        'flags': {'is_domain_controller': True, 'has_wordpress': False,
                  'has_dvwa': False, 'ms17_010_vulnerable': False}
    }]
}
pathlib.Path('state').mkdir(exist_ok=True)
pathlib.Path('state/services.json').write_text(json.dumps(data, indent=2))
print('Written state/services.json')
"
python3 modules/ad_enum.py
```

### Test exploits/ssh.py in isolation
```bash
python3 -c "
import sys; sys.path.insert(0, '.')
from modules.exploits.ssh import exploit_ssh
result = exploit_ssh('172.28.0.10')
print(result)
"
```

### Test exploits/database.py in isolation
```bash
python3 -c "
import sys; sys.path.insert(0, '.')
from modules.exploits.database import exploit_mysql, exploit_redis
print(exploit_mysql('172.28.0.11'))
print(exploit_redis('172.28.0.12'))
"
```

### Test exploits/web.py DVWA in isolation
```bash
python3 -c "
import sys; sys.path.insert(0, '.')
from modules.exploits.web import exploit_dvwa
print(exploit_dvwa('172.28.0.21'))
"
```

### Test exploits/web.py WordPress in isolation
```bash
python3 -c "
import sys; sys.path.insert(0, '.')
from modules.exploits.web import exploit_wordpress
print(exploit_wordpress('172.28.0.31'))
"
```

## What this environment does NOT test

The following require actual VMs and cannot be tested in Docker:

| Module / Path       | Reason                                      | What you need         |
|---------------------|---------------------------------------------|-----------------------|
| exploits/smb.py     | MS17-010 needs unpatched Windows            | 1x Windows 7/2008 VM  |
| exploits/winrm.py   | WinRM is a Windows-only service             | 1x Windows 10 VM      |
| ad_enum.py Kerberos | Real Kerberos needs AD or Samba4 DC         | Neutron Lab AD host   |
| postex.py Windows   | Windows commands need Windows shell         | 1x Windows VM         |

Strategy: build and verify all Docker-testable modules first, then spin up
only the two VMs you actually need (one Windows, one AD).

## Teardown

```bash
# Stop containers, keep volumes
docker compose down

# Stop and wipe all volumes (clean slate)
docker compose down -v

# Remove images too (full cleanup)
docker compose down -v --rmi all
```

## Container IP reference

| IP            | Hostname         | Service         | Credentials           |
|---------------|------------------|-----------------|-----------------------|
| 172.28.0.10   | ssh-target       | SSH :22         | root / password123    |
| 172.28.0.11   | mysql-target     | MySQL :3306     | root / (empty)        |
| 172.28.0.12   | redis-target     | Redis :6379     | no auth               |
| 172.28.0.13   | ftp-target       | FTP :21         | anonymous / (blank)   |
| 172.28.0.14   | snmp-target      | SNMP :161 UDP   | community: public     |
| 172.28.0.21   | dvwa-target      | HTTP :80        | admin / password      |
| 172.28.0.31   | wordpress-target | HTTP :80        | admin / password      |
| 172.28.0.40   | ldap-target      | LDAP :389       | anonymous bind        |
