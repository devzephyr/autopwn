#!/usr/bin/env python3
"""
modules/planner.py - Stage 4: Confidence Scoring and Attack Planning

Reads  : state/services.json  (and optionally state/ad_findings.json,
          state/exploitation.json for credential-availability checks)
Writes : state/attack_plan.json

Confidence thresholds:
  HIGH   score >= 3  -> added to executable attack_paths
  MEDIUM score 1-2   -> documented in medium_paths, not executed
  LOW    score == 0  -> discarded
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR  = Path(__file__).parent.parent
STATE_DIR = BASE_DIR / "state"

SERVICES_FILE     = STATE_DIR / "services.json"
AD_FINDINGS_FILE  = STATE_DIR / "ad_findings.json"
EXPLOIT_FILE      = STATE_DIR / "exploitation.json"
ATTACK_PLAN_FILE  = STATE_DIR / "attack_plan.json"

# ---------------------------------------------------------------------------
# Scoring rules (verbatim from CLAUDE.md spec)
# ---------------------------------------------------------------------------
SCORING_RULES: dict[str, list[tuple[str, int]]] = {
    "ms17_010": [
        ("port_445_open",          1),
        ("nse_ms17_010_vulnerable", 2),
        ("os_windows",             1),
        ("smb_signing_disabled",   1),
    ],
    "kerberoast": [
        ("port_88_open",              1),
        ("ldap_enumeration_success",  2),
        ("service_account_with_spn",  1),
    ],
    "wordpress_creds": [
        ("port_80_443_open",       1),
        ("wordpress_fingerprint",  2),
        ("wp_login_accessible",    1),
    ],
    "mysql_default": [
        ("port_3306_open",          1),
        ("mysql_empty_password_nse", 3),
    ],
    "redis_unauth": [
        ("port_6379_open",    1),
        ("redis_no_auth_nse", 3),
    ],
    "ssh_brute": [
        ("port_22_open",           1),
        ("ssh_password_auth_allowed", 2),
    ],
    "smb_null": [
        ("port_445_open",    1),
        ("smb_guest_access", 2),
    ],
    "ftp_anon": [
        ("port_21_open",  1),
        ("ftp_anon_nse",  3),
    ],
    "winrm_creds": [
        ("port_5985_open",        1),
        ("credentials_available", 3),
    ],
    "mssql_default": [
        ("port_1433_open",          1),
        ("mssql_empty_password_nse", 3),
    ],
    "mssql_xp_cmdshell": [
        ("port_1433_open",        1),
        ("credentials_available", 2),
        ("os_windows",            1),
    ],
    "rdp_bluekeep": [
        ("port_3389_open",      1),
        ("bluekeep_vulnerable", 3),
    ],
    "rdp_creds": [
        ("port_3389_open",        1),
        ("credentials_available", 3),
    ],
    "nfs_unauth": [
        ("port_2049_open",       1),
        ("nfs_world_readable_nse", 3),
    ],
    "nfs_enum": [
        ("port_2049_open", 2),
        ("port_111_open",  1),
    ],
    "smb_shares": [
        ("port_445_open",    1),
        ("smb_guest_access", 2),
        ("os_windows",       1),
    ],
    "nextcloud_creds": [
        ("port_80_443_open",        1),
        ("nextcloud_fingerprint",   3),
    ],
    "nextcloud_enum": [
        ("port_80_443_open",        1),
        ("nextcloud_fingerprint",   2),
    ],
}

# ---------------------------------------------------------------------------
# Severity ratings for every technique (used by report.py)
# ---------------------------------------------------------------------------
SEVERITY: dict[str, str] = {
    "ms17_010":         "Critical",
    "kerberoast":       "Critical",
    "mssql_default":    "Critical",
    "mssql_xp_cmdshell": "Critical",
    "rdp_bluekeep":     "Critical",
    "wordpress_creds":  "High",
    "winrm_creds":      "High",
    "mysql_default":    "High",
    "redis_unauth":     "High",
    "rdp_creds":        "High",
    "nfs_unauth":       "High",
    "smb_shares":       "High",
    "nextcloud_creds":  "High",
    "nextcloud_enum":   "Medium",
    "ssh_brute":        "Medium",
    "smb_null":         "Medium",
    "ftp_anon":         "Medium",
    "nfs_enum":         "Medium",
    "snmp_default":     "Low",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _load_json(path: Path) -> dict | None:
    """Return parsed JSON or None if the file is missing / unreadable."""
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _atomic_write(path: Path, data: dict) -> None:
    """Write JSON atomically: write to .tmp then os.rename()."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.rename(tmp, path)


def _open_ports(host: dict) -> set[int]:
    """Return the set of open TCP/UDP port numbers for a host."""
    return {
        p["port"]
        for p in host.get("ports", [])
        if p.get("state") == "open"
    }


def _all_nse(host: dict) -> dict[str, str]:
    """
    Merge nse_results from all ports into one flat dict.
    If multiple ports carry the same NSE key, the last value wins
    (acceptable for the condition checks below).
    """
    merged: dict[str, str] = {}
    for p in host.get("ports", []):
        for k, v in p.get("nse_results", {}).items():
            merged[k] = str(v)
    return merged


def _nse_contains(nse: dict[str, str], key: str, substring: str) -> bool:
    """True if nse[key] exists and contains substring (case-insensitive)."""
    val = nse.get(key, "")
    return substring.lower() in val.lower()


def _any_nse_contains(nse: dict[str, str], substring: str) -> bool:
    """True if any NSE value contains substring (case-insensitive)."""
    sub_lower = substring.lower()
    return any(sub_lower in v.lower() for v in nse.values())

# ---------------------------------------------------------------------------
# Global state loaded once per planner run
# ---------------------------------------------------------------------------
_ad_findings: dict | None = None
_exploit_data: dict | None = None


def _load_global_state() -> None:
    global _ad_findings, _exploit_data
    _ad_findings  = _load_json(AD_FINDINGS_FILE)
    _exploit_data = _load_json(EXPLOIT_FILE)


# ---------------------------------------------------------------------------
# Condition evaluators
# ---------------------------------------------------------------------------
# Each function accepts (host_dict, open_ports_set, merged_nse_dict)
# and returns True/False.

def _cond_port_445_open(host, ports, nse):
    return 445 in ports

def _cond_nse_ms17_010_vulnerable(host, ports, nse):
    val = nse.get("smb-vuln-ms17-010", "")
    # NSE reports "VULNERABLE" when confirmed; "NOT VULNERABLE" otherwise.
    return "VULNERABLE" in val and "NOT VULNERABLE" not in val

def _cond_os_windows(host, ports, nse):
    return "windows" in host.get("os_guess", "").lower()

def _cond_smb_signing_disabled(host, ports, nse):
    val = nse.get("smb-security-mode", "")
    return "signing: disabled" in val.lower() or "account_used: guest" in val.lower()

def _cond_port_88_open(host, ports, nse):
    return 88 in ports

def _cond_ldap_enumeration_success(host, ports, nse):
    if _ad_findings is None:
        return False
    return bool(_ad_findings.get("users"))

def _cond_service_account_with_spn(host, ports, nse):
    if _ad_findings is None:
        return False
    return bool(_ad_findings.get("kerberoast_hashes"))

def _cond_port_80_443_open(host, ports, nse):
    return 80 in ports or 443 in ports

def _cond_wordpress_fingerprint(host, ports, nse):
    if host.get("flags", {}).get("has_wordpress"):
        return True
    return _any_nse_contains(nse, "wordpress")

def _cond_wp_login_accessible(host, ports, nse):
    return _any_nse_contains(nse, "wp-login")

def _cond_mysql_empty_password_nse(host, ports, nse):
    val = nse.get("mysql-empty-password", "")
    return "empty password" in val.lower()

def _cond_port_3306_open(host, ports, nse):
    return 3306 in ports

def _cond_redis_no_auth_nse(host, ports, nse):
    # redis-info being present indicates an unauthenticated connection succeeded
    return "redis-info" in nse

def _cond_port_6379_open(host, ports, nse):
    return 6379 in ports

def _cond_port_22_open(host, ports, nse):
    return 22 in ports

def _cond_ssh_password_auth_allowed(host, ports, nse):
    val = nse.get("ssh-auth-methods", "")
    return "password" in val.lower()

def _cond_smb_guest_access(host, ports, nse):
    val = nse.get("smb-security-mode", "")
    return "guest" in val.lower()

def _cond_port_21_open(host, ports, nse):
    return 21 in ports

def _cond_ftp_anon_nse(host, ports, nse):
    return "ftp-anon" in nse

def _cond_port_5985_open(host, ports, nse):
    return 5985 in ports

def _cond_credentials_available(host, ports, nse):
    """True if any cracked credentials exist from AD enum or prior exploitation."""
    if _ad_findings and _ad_findings.get("cracked_credentials"):
        return True
    if _exploit_data:
        for result in _exploit_data.get("results", []):
            if result.get("credentials_recovered"):
                return True
    return False

def _cond_port_1433_open(host, ports, nse):
    return 1433 in ports

def _cond_port_3389_open(host, ports, nse):
    return 3389 in ports

def _cond_port_2049_open(host, ports, nse):
    return 2049 in ports

def _cond_port_111_open(host, ports, nse):
    return 111 in ports

def _cond_mssql_empty_password_nse(host, ports, nse):
    val = nse.get("ms-sql-empty-password", "")
    return "sa" in val.lower() or "empty" in val.lower()

def _cond_bluekeep_vulnerable(host, ports, nse):
    return bool(host.get("flags", {}).get("bluekeep_vulnerable"))

def _cond_nfs_world_readable_nse(host, ports, nse):
    if host.get("flags", {}).get("nfs_world_readable"):
        return True
    nfs_mount = nse.get("nfs-showmount", "")
    return "*" in nfs_mount

def _cond_nextcloud_fingerprint(host, ports, nse):
    if host.get("flags", {}).get("has_nextcloud"):
        return True
    for val in nse.values():
        if "nextcloud" in val.lower():
            return True
    return False


# Map condition name -> evaluator function
CONDITION_EVALUATORS: dict[str, callable] = {
    "port_445_open":             _cond_port_445_open,
    "nse_ms17_010_vulnerable":   _cond_nse_ms17_010_vulnerable,
    "os_windows":                _cond_os_windows,
    "smb_signing_disabled":      _cond_smb_signing_disabled,
    "port_88_open":              _cond_port_88_open,
    "ldap_enumeration_success":  _cond_ldap_enumeration_success,
    "service_account_with_spn":  _cond_service_account_with_spn,
    "port_80_443_open":          _cond_port_80_443_open,
    "wordpress_fingerprint":     _cond_wordpress_fingerprint,
    "wp_login_accessible":       _cond_wp_login_accessible,
    "mysql_empty_password_nse":  _cond_mysql_empty_password_nse,
    "port_3306_open":            _cond_port_3306_open,
    "redis_no_auth_nse":         _cond_redis_no_auth_nse,
    "port_6379_open":            _cond_port_6379_open,
    "port_22_open":              _cond_port_22_open,
    "ssh_password_auth_allowed": _cond_ssh_password_auth_allowed,
    "smb_guest_access":          _cond_smb_guest_access,
    "port_21_open":              _cond_port_21_open,
    "ftp_anon_nse":              _cond_ftp_anon_nse,
    "port_5985_open":            _cond_port_5985_open,
    "credentials_available":     _cond_credentials_available,
    "port_1433_open":            _cond_port_1433_open,
    "port_3389_open":            _cond_port_3389_open,
    "port_2049_open":            _cond_port_2049_open,
    "port_111_open":             _cond_port_111_open,
    "mssql_empty_password_nse":  _cond_mssql_empty_password_nse,
    "bluekeep_vulnerable":       _cond_bluekeep_vulnerable,
    "nfs_world_readable_nse":    _cond_nfs_world_readable_nse,
    "nextcloud_fingerprint":     _cond_nextcloud_fingerprint,
}

# ---------------------------------------------------------------------------
# Core scorer
# ---------------------------------------------------------------------------

def score_host(host: dict) -> list[dict]:
    """
    Evaluate all attack paths for a single host.

    Returns a list of path dicts (one per technique that scored > 0),
    each with keys: host, path, score, confidence, conditions_met.
    """
    ip    = host.get("ip", "unknown")
    ports = _open_ports(host)
    nse   = _all_nse(host)
    paths = []

    for technique, rules in SCORING_RULES.items():
        score          = 0
        conditions_met = []

        for condition_name, points in rules:
            evaluator = CONDITION_EVALUATORS.get(condition_name)
            if evaluator is None:
                # Unknown condition — skip silently so adding new rules
                # does not crash older code.
                continue
            try:
                met = evaluator(host, ports, nse)
            except Exception:
                met = False

            if met:
                score += points
                conditions_met.append(condition_name)

        if score == 0:
            continue  # No evidence at all — discard

        if score >= 3:
            confidence = "HIGH"
        elif score >= 1:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        paths.append({
            "host":           ip,
            "path":           technique,
            "confidence":     confidence,
            "score":          score,
            "conditions_met": conditions_met,
        })

    return paths

# ---------------------------------------------------------------------------
# run() — called by autopwn.py orchestrator
# ---------------------------------------------------------------------------

def run() -> None:
    """
    Main entry point.

    Loads state/services.json, scores every host against every attack path,
    separates HIGH from MEDIUM results, assigns priorities, and writes
    state/attack_plan.json atomically.
    """
    # ---- load services -------------------------------------------------------
    services = _load_json(SERVICES_FILE)
    if services is None:
        print(f"[planner] ERROR: {SERVICES_FILE} not found or unreadable.", file=sys.stderr)
        sys.exit(1)

    hosts = services.get("hosts", [])
    if not hosts:
        print("[planner] WARNING: services.json contains no hosts.", file=sys.stderr)

    # ---- load optional state files for cross-stage conditions ----------------
    _load_global_state()

    # ---- score ---------------------------------------------------------------
    all_scored: list[dict] = []
    for host in hosts:
        all_scored.extend(score_host(host))

    # ---- separate HIGH / MEDIUM paths ----------------------------------------
    high_paths   = [p for p in all_scored if p["confidence"] == "HIGH"]
    medium_paths = [p for p in all_scored if p["confidence"] == "MEDIUM"]

    # Sort HIGH by score descending; assign priority rank (1 = highest priority)
    high_paths.sort(key=lambda p: p["score"], reverse=True)
    for rank, path in enumerate(high_paths, start=1):
        path["priority"] = rank

    # Sort MEDIUM by score descending for reporting completeness
    medium_paths.sort(key=lambda p: p["score"], reverse=True)

    # ---- build output --------------------------------------------------------
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "attack_paths": high_paths,
        "medium_paths": medium_paths,
        "summary": {
            "total_hosts_evaluated": len(hosts),
            "high_confidence_paths": len(high_paths),
            "medium_confidence_paths": len(medium_paths),
        },
    }

    _atomic_write(ATTACK_PLAN_FILE, output)

    # ---- terminal summary ----------------------------------------------------
    print(f"[planner] Evaluated {len(hosts)} host(s) across {len(SCORING_RULES)} technique(s).")
    print(f"[planner] HIGH confidence paths  : {len(high_paths)}")
    print(f"[planner] MEDIUM confidence paths: {len(medium_paths)}")

    if high_paths:
        print("[planner] Prioritised attack queue:")
        for p in high_paths:
            conds = ", ".join(p["conditions_met"])
            print(
                f"  [{p['priority']:>2}] {p['host']:<18} "
                f"{p['path']:<20} score={p['score']}  ({conds})"
            )
    else:
        print("[planner] No HIGH-confidence paths found — nothing will be exploited.")

    if medium_paths:
        print("[planner] MEDIUM paths (documented, not executed):")
        for p in medium_paths:
            conds = ", ".join(p["conditions_met"])
            print(f"       {p['host']:<18} {p['path']:<20} score={p['score']}  ({conds})")

    print(f"[planner] Attack plan written to {ATTACK_PLAN_FILE}")


# ---------------------------------------------------------------------------
# Allow direct invocation for isolated testing
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    run()
