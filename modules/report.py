"""
Stage 8: HTML Report Generator
Reads all state JSON checkpoint files and renders a professional HTML report
using Jinja2 + Bootstrap 5.
"""

import json
import pathlib
import datetime
import shutil
from jinja2 import Environment, FileSystemLoader

# ---------------------------------------------------------------------------
# Severity mapping (must match planner.py technique names)
# ---------------------------------------------------------------------------
SEVERITY = {
    "ms17_010":        "Critical",
    "kerberoast":      "Critical",
    "wordpress_creds": "High",
    "winrm_creds":     "High",
    "mysql_default":   "High",
    "redis_unauth":    "High",
    "ssh_brute":       "Medium",
    "smb_null":        "Medium",
    "ftp_anon":        "Medium",
    "snmp_default":    "Low",
    "snmp_community":  "Medium",
    "docker_unauth":   "Critical",
    "password_spray":  "High",
    "kerbrute_spray":  "High",
}

# Bootstrap badge classes keyed by severity label
SEVERITY_CLASS = {
    "Critical": "danger",
    "High":     "warning",
    "Medium":   "info",
    "Low":      "secondary",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent  # autopwn/


def _load_json(rel_path: str) -> dict | list:
    """Load a JSON state file relative to BASE_DIR. Returns empty dict on missing/corrupt."""
    full = BASE_DIR / rel_path
    if not full.exists():
        return {}
    try:
        return json.loads(full.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _atomic_write(path: pathlib.Path, content: str) -> None:
    """Write content to path atomically via a .tmp intermediate file."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.rename(path)


# ---------------------------------------------------------------------------
# Stats computation
# ---------------------------------------------------------------------------

def _compute_stats(discovery, services, exploitation, attack_plan):
    """Return a stats dict used in the Executive Summary section."""
    # Hosts discovered
    hosts_discovered = len(discovery.get("hosts", []))

    # Services count: sum of open ports across all enriched hosts
    services_count = sum(
        len(h.get("ports", []))
        for h in services.get("hosts", [])
    )

    # Successful exploits
    results = exploitation.get("results", [])
    successful = [r for r in results if r.get("success")]
    vulns_confirmed = len(successful)

    # Severity breakdown
    severity_breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in successful:
        technique = r.get("technique", "")
        sev = SEVERITY.get(technique, "Low")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    # Per-host exploitation outcome
    host_outcomes = {}
    for r in results:
        ip = r.get("host", "unknown")
        if ip not in host_outcomes:
            host_outcomes[ip] = {"success": False, "technique": "", "evidence": ""}
        if r.get("success"):
            host_outcomes[ip] = {
                "success": True,
                "technique": r.get("technique", ""),
                "evidence": r.get("evidence", ""),
            }

    return {
        "hosts_discovered":   hosts_discovered,
        "services_count":     services_count,
        "vulns_confirmed":    vulns_confirmed,
        "severity_breakdown": severity_breakdown,
        "host_outcomes":      host_outcomes,
    }


# ---------------------------------------------------------------------------
# Host card assembly
# ---------------------------------------------------------------------------

def _build_host_cards(services, exploitation, postex, attack_plan):
    """
    Merge per-host data from services.json, exploitation.json, postex.json,
    and attack_plan.json into a list of dicts consumed by the template.
    """
    # Index exploitation results by host IP
    exploit_by_host: dict[str, list] = {}
    for r in exploitation.get("results", []):
        ip = r.get("host", "")
        exploit_by_host.setdefault(ip, []).append(r)

    # Index post-exploitation by host IP
    postex_by_host: dict[str, dict] = {}
    for h in postex.get("hosts", []):
        postex_by_host[h.get("ip", "")] = h

    # Index attack paths by host IP
    paths_by_host: dict[str, list] = {}
    for p in attack_plan.get("attack_paths", []):
        ip = p.get("host", "")
        paths_by_host.setdefault(ip, []).append(p)

    cards = []
    for host in services.get("hosts", []):
        ip = host.get("ip", "")
        exploits = exploit_by_host.get(ip, [])
        exploited = any(e.get("success") for e in exploits)
        postex_data = postex_by_host.get(ip, {})
        has_postex = bool(postex_data.get("commands_run"))

        # Status label for badge
        if exploited:
            status = "Exploited"
        elif has_postex:
            status = "Enumerated"
        else:
            status = "Not compromised"

        # Annotate each exploit result with severity
        annotated_exploits = []
        for e in exploits:
            tech = e.get("technique", "")
            annotated_exploits.append({
                **e,
                "severity":       SEVERITY.get(tech, "Low"),
                "severity_class": SEVERITY_CLASS.get(SEVERITY.get(tech, "Low"), "secondary"),
            })

        cards.append({
            "ip":               ip,
            "hostname":         host.get("hostname", ip),
            "os_guess":         host.get("os_guess", "Unknown"),
            "ports":            host.get("ports", []),
            "flags":            host.get("flags", {}),
            "status":           status,
            "exploited":        exploited,
            "attack_paths":     paths_by_host.get(ip, []),
            "exploits":         annotated_exploits,
            "postex":           postex_data,
        })

    return cards


# ---------------------------------------------------------------------------
# Main run() entry point
# ---------------------------------------------------------------------------

def run():
    print("[*] Stage 8: Generating HTML report...")

    # ------------------------------------------------------------------
    # 1. Load all state files (missing files return empty dicts/lists)
    # ------------------------------------------------------------------
    discovery    = _load_json("state/discovery.json")
    services     = _load_json("state/services.json")
    ad_findings  = _load_json("state/ad_findings.json")
    attack_plan  = _load_json("state/attack_plan.json")
    exploitation = _load_json("state/exploitation.json")
    lateral      = _load_json("state/lateral.json")
    postex       = _load_json("state/postex.json")
    timeline     = _load_json("state/timeline.json")

    # Normalise: exploitation may be a list (older schema) or a dict
    if isinstance(exploitation, list):
        exploitation = {"results": exploitation}
    if isinstance(timeline, list):
        timeline = {"events": timeline}

    # ------------------------------------------------------------------
    # 2. Compute derived stats
    # ------------------------------------------------------------------
    stats = _compute_stats(discovery, services, exploitation, attack_plan)

    # ------------------------------------------------------------------
    # 3. Build per-host card data
    # ------------------------------------------------------------------
    host_cards = _build_host_cards(services, exploitation, postex, attack_plan)

    # ------------------------------------------------------------------
    # 4. Build template context
    # ------------------------------------------------------------------
    generated_at = datetime.datetime.now()
    timestamp_str = generated_at.strftime("%Y%m%d_%H%M%S")

    # Annotate lateral reuse events with severity class for template
    reuse_events = []
    for event in lateral.get("reuse_events", []):
        reuse_events.append({
            **event,
            "status_class": "success" if event.get("success") else "danger",
        })

    # Annotate timeline events
    timeline_events = []
    for event in timeline.get("events", []):
        timeline_events.append(event)

    context = {
        "generated_at":       generated_at.strftime("%Y-%m-%d %H:%M:%S"),
        "cidr":               discovery.get("cidr", "N/A"),
        "stats":              stats,
        "severity_class":     SEVERITY_CLASS,
        "host_cards":         host_cards,
        "ad_findings":        ad_findings,
        "reuse_events":       reuse_events,
        "timeline_events":    timeline_events,
        "postex_hosts":       postex.get("hosts", []),
        "attack_paths":       attack_plan.get("attack_paths", []),
        "exploitation_results": exploitation.get("results", []),
    }

    # ------------------------------------------------------------------
    # 5. Render template
    # ------------------------------------------------------------------
    templates_dir = BASE_DIR / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=True,
    )
    template = env.get_template("report.html")
    html_output = template.render(**context)

    # ------------------------------------------------------------------
    # 6. Write output files atomically
    # ------------------------------------------------------------------
    output_dir = BASE_DIR / "output"
    output_dir.mkdir(exist_ok=True)

    timestamped_path = output_dir / f"report_{timestamp_str}.html"
    latest_path      = output_dir / "report_latest.html"

    _atomic_write(timestamped_path, html_output)

    # Copy (not symlink) for portability across filesystems
    shutil.copy2(timestamped_path, latest_path)

    print(f"[+] Report written to: {timestamped_path}")
    print(f"[+] Latest report:     {latest_path}")
    return str(timestamped_path)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    run()
