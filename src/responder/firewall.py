"""
firewall.py
Executes iptables block/unblock commands.
DRY_RUN=True by default so tests never touch the real firewall.
Set DRY_RUN=False in production.
"""

import subprocess
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Set to False on real VPS deployment
DRY_RUN = True

# In-memory record of blocked IPs: ip → {blocked_at, duration_minutes, reason}
_blocked: dict[str, dict] = {}


def _run(cmd: list[str]) -> bool:
    if DRY_RUN:
        logger.info(f"[DRY-RUN] {' '.join(cmd)}")
        return True
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            logger.error(f"iptables error: {result.stderr}")
            return False
        return True
    except Exception as e:
        logger.error(f"iptables exception: {e}")
        return False


def block_ip(ip: str, duration_minutes: int = 1440, reason: str = "") -> bool:
    """Block an IP via iptables INPUT DROP rule."""
    if ip in _blocked:
        return True   # already blocked

    success = _run([
        "iptables", "-A", "INPUT",
        "-s", ip,
        "-j", "DROP",
        "-m", "comment", "--comment", f"hackverse-ids:{reason[:40]}"
    ])

    if success:
        _blocked[ip] = {
            "blocked_at":       datetime.now(timezone.utc).isoformat(),
            "duration_minutes": duration_minutes,
            "reason":           reason,
        }
        logger.info(f"[FIREWALL] Blocked {ip} for {duration_minutes}m — {reason}")

    return success


def unblock_ip(ip: str) -> bool:
    """Remove iptables block rule for an IP."""
    if ip not in _blocked:
        return True

    success = _run([
        "iptables", "-D", "INPUT",
        "-s", ip,
        "-j", "DROP"
    ])

    if success:
        del _blocked[ip]
        logger.info(f"[FIREWALL] Unblocked {ip}")

    return success


def is_blocked(ip: str) -> bool:
    return ip in _blocked


def get_blocked_list() -> dict:
    return dict(_blocked)


def apply_decision(record: dict) -> dict:
    """
    Called after decision.py — executes the firewall action if needed.
    Returns the record enriched with firewall_action field.
    """
    level  = record.get("response_level", 1)
    ip     = record.get("ip", "")
    reason = record.get("justification", "")[:80]

    cfg    = _load_duration_config()
    action = "none"

    if level == 4 and ip:
        ok = block_ip(ip, duration_minutes=cfg["block_long_minutes"], reason=reason)
        action = "blocked" if ok else "block_failed"

    elif level == 3 and ip:
        # Rate limiting: lighter block, shorter duration
        ok = block_ip(ip, duration_minutes=cfg["block_temp_minutes"], reason=f"SLOWDOWN:{reason}")
        action = "rate_limited" if ok else "rate_limit_failed"

    return {**record, "firewall_action": action}


def _load_duration_config() -> dict:
    try:
        import yaml
        with open("config/config.yaml") as f:
            cfg = yaml.safe_load(f)
        return cfg.get("ssh_thresholds", {})
    except Exception:
        return {"block_temp_minutes": 60, "block_long_minutes": 1440}
