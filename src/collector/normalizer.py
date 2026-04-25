"""
normalizer.py
Converts all log sources (Apache, SSH, Network) into a unified dict format.
"""

import pandas as pd
import hashlib
from datetime import datetime, timezone


MALICIOUS_AGENTS = ["nikto", "sqlmap", "masscan", "nmap", "zgrab",
                    "python-requests", "curl", "go-http-client"]
SENSITIVE_PATHS  = [".env", ".git", "phpmyadmin", "backup.sql",
                    "config.php", "wp-admin", "passwd"]
SQLI_PATTERNS    = ["drop table", "select ", "union ", "' or ", "'--",
                    "1=1", "sleep(", "benchmark("]
TRAVERSAL        = ["../", "..\\", "/etc/", "/proc/"]


def _hash_content(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Apache ────────────────────────────────────────────────────────────────────

def load_apache(filepath: str) -> list[dict]:
    df = pd.read_csv(filepath, header=0, low_memory=False)

    def _get_label(row):
        for col in ["Unnamed: 7", "Unnamed: 8"]:
            val = str(row.get(col, "")).strip().lower()
            if val in ["legit", "attack", "scan"]:
                return val
        # unlabeled rows with known bad agents from external IPs → scan
        agent = str(row.get("user_agent", "")).lower()
        ip    = str(row.get("ip", ""))
        if not ip.startswith("10."):
            for bad in MALICIOUS_AGENTS:
                if bad in agent:
                    return "scan"
        return "legit"

    def _safe_int(val, default=0):
        try:
            return int(str(val).strip())
        except (ValueError, TypeError):
            return default

    records = []
    for _, row in df.iterrows():
        raw = ",".join(str(v) for v in row.values)

        # ── Column-shift fix ────────────────────────────────────────────────
        # SQLi paths contain a comma e.g. "/api/users?id=1, DROP TABLE users"
        # The CSV parser splits this → status col gets " DROP TABLE users"
        # Detect by checking if status is not numeric → reconstruct columns
        status_raw = str(row.get("status", "")).strip()
        if not status_raw.lstrip("-").isdigit():
            # Shifted row: real_path = path + "," + status
            #              real_status = bytes, real_bytes = user_agent
            full_path  = str(row.get("path", "")).strip() + "," + status_raw
            status     = _safe_int(row.get("bytes", 0))
            bytes_val  = _safe_int(row.get("user_agent", 0))
            agent      = ""           # agent not available in shifted rows
        else:
            full_path  = str(row.get("path", "")).strip()
            status     = _safe_int(status_raw)
            bytes_val  = _safe_int(row.get("bytes", 0))
            agent      = str(row.get("user_agent", "")).strip()

        path_lower  = full_path.lower()
        agent_lower = agent.lower()

        rec = {
            "source":           "apache",
            "timestamp_log":    str(row.get("timestamp", "")),
            "timestamp_recv":   _now_utc(),
            "ip":               str(row.get("ip", "")).strip(),
            "method":           str(row.get("method", "")).strip(),
            "path":             full_path,
            "status":           status,
            "bytes":            bytes_val,
            "user_agent":       agent,
            "label":            _get_label(row),
            # derived features
            "ip_is_external":   not str(row.get("ip", "")).startswith("10."),
            "agent_malicious":  any(b in agent_lower for b in MALICIOUS_AGENTS),
            "path_traversal":   any(t in path_lower  for t in TRAVERSAL),
            "path_sqli":        any(s in path_lower  for s in SQLI_PATTERNS),
            "path_sensitive":   any(p in path_lower  for p in SENSITIVE_PATHS),
            # integrity
            "log_hash":         _hash_content(raw),
            "integrity_ok":     True,
        }
        records.append(rec)
    return records


# ── SSH ───────────────────────────────────────────────────────────────────────

def load_ssh(filepath: str) -> list[dict]:
    df = pd.read_csv(filepath)
    records = []
    for _, row in df.iterrows():
        raw   = ",".join(str(v) for v in row.values)
        event = str(row.get("event", "")).strip()
        rec = {
            "source":          "ssh",
            "timestamp_log":   str(row.get("timestamp", "")),
            "timestamp_recv":  _now_utc(),
            "ip":              str(row.get("ip", "")).strip(),
            "user":            str(row.get("user", "")).strip(),
            "event":           event,
            "port":            row.get("port", 22),
            "label":           "attack" if event == "Failed password" else "legit",
            "ip_is_external":  not str(row.get("ip", "")).startswith("10."),
            "log_hash":        _hash_content(raw),
            "integrity_ok":    True,
        }
        records.append(rec)
    return records


# ── Network flows ─────────────────────────────────────────────────────────────

SENSITIVE_PORTS = {22, 3306, 5432, 6379, 27017, 1433, 23, 21}

def load_network(filepath: str) -> list[dict]:
    df = pd.read_csv(filepath)
    records = []
    for _, row in df.iterrows():
        raw      = ",".join(str(v) for v in row.values)
        src_ip   = str(row.get("src_ip", "")).strip()
        dst_port = int(row.get("dst_port", 0))
        flags    = str(row.get("flags", "")).strip()
        rec = {
            "source":              "network",
            "timestamp_log":       str(row.get("timestamp", "")),
            "timestamp_recv":      _now_utc(),
            "ip":                  src_ip,
            "src_ip":              src_ip,
            "dst_ip":              str(row.get("dst_ip", "")).strip(),
            "src_port":            int(row.get("src_port", 0)),
            "dst_port":            dst_port,
            "protocol":            str(row.get("protocol", "")).strip(),
            "bytes_sent":          int(row.get("bytes_sent", 0)),
            "packets":             int(row.get("packets", 0)),
            "duration_ms":         int(row.get("duration_ms", 0)),
            "flags":               flags,
            "label":               None,   # no labels → Isolation Forest
            "ip_is_external":      not src_ip.startswith("10."),
            "port_sensitive":      dst_port in SENSITIVE_PORTS,
            "flag_syn_only":       flags == "SYN",
            "flag_multi_syn":      "SYN,SYN" in flags,
            "log_hash":            _hash_content(raw),
            "integrity_ok":        True,
        }
        records.append(rec)
    return records


# ── Public loader ─────────────────────────────────────────────────────────────

def load_all(apache_path: str, ssh_path: str, network_path: str) -> dict:
    return {
        "apache":  load_apache(apache_path),
        "ssh":     load_ssh(ssh_path),
        "network": load_network(network_path),
    }
