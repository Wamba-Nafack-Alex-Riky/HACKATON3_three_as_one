import requests
import time
import random
import sys
from datetime import datetime, timezone

# Configuration
SERVER_URL = "http://localhost:8888"
INJECT_URL = f"{SERVER_URL}/api/inject"

def inject(payload):
    try:
        r = requests.post(INJECT_URL, json=payload, timeout=2)
        if r.status_code == 200:
            res = r.json()
            print(f"  [OK] Decision: {res.get('decision')} | Score: {res.get('risk_score')}")
        else:
            print(f"  [Error] Status {r.status_code}: {r.text}")
    except Exception as e:
        print(f"  [Failed] {e}")

def run_port_scan(attacker_ip="192.168.50.10"):
    print(f"🔍 Scenario: PORT SCAN from {attacker_ip}")
    sensitive_ports = [21, 22, 23, 80, 443, 3306, 5432, 8080]
    for port in sensitive_ports:
        payload = {
            "source": "network",
            "ip": attacker_ip,
            "dst_port": port,
            "protocol": "TCP",
            "flags": "SYN",
            "port_sensitive": True,
            "ip_is_external": True,
            "bytes_sent": 0,
            "packets": 1,
            "duration_ms": 0
        }
        print(f"  Scanning port {port}...")
        inject(payload)
        time.sleep(0.2)

def run_ssh_brute_force(attacker_ip="172.16.10.42", count=10):
    print(f"🔥 Scenario: SSH BRUTE FORCE from {attacker_ip} ({count} attempts)")
    for i in range(count):
        payload = {
            "source": "ssh",
            "ip": attacker_ip,
            "user": "admin",
            "event": "Failed password",
            "timestamp_log": datetime.now(timezone.utc).isoformat()
        }
        print(f"  Attempt {i+1}/{count}...")
        inject(payload)
        time.sleep(0.1)

def run_sqli_attack(attacker_ip="45.33.22.11"):
    print(f"🌐 Scenario: AGGRESSIVE SQL INJECTION from {attacker_ip}")
    payloads = [
        "/api/users?id=' OR 1=1 --",
        "/api/login?u=admin&p=' OR '1'='1",
        "/api/products?search='; DROP TABLE users; --",
        "/api/data?q=UNION SELECT username, password FROM users",
        "/login?user=admin'--",
        "/search?q=1'; WAITFOR DELAY '0:0:10'--",
        "/?id=1 AND (SELECT * FROM (SELECT(SLEEP(5)))YQxU)",
    ]
    sources = ["apache", "nginx", "tomcat", "iis"]
    
    # Beaucoup de requêtes pour forcer le modèle à monter en score et accumuler de l'évidence
    for _ in range(3):
        for p in payloads:
            payload = {
                "source": random.choice(sources),
                "ip": attacker_ip,
                "method": "POST",
                "path": p,
                "status": 500,
                "bytes": random.randint(100, 5000),
                "user_agent": "sqlmap/1.4.12",
                "ip_is_external": True,
                "evidence": [f"SQLi pattern detected in: {p}"]
            }
            print(f"  Injecting payload: {p}")
            inject(payload)
            time.sleep(0.1)

def run_path_traversal(attacker_ip="88.99.11.22"):
    print(f"📂 Scenario: MASSIVE PATH TRAVERSAL from {attacker_ip}")
    payloads = [
        "/download?file=../../../../etc/passwd",
        "/static/../../config/config.yaml",
        "/view?doc=../../.env",
        "/../../../var/log/auth.log",
        "/etc/shadow",
        "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/api/v1/files?path=....//....//....//etc/passwd"
    ]
    sources = ["nginx", "apache", "lighttpd"]
    
    for _ in range(4):
        for p in payloads:
            payload = {
                "source": random.choice(sources),
                "ip": attacker_ip,
                "method": "GET",
                "path": p,
                "status": 403,
                "bytes": random.randint(50, 800),
                "user_agent": "dirbuster/1.0-RC1",
                "ip_is_external": True,
                "evidence": [f"Path traversal attempt: {p}"]
            }
            print(f"  Injecting payload: {p}")
            inject(payload)
            time.sleep(0.1)

def run_massive_ddos(attacker_ip="203.0.113.50"):
    print(f"💣 Scenario: MASSIVE NETWORK DDOS from {attacker_ip}")
    for i in range(25):
        payload = {
            "source": "network",
            "ip": attacker_ip,
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "SYN",
            "port_sensitive": True,
            "ip_is_external": True,
            "bytes_sent": 1500,
            "packets": 5000,
            "duration_ms": 10,
            "evidence": ["High packet rate detected (SYN Flood)"]
        }
        if i % 5 == 0: print(f"  Sending DDoS wave {i//5 + 1}/5...")
        inject(payload)
        time.sleep(0.05)

if __name__ == "__main__":
    print("🛡️ ThreeSentinel Simulation Tool")
    print("=================================")
    
    if len(sys.argv) < 2:
        print("Usage: python simulation.py [scan|ssh|sqli|traversal|all]")
        sys.exit(1)
        
    cmd = sys.argv[1].lower()
    
    if cmd == "scan":
        run_port_scan()
    elif cmd == "ssh":
        run_ssh_brute_force()
    elif cmd == "sqli":
        run_sqli_attack()
    elif cmd == "traversal":
        run_path_traversal()
    elif cmd == "ddos":
        run_massive_ddos()
    elif cmd == "all":
        run_port_scan()
        time.sleep(1)
        run_ssh_brute_force()
        time.sleep(1)
        run_sqli_attack()
        time.sleep(1)
        run_path_traversal()
        time.sleep(1)
        run_massive_ddos()
    else:
        print(f"Unknown command: {cmd}")
