import requests
import sys
import time
import random

# Configuration
SERVER_IP = "localhost"
PORT = 8888
BASE_URL = f"http://{SERVER_IP}:{PORT}"

def inject_event(ip, source, event, user="admin"):
    url = f"{BASE_URL}/api/inject"
    payload = {
        "source": source,
        "ip": ip,
        "user": user,
        "event": event
    }
    try:
        r = requests.post(url, json=payload, timeout=1)
        return r.status_code == 200
    except:
        return False

def trigger_flood(count=20):
    print(f"🔥 LANCEMENT D'UN ASSAUT MASSIF ({count} attaques)...")
    
    # Liste d'IPs d'attaquants fictifs
    attackers = [f"192.168.10.{random.randint(10, 250)}" for _ in range(5)]
    
    for i in range(count):
        ip = random.choice(attackers)
        # On alterne entre SSH et Web
        if i % 2 == 0:
            success = inject_event(ip, "ssh", f"Failed password for user {i}")
            print(f"  [{i+1}/{count}] 🛡️ SSH Attack from {ip}...")
        else:
            # Injection SQL directe via URL
            try:
                requests.get(f"{BASE_URL}/api/users?id=' OR 1={i} --", timeout=1)
                print(f"  [{i+1}/{count}] 🌐 Web Attack on /api/users...")
            except: pass
        
        time.sleep(0.05) # Très rapide

    print("\n✅ Assaut terminé. Regarde le Dashboard !")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python attack.py [ssh|web|flood]")
        sys.exit(1)
    
    cmd = sys.argv[1].lower()
    if cmd == "ssh":
        inject_event("172.16.0.42", "ssh", "Failed password")
        print("🚀 Attaque SSH envoyée.")
    elif cmd == "web":
        try:
            requests.get(f"{BASE_URL}/api/users?id=' OR 1=1 --")
            print("🚀 Attaque Web envoyée.")
        except: print("❌ Erreur")
    elif cmd == "flood":
        trigger_flood(20)
    else:
        print("❌ Commande inconnue.")
