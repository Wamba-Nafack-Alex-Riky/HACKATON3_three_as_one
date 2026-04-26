"""
run_dashboard.py — Serveur autonome pour le Frontend du Dashboard.
Ce fichier sert uniquement les pages HTML et les fichiers statiques.
Il se connecte à l'API qui tourne sur le port 8888.
"""

import os
from flask import Flask, send_from_directory

app = Flask(__name__, static_folder=None)

# ── Routes dashboard ──────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Sert la Landing Page institutionnelle."""
    try:
        with open("src/dashboard/templates/landing.html", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}
    except FileNotFoundError:
        return "<h1>Landing Page non trouvée</h1>", 404

@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Sert le tableau de bord HTML (Surveillance)."""
    try:
        with open("src/dashboard/templates/index.html", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}
    except FileNotFoundError:
        return "<h1>Dashboard non trouvé</h1>", 404

@app.route("/firewall", methods=["GET"])
def firewall():
    """Sert la page Firewall (Intervention)."""
    try:
        with open("src/dashboard/templates/firewall.html", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}
    except FileNotFoundError:
        return "<h1>Page Firewall non trouvée</h1>", 404

@app.route("/analysis", methods=["GET"])
def analysis():
    """Sert la page Analyse (Profilage)."""
    try:
        with open("src/dashboard/templates/analysis.html", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}
    except FileNotFoundError:
        return "<h1>Page Analyse non trouvée</h1>", 404

@app.route("/help", methods=["GET"])
def help():
    """Sert la page d'aide et documentation."""
    try:
        with open("src/dashboard/templates/help.html", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}
    except FileNotFoundError:
        return "<h1>Page d'aide non trouvée</h1>", 404

@app.route("/static/<path:filename>", methods=["GET"])
def static_files(filename):
    """Sert les fichiers statiques du dashboard (CSS, JS)."""
    static_dir = os.path.join(os.path.dirname(__file__), "src", "dashboard", "static")
    return send_from_directory(static_dir, filename)

if __name__ == "__main__":
    port = 3000
    print(f"""
╔══════════════════════════════════════════════════════╗
║         ThreeSentinel — Frontend Serveur             ║
╠══════════════════════════════════════════════════════╣
║  Frontend disponible sur : http://localhost:{port}     ║
║  L'API doit tourner sur le port 8888                 ║
╚══════════════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)
