"""
api/app.py
Flask REST API — point d'entrée principal.
Enregistre le Blueprint depuis routes.py et sert le dashboard HTML.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from flask import Flask, redirect, send_from_directory

app = Flask(__name__, static_folder=None)

# ── Enregistrement du Blueprint routes.py ─────────────────────────────────────
from src.api.routes import api_bp
app.register_blueprint(api_bp)

# ── Routes dashboard ──────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Redirige vers le dashboard."""
    return redirect("/dashboard")


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Sert le tableau de bord HTML."""
    try:
        with open("src/dashboard/templates/index.html", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}
    except FileNotFoundError:
        return "<h1>Dashboard non trouvé</h1>", 404


@app.route("/static/<path:filename>", methods=["GET"])
def static_files(filename):
    """Sert les fichiers statiques du dashboard (CSS, JS)."""
    static_dir = os.path.join(os.path.dirname(__file__), "..", "dashboard", "static")
    return send_from_directory(static_dir, filename)


# ── Gestion des erreurs ───────────────────────────────────────────────────────

@app.errorhandler(400)
def bad_request(e):
    from flask import jsonify
    return jsonify({"error": "Bad Request", "message": str(e)}), 400


@app.errorhandler(404)
def not_found(e):
    from flask import jsonify
    return jsonify({"error": "Not Found", "message": str(e)}), 404


@app.errorhandler(500)
def server_error(e):
    from flask import jsonify
    return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ── Point d'entrée ────────────────────────────────────────────────────────────

def run_api(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_api(debug=True)
