"""
api/app.py
Flask REST API — point d'entrée principal.
Enregistre le Blueprint depuis routes.py et sert le dashboard HTML.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from flask import Flask, redirect, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder=None)

# ── Enregistrement du Blueprint routes.py ─────────────────────────────────────
CORS(app) # Autorise les requêtes depuis n'importe quelle source
from src.api.routes import api_bp
app.register_blueprint(api_bp)

# ── Frontend logic removed (served by run_dashboard.py) ─────────────────────


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
    # threaded=True : chaque requête dans son propre thread
    # évite le blocage quand le dashboard fait plusieurs appels API en parallèle
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    run_api(debug=True)
