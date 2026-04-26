# 🐳 Dockerfile pour ThreeSentinel
FROM python:3.11-slim

# Éviter les fichiers .pyc et activer le buffering des logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Installation des dépendances système (si nécessaire)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copie des requirements et installation
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du reste du code
COPY . .

# Exposer le port de l'API/Dashboard
EXPOSE 8888

# Lancement du système (mode fast par défaut pour la démo)
CMD ["python", "main.py", "--fast"]
