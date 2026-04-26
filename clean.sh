#!/bin/bash
echo "🧹 Nettoyage de ThreeSentinel..."
pkill -f python
rm -f journal.jsonl
sudo fuser -k 8080/tcp 2>/dev/null
sudo fuser -k 9000/tcp 2>/dev/null
echo "✅ Système prêt pour une nouvelle démo !"
