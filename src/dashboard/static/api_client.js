/**
 * api_client.js — Client API partagé pour ThreeSentinel
 */

const API = 'http://localhost:8888';

/**
 * Appel générique à l'API
 */
async function apiCall(path, options = {}) {
  try {
    const r = await fetch(API + path, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(err.message || r.statusText);
    }
    return await r.json();
  } catch (e) {
    console.error(`[API Error] ${path}:`, e);
    return null;
  }
}

/**
 * Système de notification (Toast)
 */
function showToast(message, isSuccess = true) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  
  toast.textContent = message;
  toast.style.borderColor = isSuccess ? 'rgba(0, 212, 170, 0.4)' : 'rgba(255, 77, 109, 0.4)';
  toast.style.background = isSuccess ? 'rgba(0, 212, 170, 0.05)' : 'rgba(255, 77, 109, 0.05)';
  
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 3500);
}

/**
 * Utilitaires de formatage
 */
const Format = {
  time: (ts) => {
    if (!ts) return '—';
    try { return new Date(ts).toLocaleTimeString('fr-FR'); }
    catch { return ts.slice(11, 19) || '—'; }
  },
  badge: (decision) => {
    return `<span class="badge badge-${decision.toLowerCase()}" style="min-width: 80px; text-align: center; display: inline-block;">${decision}</span>`;
  }
};

/**
 * Horloge universelle
 */
function startClock() {
  const el = document.getElementById('clock');
  if (!el) return;
  const update = () => el.textContent = new Date().toLocaleTimeString('fr-FR');
  setInterval(update, 1000);
  update();
}

document.addEventListener('DOMContentLoaded', startClock);
