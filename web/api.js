const API_BASE = window.location.origin;

function esc(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Loop guard: if we've already redirected to re-auth in the last few seconds,
// the proxy presumably bounced us back here without a session. Don't loop —
// surface the failure so the user can see something is wrong.
const REDIRECT_GUARD_KEY = 'wgxdp_auth_redirect_at';
const REDIRECT_GUARD_WINDOW_MS = 5000;

function recentlyRedirected() {
  try {
    const ts = Number(sessionStorage.getItem(REDIRECT_GUARD_KEY) || 0);
    return ts && (Date.now() - ts) < REDIRECT_GUARD_WINDOW_MS;
  } catch {
    return false;
  }
}

function markRedirected() {
  try { sessionStorage.setItem(REDIRECT_GUARD_KEY, String(Date.now())); } catch {}
}

function clearRedirectGuard() {
  try { sessionStorage.removeItem(REDIRECT_GUARD_KEY); } catch {}
}

async function handleSessionLost(res) {
  if (recentlyRedirected()) {
    throw new Error('Session lost. Please reload the page to sign in.');
  }
  let target = '';
  try {
    const body = await res.clone().json();
    if (body && typeof body.redirect === 'string') target = body.redirect;
  } catch {}
  // Fallback: reload the current URL. If a transparent reverse proxy fronts
  // the backend, an unauthenticated request will be intercepted and the user
  // bounced to the IdP. If not, at least the page reloads cleanly.
  if (!target) target = window.location.href;
  markRedirected();
  window.location.assign(target);
  // Page is navigating away — return a never-settling promise so callers'
  // spinners stay up until the new page loads, instead of resolving/rejecting
  // and flashing a stale error toast over the unloading document.
  return new Promise(() => {});
}

async function request(path, opts = {}) {
  const res = await fetch(`${API_BASE}${path}`, opts);
  if (res.status === 401) {
    await handleSessionLost(res);
  }
  if (res.ok) {
    clearRedirectGuard();
    return res;
  }
  let message = res.statusText;
  const text = await res.text();
  if (text) {
    try {
      const body = JSON.parse(text);
      message = body.message || body.error || text;
    } catch {
      message = text;
    }
  }
  throw new Error(message);
}

const api = {
  async fetchPeers() {
    const res = await request('/peers');
    return res.json();
  },

  async deletePeer(name) {
    await request(`/peers/${encodeURIComponent(name)}`, { method: 'DELETE' });
  },

  async fetchRules() {
    const res = await request('/rules');
    return res.json();
  },

  async addRule(srcIP, dstIP, port, proto) {
    const res = await request('/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ src_ip: srcIP, dst_ip: dstIP, port: Number(port), proto: Number(proto) })
    });
    return res.json();
  },

  async deleteRule(id) {
    await request(`/rules/${id}`, { method: 'DELETE' });
  },

  async fetchServerInfo() {
    const res = await request('/server-info');
    return res.json();
  },

  async verifyDeviceCode(code) {
    const res = await request(`/device/verify?code=${encodeURIComponent(code)}`, {
      headers: { 'Accept': 'application/json' }
    });
    return res.json();
  },

  async deviceVerifyAction(userCode, action) {
    const res = await request('/device/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_code: userCode, action })
    });
    return res.json();
  }
};
