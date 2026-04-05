const API_BASE = window.location.origin;

function esc(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const api = {
  async fetchPeers() {
    const res = await fetch(`${API_BASE}/peers`);
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  async deletePeer(name) {
    const res = await fetch(`${API_BASE}/peers/${encodeURIComponent(name)}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(await res.text());
  },

  async fetchRules() {
    const res = await fetch(`${API_BASE}/rules`);
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  async addRule(srcIP, dstIP, port, proto) {
    const res = await fetch(`${API_BASE}/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ src_ip: srcIP, dst_ip: dstIP, port: Number(port), proto: Number(proto) })
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  async deleteRule(id) {
    const res = await fetch(`${API_BASE}/rules/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(await res.text());
  },

  async fetchServerInfo() {
    const res = await fetch(`${API_BASE}/server-info`);
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  async verifyDeviceCode(code) {
    const res = await fetch(`${API_BASE}/device/verify?code=${encodeURIComponent(code)}`, {
      headers: { 'Accept': 'application/json' }
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({ message: res.statusText }));
      throw new Error(body.message || 'Invalid or expired code.');
    }
    return res.json();
  },

  async deviceVerifyAction(userCode, action) {
    const res = await fetch(`${API_BASE}/device/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_code: userCode, action })
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.message || 'Action failed.');
    return body;
  }
};
