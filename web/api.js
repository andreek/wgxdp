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
  }
};
