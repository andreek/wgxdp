const QUICK_SERVICES = [
  { label: 'DNS', port: 53, proto: 17 },
  { label: 'HTTP', port: 80, proto: 6 },
  { label: 'HTTPS', port: 443, proto: 6 },
  { label: 'SSH', port: 22, proto: 6 },
];

class PeerDetail extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.peer = null;
    this.outboundRules = [];
    this.inboundRules = [];
    this.serverIP = '';
    this.peersByIP = {};
    this.customOpen = false;
  }

  setPeer(peer) {
    this.peer = peer;
    this.customOpen = false;
    this.loadData();
  }

  async loadData() {
    try {
      const [allRules, peers, serverInfo] = await Promise.all([
        api.fetchRules().then(r => r || []),
        api.fetchPeers().then(p => p || []),
        this.serverIP ? Promise.resolve(null) : api.fetchServerInfo()
      ]);
      if (serverInfo) this.serverIP = serverInfo.wg_ip || '';
      this.peersByIP = {};
      for (const p of peers) this.peersByIP[p.assigned_ip] = p.name;
      const ip = this.peer.assigned_ip;
      this.outboundRules = allRules.filter(r => r.src_ip === ip);
      this.inboundRules = allRules.filter(r => r.dst_ip === ip && r.src_ip !== ip);
    } catch (e) {
      this.outboundRules = [];
      this.inboundRules = [];
      document.querySelector('toast-notification').show(e.message, 'error');
    }
    this.render();
  }

  render() {
    if (!this.peer) return;
    const p = this.peer;
    const protoName = v => ({ 6: 'TCP', 17: 'UDP' }[v] || v);

    this.shadowRoot.innerHTML = `
      <style>
        :host { display: block; }
        .info {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: var(--radius);
          padding: 20px;
          margin-bottom: 24px;
        }
        .info-grid {
          display: grid;
          grid-template-columns: auto 1fr;
          gap: 6px 16px;
          font-size: 14px;
        }
        .info-label { color: var(--text-muted); }
        .info-value { color: var(--text); font-family: monospace; word-break: break-all; }
        .status {
          display: inline-block;
          font-family: system-ui, sans-serif;
          font-size: 12px;
          padding: 2px 8px;
          border-radius: 4px;
        }
        .status.active {
          color: var(--success);
          background: color-mix(in srgb, var(--success) 10%, transparent);
        }
        .status.inactive {
          color: var(--text-muted);
          background: color-mix(in srgb, var(--text-muted) 10%, transparent);
        }
        .form-card {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: var(--radius);
          padding: 20px;
        }
        .section-title {
          font-size: 16px;
          font-weight: 600;
          margin-bottom: 12px;
          color: var(--text);
        }
        .rule-list {
          background: var(--surface);
          border-radius: var(--radius);
          overflow: hidden;
          margin-bottom: 24px;
        }
        .rule-header, .rule-row {
          display: flex;
          align-items: center;
          padding: 10px 16px;
          gap: 8px;
        }
        .rule-header {
          border-bottom: 1px solid var(--border);
        }
        .rule-header span {
          color: var(--text-muted);
          font-size: 12px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          font-weight: 600;
        }
        .rule-row {
          font-size: 14px;
          color: var(--text);
          border-bottom: 1px solid var(--border);
        }
        .rule-row:last-child { border-bottom: none; }
        .rule-row:hover { background: var(--surface-hover); }
        .col-target { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .col-port { flex: 0 0 64px; }
        .col-proto { flex: 0 0 48px; }
        .col-action { flex: 0 0 60px; text-align: right; }
        @media (max-width: 480px) {
          .rule-header { display: none; }
          .rule-row {
            flex-wrap: wrap;
            gap: 4px 12px;
            padding: 12px 16px;
          }
          .col-target { flex: 1 1 100%; }
          .col-port, .col-proto { flex: 0 0 auto; }
          .col-action { margin-left: auto; }
        }
        .empty {
          padding: 24px;
          text-align: center;
          color: var(--text-muted);
          background: var(--surface);
          border-radius: var(--radius);
          margin-bottom: 24px;
        }
        button.delete {
          background: transparent;
          color: var(--danger);
          border: 1px solid color-mix(in srgb, var(--danger) 27%, transparent);
          padding: 4px 10px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 12px;
        }
        button.delete:hover { background: var(--danger); color: white; }
        label {
          display: block;
          font-size: 12px;
          color: var(--text-muted);
          margin-bottom: 4px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        select, input {
          width: 100%;
          padding: 8px 12px;
          background: var(--bg);
          border: 1px solid var(--border);
          border-radius: 6px;
          color: var(--text);
          font-size: 14px;
        }
        select:focus, input:focus { outline: none; border-color: var(--primary); }
        .dst-row {
          margin-bottom: 16px;
          max-width: 280px;
        }
        .quick-btns {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin-bottom: 16px;
        }
        button.quick {
          background: var(--surface-hover);
          color: var(--text);
          border: 1px solid var(--border);
          padding: 6px 16px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 13px;
          font-weight: 500;
          transition: all 0.15s;
        }
        button.quick:hover {
          background: var(--text);
          color: var(--bg);
        }
        .custom-toggle {
          background: none;
          border: none;
          color: var(--text-muted);
          cursor: pointer;
          font-size: 13px;
          padding: 4px 0;
        }
        .custom-toggle:hover { color: var(--text); }
        .custom-form {
          display: ${this.customOpen ? 'grid' : 'none'};
          grid-template-columns: 1fr 1fr auto;
          gap: 12px;
          align-items: end;
          margin-top: 12px;
        }
        button.add {
          background: var(--text);
          color: var(--bg);
          border: none;
          padding: 8px 20px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 14px;
          font-weight: 500;
          white-space: nowrap;
        }
        button.add:hover { background: var(--primary); }
        .peer-actions {
          margin-top: 24px;
          display: flex;
          justify-content: flex-end;
        }
        button.delete-peer {
          background: transparent;
          color: var(--danger);
          border: 1px solid color-mix(in srgb, var(--danger) 40%, transparent);
          padding: 8px 20px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 14px;
        }
        button.delete-peer:hover { background: var(--danger); color: white; }
      </style>

      <h3 class="section-title">${esc(p.name)}</h3>
      <div class="info">
        <div class="info-grid">
          <span class="info-label">Assigned IP</span>
          <span class="info-value">${esc(p.assigned_ip)}</span>
          <span class="info-label">Status</span>
          <span class="info-value"><span class="status ${p.active ? 'active' : 'inactive'}">${p.active ? 'active' : 'inactive'}</span></span>
          <span class="info-label">Public Key</span>
          <span class="info-value">${esc(p.public_key)}</span>
        </div>
      </div>

      <h3 class="section-title">Outbound Rules</h3>
      ${this.outboundRules.length === 0
        ? '<div class="empty">No outbound rules</div>'
        : `<div class="rule-list">
            <div class="rule-header">
              <span class="col-target">Destination</span>
              <span class="col-port">Port</span>
              <span class="col-proto">Proto</span>
              <span class="col-action"></span>
            </div>
            ${this.outboundRules.map(r => `
              <div class="rule-row">
                <span class="col-target">${this.ipLabel(r.dst_ip)}</span>
                <span class="col-port">${r.port}</span>
                <span class="col-proto">${protoName(r.proto)}</span>
                <span class="col-action"><button class="delete" data-id="${r.id}">Delete</button></span>
              </div>
            `).join('')}
          </div>`
      }

      <h3 class="section-title">Inbound Rules</h3>
      ${this.inboundRules.length === 0
        ? '<div class="empty">No inbound rules</div>'
        : `<div class="rule-list">
            <div class="rule-header">
              <span class="col-target">Source</span>
              <span class="col-port">Port</span>
              <span class="col-proto">Proto</span>
              <span class="col-action"></span>
            </div>
            ${this.inboundRules.map(r => `
              <div class="rule-row">
                <span class="col-target">${this.ipLabel(r.src_ip)}</span>
                <span class="col-port">${r.port}</span>
                <span class="col-proto">${protoName(r.proto)}</span>
                <span class="col-action"><button class="delete" data-id="${r.id}">Delete</button></span>
              </div>
            `).join('')}
          </div>`
      }

      <h3 class="section-title">Add Rule</h3>
      <div class="form-card">
        <div class="dst-row">
          <label>Destination</label>
          <input type="text" id="dst_ip" value="${esc(this.serverIP)}" placeholder="10.200.0.1">
        </div>
        <label>Quick add</label>
        <div class="quick-btns">
          ${QUICK_SERVICES.map(s => `
            <button class="quick" data-port="${s.port}" data-proto="${s.proto}">${s.label}</button>
          `).join('')}
        </div>
        <button class="custom-toggle" id="custom-toggle">${this.customOpen ? 'Hide custom rule' : 'Custom rule...'}</button>
        <div class="custom-form">
          <div>
            <label>Port</label>
            <input type="number" id="port" placeholder="8080" min="1" max="65535">
          </div>
          <div>
            <label>Protocol</label>
            <select id="proto">
              <option value="6">TCP</option>
              <option value="17">UDP</option>
            </select>
          </div>
          <div>
            <button class="add" id="add-btn">Add</button>
          </div>
        </div>
      </div>

      <div class="peer-actions">
        <button class="delete-peer" id="delete-peer-btn">Delete Peer</button>
      </div>
    `;

    this.shadowRoot.querySelectorAll('.delete').forEach(btn => {
      btn.addEventListener('click', () => this.handleDeleteRule(btn.dataset.id));
    });

    this.shadowRoot.querySelectorAll('.quick').forEach(btn => {
      btn.addEventListener('click', () => this.handleQuickAdd(btn.dataset.port, btn.dataset.proto));
    });

    this.shadowRoot.getElementById('custom-toggle').addEventListener('click', () => {
      this.customOpen = !this.customOpen;
      this.render();
    });

    this.shadowRoot.getElementById('add-btn').addEventListener('click', () => this.handleAddRule());
    this.shadowRoot.getElementById('delete-peer-btn').addEventListener('click', () => this.handleDeletePeer());
  }

  getDstIP() {
    return this.shadowRoot.getElementById('dst_ip').value.trim();
  }

  async handleQuickAdd(port, proto) {
    const dstIP = this.getDstIP();
    if (!dstIP) {
      document.querySelector('toast-notification').show('Enter a destination IP first', 'error');
      return;
    }
    try {
      await api.addRule(this.peer.assigned_ip, dstIP, port, proto);
      document.querySelector('toast-notification').show('Rule added');
      this.loadData();
    } catch (e) {
      document.querySelector('toast-notification').show(e.message, 'error');
    }
  }

  async handleAddRule() {
    const dstIP = this.getDstIP();
    const port = this.shadowRoot.getElementById('port').value;
    const proto = this.shadowRoot.getElementById('proto').value;

    if (!dstIP || !port) {
      document.querySelector('toast-notification').show('Destination IP and port are required', 'error');
      return;
    }

    try {
      await api.addRule(this.peer.assigned_ip, dstIP, port, proto);
      document.querySelector('toast-notification').show('Rule added');
      this.loadData();
    } catch (e) {
      document.querySelector('toast-notification').show(e.message, 'error');
    }
  }

  async handleDeleteRule(id) {
    if (!confirm('Delete this firewall rule?')) return;
    try {
      await api.deleteRule(id);
      document.querySelector('toast-notification').show('Rule deleted');
      this.loadData();
    } catch (e) {
      document.querySelector('toast-notification').show(e.message, 'error');
    }
  }

  async handleDeletePeer() {
    if (!confirm(`Delete peer "${this.peer.name}" and all its firewall rules?`)) return;
    try {
      await api.deletePeer(this.peer.name);
      document.querySelector('toast-notification').show(`Peer "${this.peer.name}" deleted`);
      this.dispatchEvent(new CustomEvent('peer-deleted', { bubbles: true }));
    } catch (e) {
      document.querySelector('toast-notification').show(e.message, 'error');
    }
  }

  ipLabel(ip) {
    if (ip === this.serverIP) return 'server';
    const name = this.peersByIP[ip];
    return name ? `${esc(name)} (${esc(ip)})` : esc(ip);
  }

}

customElements.define('peer-detail', PeerDetail);
