class PeersList extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.peers = [];
  }

  connectedCallback() {
    this.load();
  }

  async load() {
    try {
      this.peers = await api.fetchPeers() || [];
    } catch (e) {
      this.peers = [];
      document.querySelector('toast-notification').show(e.message, 'error');
    }
    this.render();
  }

  render() {
    this.shadowRoot.innerHTML = `
      <style>
        :host { display: block; }
        .grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
          gap: 12px;
        }
        .card {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: var(--radius);
          padding: 16px;
          cursor: pointer;
          transition: border-color 0.15s, background 0.15s;
        }
        .card:hover {
          border-color: var(--primary);
          background: var(--surface-hover);
        }
        .card-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 8px;
        }
        .name {
          font-size: 15px;
          font-weight: 600;
          color: var(--text);
        }
        .ip {
          font-family: monospace;
          font-size: 13px;
          color: var(--text-muted);
          background: color-mix(in srgb, var(--primary) 10%, transparent);
          padding: 2px 8px;
          border-radius: 4px;
        }
        .ip.active {
          color: var(--success);
          background: color-mix(in srgb, var(--success) 10%, transparent);
        }
        .key {
          font-family: monospace;
          font-size: 11px;
          color: var(--text-muted);
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          margin-top: 4px;
        }
        .actions {
          margin-top: 12px;
          display: flex;
          justify-content: flex-end;
        }
        button.delete {
          background: transparent;
          color: var(--danger);
          border: 1px solid color-mix(in srgb, var(--danger) 27%, transparent);
          padding: 4px 12px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 12px;
        }
        button.delete:hover {
          background: var(--danger);
          color: white;
        }
        .empty {
          padding: 48px;
          text-align: center;
          color: var(--text-muted);
          font-size: 15px;
        }
      </style>
      ${this.peers.length === 0
        ? '<div class="empty">No peers registered</div>'
        : `<div class="grid">
            ${this.peers.map(p => `
              <div class="card" data-peer='${esc(JSON.stringify(p))}'>
                <div class="card-header">
                  <span class="name">${esc(p.name)}</span>
                  <span class="ip${p.active ? ' active' : ''}">${esc(p.assigned_ip)}</span>
                </div>
                <div class="key" title="${esc(p.public_key)}">${esc(p.public_key)}</div>
                <div class="actions">
                  <button class="delete" data-name="${esc(p.name)}">Delete</button>
                </div>
              </div>
            `).join('')}
          </div>`
      }
    `;

    this.shadowRoot.querySelectorAll('.card').forEach(card => {
      card.addEventListener('click', e => {
        if (e.target.closest('.delete')) return;
        const peer = JSON.parse(card.dataset.peer);
        this.dispatchEvent(new CustomEvent('peer-selected', { detail: peer, bubbles: true }));
      });
    });

    this.shadowRoot.querySelectorAll('.delete').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        this.handleDelete(btn.dataset.name);
      });
    });
  }

  async handleDelete(name) {
    if (!confirm(`Delete peer "${name}" and all its firewall rules?`)) return;
    try {
      await api.deletePeer(name);
      document.querySelector('toast-notification').show(`Peer "${name}" deleted`);
      this.load();
    } catch (e) {
      document.querySelector('toast-notification').show(e.message, 'error');
    }
  }
}

customElements.define('peers-list', PeersList);
