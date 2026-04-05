class DeviceApprove extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.code = '';
    this.info = null;
    this.error = '';
    this.loading = false;
  }

  setCode(code) {
    this.code = code || '';
    this.info = null;
    this.error = '';
    if (this.code) {
      this.lookup();
    } else {
      this.render();
    }
  }

  async lookup() {
    this.loading = true;
    this.error = '';
    this.render();
    try {
      this.info = await api.verifyDeviceCode(this.code);
    } catch (e) {
      this.error = e.message;
    }
    this.loading = false;
    this.render();
  }

  async handleAction(action) {
    this.loading = true;
    this.render();
    try {
      const result = await api.deviceVerifyAction(this.code, action);
      document.querySelector('toast-notification').show(result.message, result.title === 'Denied' ? 'error' : 'success');
      this.dispatchEvent(new CustomEvent('navigate-back', { bubbles: true }));
    } catch (e) {
      document.querySelector('toast-notification').show(e.message, 'error');
    }
    this.loading = false;
    this.render();
  }

  render() {
    const hasCode = this.code && this.info && this.info.status === 'pending';

    this.shadowRoot.innerHTML = `
      <style>
        :host { display: block; }
        .card {
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: var(--radius);
          padding: 24px;
          max-width: 480px;
          margin: 0 auto;
        }
        h3 {
          font-size: 18px;
          font-weight: 600;
          margin-bottom: 16px;
          color: var(--text);
        }
        p {
          color: var(--text-muted);
          font-size: 14px;
          margin-bottom: 16px;
          line-height: 1.5;
        }
        .code-display {
          font-family: monospace;
          font-size: 28px;
          letter-spacing: 4px;
          text-align: center;
          padding: 16px;
          background: var(--bg);
          border: 1px solid var(--border);
          border-radius: 6px;
          color: var(--text);
          margin-bottom: 20px;
        }
        label {
          display: block;
          font-size: 12px;
          color: var(--text-muted);
          margin-bottom: 4px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        input {
          width: 100%;
          padding: 12px;
          font-size: 20px;
          text-align: center;
          letter-spacing: 4px;
          border: 1px solid var(--border);
          border-radius: 6px;
          background: var(--bg);
          color: var(--text);
          font-family: monospace;
          box-sizing: border-box;
          margin-bottom: 16px;
        }
        input:focus { outline: none; border-color: var(--primary); }
        .buttons {
          display: flex;
          gap: 12px;
        }
        button {
          flex: 1;
          padding: 12px;
          font-size: 15px;
          font-weight: 500;
          border: none;
          border-radius: 6px;
          cursor: pointer;
          transition: background 0.15s;
        }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        .approve { background: var(--success); color: white; }
        .approve:hover:not(:disabled) { filter: brightness(0.9); }
        .deny { background: var(--danger); color: white; }
        .deny:hover:not(:disabled) { filter: brightness(0.9); }
        .lookup-btn {
          background: var(--text);
          color: var(--bg);
        }
        .lookup-btn:hover:not(:disabled) { background: var(--primary); }
        .error {
          color: var(--danger);
          font-size: 14px;
          text-align: center;
          margin-bottom: 16px;
        }
        .status-badge {
          display: inline-block;
          font-size: 12px;
          padding: 2px 8px;
          border-radius: 4px;
          color: var(--text-muted);
          background: color-mix(in srgb, var(--text-muted) 10%, transparent);
        }
      </style>

      <h3>Authorize Device</h3>
      <div class="card">
        ${this.loading ? '<p>Loading...</p>' : this.renderContent(hasCode)}
      </div>
    `;

    if (!this.loading) {
      this.addListeners(hasCode);
    }
  }

  renderContent(hasCode) {
    if (this.error) {
      return `
        <p class="error">${esc(this.error)}</p>
        <label>Device Code</label>
        <input type="text" id="code-input" value="${esc(this.code)}" placeholder="XXXX-XXXX">
        <div class="buttons">
          <button class="lookup-btn" id="lookup-btn">Verify</button>
        </div>
      `;
    }

    if (hasCode) {
      return `
        <p>A device is requesting to join the network.</p>
        <div class="code-display">${esc(this.info.user_code)}</div>
        <div class="buttons">
          <button class="approve" id="approve-btn">Approve</button>
          <button class="deny" id="deny-btn">Deny</button>
        </div>
      `;
    }

    return `
      <p>Enter the code displayed on the device to authorize it to join the network.</p>
      <label>Device Code</label>
      <input type="text" id="code-input" value="${esc(this.code)}" placeholder="XXXX-XXXX">
      <div class="buttons">
        <button class="lookup-btn" id="lookup-btn">Verify</button>
      </div>
    `;
  }

  addListeners(hasCode) {
    const approveBtn = this.shadowRoot.getElementById('approve-btn');
    const denyBtn = this.shadowRoot.getElementById('deny-btn');
    const lookupBtn = this.shadowRoot.getElementById('lookup-btn');
    const codeInput = this.shadowRoot.getElementById('code-input');

    if (approveBtn) approveBtn.addEventListener('click', () => this.handleAction('approve'));
    if (denyBtn) denyBtn.addEventListener('click', () => this.handleAction('deny'));
    if (lookupBtn) {
      lookupBtn.addEventListener('click', () => {
        this.code = codeInput.value.trim();
        if (this.code) this.lookup();
      });
    }
    if (codeInput) {
      codeInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          this.code = codeInput.value.trim();
          if (this.code) this.lookup();
        }
      });
    }
  }
}

customElements.define('device-approve', DeviceApprove);
