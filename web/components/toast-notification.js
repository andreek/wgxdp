class ToastNotification extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.shadowRoot.innerHTML = `
      <style>
        :host {
          position: fixed;
          bottom: 24px;
          right: 24px;
          z-index: 1000;
        }
        .toast {
          padding: 12px 20px;
          border-radius: var(--radius, 8px);
          color: #fff;
          font-size: 14px;
          font-family: system-ui, sans-serif;
          opacity: 0;
          transform: translateY(16px);
          transition: all 0.3s;
          max-width: 360px;
        }
        .toast.visible {
          opacity: 1;
          transform: translateY(0);
        }
        .toast.success { background: var(--success, #22c55e); }
        .toast.error { background: var(--danger-hover, #dc2626); }
      </style>
      <div class="toast"></div>
    `;
  }

  show(message, type = 'success') {
    const toast = this.shadowRoot.querySelector('.toast');
    toast.textContent = message;
    toast.className = `toast ${type}`;
    requestAnimationFrame(() => toast.classList.add('visible'));
    clearTimeout(this._timer);
    this._timer = setTimeout(() => toast.classList.remove('visible'), 3000);
  }
}

customElements.define('toast-notification', ToastNotification);
