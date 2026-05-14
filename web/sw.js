const CACHE = 'wgxdp-v101002';
const SHELL = [
  '/',
  '/icon-192.png',
  '/icon-512.png',
  '/style.css',
  '/api.js',
  '/components/toast-notification.js',
  '/components/peers-list.js',
  '/components/peer-detail.js',
  '/components/device-approve.js',
  '/manifest.json'
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // SPA: all navigation requests get the cached index.html
  if (e.request.mode === 'navigate') {
    e.respondWith(
      caches.match('/').then(r => r || fetch('/'))
    );
    return;
  }

  // Network-first for API calls
  if (url.pathname.startsWith('/peers') || url.pathname.startsWith('/rules') || url.pathname.startsWith('/device/') || url.pathname === '/server-info') {
    e.respondWith(
      fetch(e.request).catch(() => caches.match(e.request))
    );
    return;
  }

  // Cache-first for app shell assets
  e.respondWith(
    caches.match(e.request).then(r => r || fetch(e.request))
  );
});
