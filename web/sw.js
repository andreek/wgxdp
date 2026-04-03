const CACHE = 'wgxdp-v2';
const SHELL = [
  '/',
  '/icon-192.png',
  '/icon-512.png',
  '/style.css',
  '/api.js',
  '/components/toast-notification.js',
  '/components/peers-list.js',
  '/components/peer-detail.js',
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

  // Network-first for API calls
  if (url.pathname.startsWith('/peers') || url.pathname.startsWith('/rules')) {
    e.respondWith(
      fetch(e.request).catch(() => caches.match(e.request))
    );
    return;
  }

  // Cache-first for app shell
  if (url.pathname.startsWith('/')) {
    e.respondWith(
      caches.match(e.request).then(r => r || fetch(e.request))
    );
  }
});
