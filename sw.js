/* sw.js — Production, 2025-08-19 */
self.__WB_DISABLE_DEV_LOGS = true;

// Workbox v7
importScripts('https://storage.googleapis.com/workbox-cdn/releases/7.1.0/workbox-sw.js');

const OFFLINE_URL = '/offline.html';      // optional: add this file to your build
const FALLBACK_ICON = '/icon-192.png';    // optional: small icon for fallback responses

if (self.workbox) {
  const {
    core,
    routing,
    strategies,
    precaching,
    expiration,
    cacheableResponse,
    backgroundSync,
    navigationPreload,
    broadcastUpdate
  } = self.workbox;

  // ------- Lifecycle & cache names -------
  core.skipWaiting();
  core.clientsClaim();
  navigationPreload.enable(); // speed up navigations

  core.setCacheNameDetails({
    prefix: 'biovault',
    suffix: 'v1',
    precache: 'precache',
    runtime: 'runtime',
  });

  // ------- Precache manifest (filled at build) -------
  precaching.precacheAndRoute(self.__WB_MANIFEST || []);

  // Helper: cacheable (opaque/200) plugin
  const cacheOK = new cacheableResponse.CacheableResponsePlugin({ statuses: [0, 200] });

  // Helper: reasonable expiration plugins
  const expPages   = new expiration.ExpirationPlugin({ maxEntries: 50, purgeOnQuotaError: true });
  const expAssets  = new expiration.ExpirationPlugin({ maxEntries: 120, purgeOnQuotaError: true });
  const expImages  = new expiration.ExpirationPlugin({ maxEntries: 150, maxAgeSeconds: 60 * 24 * 60 * 60, purgeOnQuotaError: true }); // 60d
  const expFonts   = new expiration.ExpirationPlugin({ maxEntries: 40, maxAgeSeconds: 180 * 24 * 60 * 60, purgeOnQuotaError: true }); // 180d
  const expJSON    = new expiration.ExpirationPlugin({ maxEntries: 80, maxAgeSeconds: 3 * 24 * 60 * 60, purgeOnQuotaError: true });   // 3d

  // Helper: is CDN host?
  function isCdn(url) {
    const h = url.hostname;
    return (
      h.endsWith('jsdelivr.net') ||
      h === 'unpkg.com' ||
      h.endsWith('cdnjs.cloudflare.com') ||
      h.endsWith('gstatic.com') ||
      h.endsWith('googleapis.com')
    );
  }

  // ------- Page navigations: NetworkFirst w/ preload & fast timeout -------
  routing.registerRoute(
    ({ request }) => request.mode === 'navigate',
    new strategies.NetworkFirst({
      cacheName: 'biovault-pages',
      networkTimeoutSeconds: 3,
      plugins: [expPages, cacheOK],
      fetchOptions: { credentials: 'same-origin' }
    })
  );

  // ------- Scripts & styles (local or CDN): SWR -------
  routing.registerRoute(
    ({ request, url }) =>
      (request.destination === 'script' || request.destination === 'style' || request.destination === 'worker') &&
      (url.origin === self.location.origin || isCdn(url)),
    new strategies.StaleWhileRevalidate({
      cacheName: 'biovault-assets',
      plugins: [expAssets, cacheOK, new broadcastUpdate.BroadcastUpdatePlugin()],
    })
  );

  // ------- JSON / manifest / WASM: SWR -------
  routing.registerRoute(
    ({ request }) =>
      request.destination === 'document' ? false :
      (request.url.endsWith('.json') ||
       request.destination === 'manifest' ||
       request.url.endsWith('.wasm')),
    new strategies.StaleWhileRevalidate({
      cacheName: 'biovault-data',
      plugins: [expJSON, cacheOK],
    })
  );

  // ------- Images: CacheFirst (with fallback icon) -------
  routing.registerRoute(
    ({ request }) => request.destination === 'image',
    new strategies.CacheFirst({
      cacheName: 'biovault-images',
      plugins: [expImages, cacheOK],
    })
  );

  // ------- Fonts (Google/CDN): CacheFirst + opaque ok -------
  routing.registerRoute(
    ({ request, url }) =>
      request.destination === 'font' ||
      url.origin.includes('fonts.googleapis.com') ||
      url.origin.includes('fonts.gstatic.com'),
    new strategies.CacheFirst({
      cacheName: 'biovault-fonts',
      plugins: [cacheOK, expFonts],
    })
  );

  // ------- Known CDN long-lived caching for CSS/JS bundles -------
  routing.registerRoute(
    ({ url, request }) =>
      (request.destination === 'script' || request.destination === 'style') && isCdn(url),
    new strategies.StaleWhileRevalidate({
      cacheName: 'biovault-cdn',
      plugins: [expAssets, cacheOK],
    })
  );

  // ------- API: GET → NetworkFirst, POST → BackgroundSync -------
  routing.registerRoute(
    ({ url, request }) => request.method === 'GET' && url.pathname.startsWith('/api/'),
    new strategies.NetworkFirst({
      cacheName: 'biovault-api',
      networkTimeoutSeconds: 2,
      plugins: [expJSON],
    })
  );

  const txQueue = new backgroundSync.BackgroundSyncPlugin('txQueue', {
    maxRetentionTime: 24 * 60, // minutes
  });
  routing.registerRoute(
    ({ url, request }) => request.method === 'POST' && url.pathname.startsWith('/api/tx/'),
    new strategies.NetworkOnly({ plugins: [txQueue] }),
    'POST'
  );

  // ------- Offline fallbacks -------
  routing.setCatch(async ({ event }) => {
    if (event.request.destination === 'document') {
      // Try a precached offline page if available
      const cache = await caches.open(core.cacheNames.precache);
      const offline = await cache.match(OFFLINE_URL);
      if (offline) return offline;
      return new Response('<h1>Offline</h1><p>Please check your connection.</p>', {
        headers: { 'Content-Type': 'text/html; charset=UTF-8' },
      });
    }
    if (event.request.destination === 'image' && FALLBACK_ICON) {
      const cache = await caches.open(core.cacheNames.precache);
      const icon = await cache.match(FALLBACK_ICON);
      if (icon) return icon;
    }
    return Response.error();
  });

  // ------- Client messaging -------
  self.addEventListener('message', (event) => {
    const data = event.data || {};
    if (data && data.type === 'SKIP_WAITING') self.skipWaiting();
    if (data && data.type === 'CLEAR_CACHES') {
      event.waitUntil((async () => {
        const keys = await caches.keys();
        await Promise.all(keys.map((k) => caches.delete(k)));
      })());
    }
  });

  // ------- Push notifications -------
  self.addEventListener('push', (event) => {
    let data = {};
    try { data = event.data ? event.data.json() : {}; } catch (_) {}
    const title = data.title || 'BioVault';
    const options = {
      body: data.body || 'You have a new notification.',
      icon: data.icon || 'icon-192.png',
      badge: data.badge || 'icon-72.png',
      data: data.data || {},
    };
    event.waitUntil(self.registration.showNotification(title, options));
  });

  // Focus/open app when user clicks a notification
  self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    event.waitUntil((async () => {
      const all = await clients.matchAll({ type: 'window', includeUncontrolled: true });
      const targetURL = (event.notification && event.notification.data && event.notification.data.url) || '/';
      const abs = new URL(targetURL, location.origin).href;
      const match = all.find(c => c.url === abs);
      if (match) return match.focus();
      return clients.openWindow(abs);
    })());
  });

} else {
  // ------- Minimal fallback if Workbox CDN failed -------
  self.addEventListener('install', (e) => e.waitUntil(self.skipWaiting()));
  self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
  self.addEventListener('fetch', (event) => {
    event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
  });
}
