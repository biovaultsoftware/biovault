// sw.js (Full from Previous, Updated for Workbox v7 as of 2025)
importScripts('https://storage.googleapis.com/workbox-cdn/releases/7.1.0/workbox-sw.js');

workbox.routing.registerRoute(
  ({request}) => request.mode === 'navigate',
  new workbox.strategies.NetworkFirst()
);

workbox.routing.registerRoute(
  ({request}) => request.destination === 'script' || request.destination === 'style' || request.destination === 'image',
  new workbox.strategies.StaleWhileRevalidate({cacheName: 'assets-cache'})
);

workbox.precaching.precacheAndRoute(self.__WB_MANIFEST || []);

self.addEventListener('install', (event) => {
  console.log('📦 Service Worker Installed');
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request);
    })
  );
});

// Background Sync for Transactions
const bgSyncPlugin = new workbox.backgroundSync.BackgroundSyncPlugin('txQueue', {
  maxRetentionTime: 24 * 60 // Retry for 24 hours
});

workbox.routing.registerRoute(
  new RegExp('/api/tx/'), // If using relay
  new workbox.strategies.NetworkOnly({
    plugins: [bgSyncPlugin]
  }),
  'POST'
);

// Push Notifications
self.addEventListener('push', (event) => {
  const data = event.data.json();
  const options = {
    body: data.body,
    icon: 'icon-192.png'
  };
  event.waitUntil(self.registration.showNotification(data.title, options));
});
