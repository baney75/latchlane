const OFFLINE_CACHE = "latchlane-offline-v1";
const OFFLINE_PAGE = "/offline.html";

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(OFFLINE_CACHE).then((cache) =>
      cache.addAll([OFFLINE_PAGE, "/assets/offline.css"]),
    ),
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin === self.location.origin && url.pathname === "/assets/offline.css") {
    event.respondWith(
      fetch(event.request, { cache: "no-store" }).catch(() =>
        caches.match("/assets/offline.css"),
      ),
    );
    return;
  }
  if (event.request.mode !== "navigate") return;
  event.respondWith(
    fetch(event.request, { cache: "no-store" }).catch(() => caches.match(OFFLINE_PAGE)),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((windows) => {
      const openWindow = windows.find((client) => new URL(client.url).origin === self.location.origin);
      return openWindow ? openWindow.focus() : self.clients.openWindow("/");
    }),
  );
});
