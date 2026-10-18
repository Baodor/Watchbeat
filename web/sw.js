// Static shell caching only. Never cache API, authentication or protected music.
const CACHE='watchbeat-static-v1';
self.addEventListener('install',event=>{event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(['/','/app.css','/app.js','/assets/icons/watchbeat-192.png'])));self.skipWaiting()});
self.addEventListener('activate',event=>{event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));self.clients.claim()});
self.addEventListener('fetch',event=>{const u=new URL(event.request.url);if(event.request.method!=='GET'||u.origin!==self.location.origin||u.pathname.startsWith('/api/')||u.pathname.startsWith('/auth/')||u.pathname.startsWith('/ws/'))return;event.respondWith(fetch(event.request).then(r=>{if(r.ok&&['/','/app.js','/app.css'].includes(u.pathname)){const copy=r.clone();caches.open(CACHE).then(c=>c.put(event.request,copy))}return r}).catch(()=>caches.match(event.request)))});
