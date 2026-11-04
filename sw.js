// ХСТИ Гүйцэтгэлийн систем — Service Worker (offline дэмжлэг)
// Хувилбар солих бүрт CACHE_NAME-ийн дугаарыг нэмнэ (хуучин кэш цэвэрлэгдэнэ)
// v2 (2026-11-04): зөвхөн өөрийн сайтын хүсэлтийг барина; сүлжээ тасарвал үргэлж хариу (Response) буцаана;
//                  maskable дүрснүүдийг кэшэд нэмсэн.
const CACHE_NAME = 'hsti-v2';

// Offline үед хэрэгтэй үндсэн файлууд
const CORE_ASSETS = [
  './',
  './index.html',
  './site.webmanifest',
  './web-app-manifest-192x192.png',
  './web-app-manifest-512x512.png',
  './maskable-192x192.png',
  './maskable-512x512.png',
  './apple-touch-icon.png',
  './favicon.ico',
  './favicon.svg'
];

// Суулгах үед үндсэн файлуудыг кэшлэх
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) =>
      // Файл тус бүрийг тусад нь нэмэх — нэг нь алдаа өгвөл бусад нь орно
      Promise.allSettled(
        CORE_ASSETS.map((url) => cache.add(url).catch(() => console.warn('[SW] Кэшлэж чадсангүй:', url)))
      )
    )
  );
  self.skipWaiting(); // Шинэ SW-г шууд идэвхжүүлэх
});

// Идэвхжих үед хуучин кэшийг цэвэрлэх
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

// Хүсэлт таслах — Network-first (эхлээд интернэт, амжилтгүй бол кэш)
self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  // Зөвхөн ӨӨРИЙН сайтын файл. Google API, Cloudflare Worker, Sentry, CDN зэрэг гадны
  // хүсэлтэд огт оролцохгүй — браузер өөрөө шийднэ (CORS, нэвтрэлт, шинэ өгөгдөл).
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    fetch(req)
      .then((res) => {
        // Амжилттай бол кэшийг шинэчлэх (дараагийн offline-д зориулж)
        if (res && res.status === 200 && res.type === 'basic') {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, copy)).catch(() => {});
        }
        return res;
      })
      .catch(async () => {
        // Интернэт байхгүй / хүсэлт тасарсан — кэшээс өгөх
        const cached = await caches.match(req, { ignoreSearch: req.mode === 'navigate' });
        if (cached) return cached;
        if (req.mode === 'navigate') {
          const shell = await caches.match('./index.html');
          if (shell) return shell;
        }
        // Урьд нь энд юу ч буцаадаггүй (undefined) байсан тул Chrome "Download error" гэж
        // улаан алдаа гаргадаг байв. Одоо ойлгомжтой 503 хариу буцаана.
        return new Response('', { status: 503, statusText: 'Offline' });
      })
  );
});
