// ХСТИ Гүйцэтгэлийн систем — Service Worker (offline дэмжлэг)
// Хувилбар солих бүрт CACHE_NAME-ийн дугаарыг нэмнэ (хуучин кэш цэвэрлэгдэнэ)
const CACHE_NAME = 'hsti-v1';

// Offline үед хэрэгтэй үндсэн файлууд
const CORE_ASSETS = [
  './',
  './index.html',
  './site.webmanifest',
  './web-app-manifest-192x192.png',
  './web-app-manifest-512x512.png',
  './apple-touch-icon.png',
  './favicon.ico',
  './favicon.svg'
];

// Суулгах үед үндсэн файлуудыг кэшлэх
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      // Файл тус бүрийг тусад нь нэмэх — нэг нь алдаа өгвөл бусад нь орно
      return Promise.allSettled(
        CORE_ASSETS.map((url) => cache.add(url).catch((e) => console.warn('[SW] Кэшлэж чадсангүй:', url)))
      );
    })
  );
  self.skipWaiting(); // Шинэ SW-г шууд идэвхжүүлэх
});

// Идэвхжих үед хуучин кэшийг цэвэрлэх
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(
        names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n))
      )
    )
  );
  self.clients.claim();
});

// Хүсэлт таслах — Network-first стратеги
// Эхлээд интернэтээс авах оролдоно, амжилтгүй бол кэшээс өгнө
self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Зөвхөн GET хүсэлт кэшлэх (POST зэрэг өөрчлөлт хийдэг хүсэлт биш)
  if (req.method !== 'GET') return;

  // Google API, Drive руу явах хүсэлтийг кэшлэхгүй (үргэлж шинэ байх ёстой)
  const url = new URL(req.url);
  if (url.hostname.includes('googleapis.com') ||
      url.hostname.includes('google.com') ||
      url.hostname.includes('gstatic.com')) {
    return; // Browser-ийн энгийн зан үйлээр явуулах
  }

  event.respondWith(
    fetch(req)
      .then((res) => {
        // Амжилттай бол кэшийг шинэчлэх (дараагийн offline-д зориулж)
        if (res && res.status === 200 && res.type === 'basic') {
          const resClone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
        }
        return res;
      })
      .catch(() => {
        // Интернэт байхгүй — кэшээс өгөх
        return caches.match(req).then((cached) => {
          if (cached) return cached;
          // index.html-д fallback (навигаци хүсэлтэд)
          if (req.mode === 'navigate') return caches.match('./index.html');
        });
      })
  );
});
