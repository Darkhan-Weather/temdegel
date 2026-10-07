// ХСТИ AI proxy — Cloudflare Worker (odd-breeze-d4e0)
// 2026-10-07 (F22): Зөвхөн ХСТИ аппаар нэвтэрсэн Google хэрэглэгчийн хүсэлтийг хүлээн авна.
// Урьд нь URL-ийг мэдсэн хэн ч (curl, өөр сайт) AI-г дуудаж, үнэгүй квотыг дуусгах боломжтой байв.
//
// Тохиргоо (Settings → Variables, заавал биш):
//   EXTRA_CLIENT_IDS — өөр апп (жишээ нь Homebook)-ын Google OAuth client ID, таслалаар
//   ALLOWED_SUBS     — зөвхөн эдгээр Google хэрэглэгч (sub) ашиглана, таслалаар. Хоосон бол аппаар нэвтэрсэн хэн ч.

const HSTI_CLIENT_ID = '318160635801-6970fmqoqafpp6j9nm216skqe0945fvm.apps.googleusercontent.com';

// Origin-ийг ЯГ таарахаар шалгана (startsWith нь "https://darkhan-weather.github.io.evil.com"-г ч зөвшөөрдөг байв)
const ALLOWED_ORIGINS = new Set(['https://darkhan-weather.github.io']);
const LOCAL_ORIGIN_RE = /^http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/;
const isAllowedOrigin = (o) => ALLOWED_ORIGINS.has(o) || LOCAL_ORIGIN_RE.test(o);

const SECURITY_HEADERS = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
};

const MAX_BODY_BYTES = 20000;
const RATE_LIMIT = 30;                 // хэрэглэгч бүрт...
const RATE_WINDOW_MS = 10 * 60 * 1000; // ...10 минутад

// Isolate доторх кэш (Worker дахин эхлэхэд цэвэрлэгдэнэ — зөвхөн хурдасгах зорилготой)
const tokenCache = new Map(); // sha256(token) → {sub, exp}
const rateMap = new Map();    // sub → [timestamps]

function csv(v) { return String(v || '').split(',').map(s => s.trim()).filter(Boolean); }

async function sha256(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Google access token-ийг шалгах. Буцаах: {ok:true, sub} | {ok:false, status, error}
async function verifyGoogleToken(token, env) {
  if (!token || token.length > 4096) return { ok: false, status: 401, error: 'Нэвтрэлт шаардлагатай' };
  const key = await sha256(token);
  const now = Date.now();
  const allowedSubs = csv(env.ALLOWED_SUBS);
  const subOk = (sub) => !allowedSubs.length || allowedSubs.includes(sub);
  const hit = tokenCache.get(key);
  if (hit && hit.exp > now) {
    return subOk(hit.sub) ? { ok: true, sub: hit.sub } : { ok: false, status: 403, error: 'Энэ хэрэглэгчид зөвшөөрөлгүй' };
  }

  const r = await fetch('https://oauth2.googleapis.com/tokeninfo?access_token=' + encodeURIComponent(token));
  if (!r.ok) return { ok: false, status: 401, error: 'Token хүчингүй эсвэл хугацаа дууссан' };
  const info = await r.json();

  const clients = [HSTI_CLIENT_ID, ...csv(env.EXTRA_CLIENT_IDS)];
  if (!clients.includes(info.aud) && !clients.includes(info.azp)) {
    return { ok: false, status: 403, error: 'Энэ апп-ын token биш' };
  }
  const expiresIn = parseInt(info.expires_in || '0', 10);
  if (!(expiresIn > 0)) return { ok: false, status: 401, error: 'Token хугацаа дууссан' };

  let sub = info.sub || '';
  if (!sub) {
    // Зарим token-ийн tokeninfo-д sub ирэхгүй байж болно — userinfo-оос авна
    const u = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', { headers: { Authorization: 'Bearer ' + token } });
    if (u.ok) sub = (await u.json()).sub || '';
  }
  if (tokenCache.size > 500) tokenCache.clear();
  tokenCache.set(key, { sub, exp: now + Math.min(expiresIn * 1000, 10 * 60 * 1000) });
  if (!subOk(sub)) return { ok: false, status: 403, error: 'Энэ хэрэглэгчид зөвшөөрөлгүй' };
  return { ok: true, sub };
}

function rateLimited(sub) {
  const now = Date.now();
  const arr = (rateMap.get(sub) || []).filter(t => now - t < RATE_WINDOW_MS);
  if (arr.length >= RATE_LIMIT) { rateMap.set(sub, arr); return true; }
  arr.push(now);
  rateMap.set(sub, arr);
  if (rateMap.size > 1000) rateMap.clear();
  return false;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const originOk = isAllowedOrigin(origin);

    const corsHeaders = {
      'Access-Control-Allow-Origin': originOk ? origin : 'https://darkhan-weather.github.io',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin',
    };
    const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
      status,
      headers: { 'Content-Type': 'application/json', ...corsHeaders, ...SECURITY_HEADERS },
    });

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: originOk ? 204 : 403, headers: { ...corsHeaders, ...SECURITY_HEADERS } });
    }

    if (url.pathname === '/api/ai' && request.method === 'POST') {
      // 1. Зөвхөн зөвшөөрөгдсөн сайтаас (браузер Origin-ийг хуурамчаар илгээж чадахгүй)
      if (!originOk) return json({ error: 'Зөвшөөрөгдөөгүй эх сурвалж' }, 403);

      // 2. Google token
      const auth = request.headers.get('Authorization') || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
      let v;
      try { v = await verifyGoogleToken(token, env); }
      catch (e) { console.error('verify', e); return json({ error: 'Нэвтрэлт шалгаж чадсангүй' }, 502); }
      if (!v.ok) return json({ error: v.error }, v.status);

      // 3. Хэт олон хүсэлт
      if (rateLimited(v.sub || 'anon')) return json({ error: 'Хэт олон хүсэлт — хэдэн минутын дараа дахин оролдоно уу' }, 429);

      try {
        if (!env.AI) return json({ error: 'Workers AI binding олдсонгүй' }, 500);

        const len = parseInt(request.headers.get('Content-Length') || '0', 10);
        if (len > MAX_BODY_BYTES) return json({ error: 'Хүсэлт хэт том' }, 413);
        const body = await request.json();
        if (!body || typeof body.prompt !== 'string' || !body.prompt.trim()) {
          return json({ error: 'prompt талбар шаардлагатай' }, 400);
        }

        const prompt = body.prompt.slice(0, 1500);
        const systemPrompt = (typeof body.system === 'string' && body.system.trim())
          ? body.system.slice(0, 2000)
          :
`Чи бол албан байгууллагын ажлын тайлан бичдэг Монгол хэлний мэргэжлийн редактор.

Даалгавар: Хэрэглэгч чамд хийсэн ажлуудынхаа жагсаалтыг өгнө.
Чи түүнийг ЖАГСААЛТ хэлбэрээр БУЦААХГҮЙ.
Харин нэг эвлэг, урсгал сайтай, албан ёсны ТАЙЛАНГИЙН ДОГОЛ МӨР болгон нэгтгэж бичнэ.

Дүрэм:
- Ажлуудыг холбоос үг (мөн, түүнчлэн, дараа нь, улмаар, зэрэг) ашиглан нэг догол мөр болгож урсгалтай холбо
- Үг үсэг, найруулгын алдааг зас
- Албан ёсны, тайлангийн хэв маягаар бич ("...хийж гүйцэтгэсэн", "...ажлыг зохион байгууллаа" гэх мэт)
- Дугаарлахгүй, тэмдэглэгээ (1. 2. 3.) хийхгүй — цэлмэг догол мөр
- Үр дүнг байгаа бол дүгнэлт хэсэгт эвлэгээр оруул
- 3-6 өгүүлбэрт багтаа
- Зөвхөн эцсийн догол мөрийг л буцаа, өөр тайлбар бичихгүй`;

        const response = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: prompt },
          ],
          max_tokens: 500,
          temperature: 0.5,
        });

        return json({ result: response.response, model: 'llama-3.3-70b-instruct-fp8-fast' });
      } catch (err) {
        console.error('AI', err);
        return json({ error: 'AI хүсэлт боловсруулахад алдаа' }, 500);
      }
    }

    return json({ status: 'ok', available: ['/api/ai (POST, Authorization: Bearer <Google token>)'] });
  },
};
