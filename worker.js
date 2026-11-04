// ХСТИ AI proxy — Cloudflare Worker (odd-breeze-d4e0)
// 2026-10-07 (F22): Зөвхөн ХСТИ аппаар нэвтэрсэн Google хэрэглэгчийн хүсэлтийг хүлээн авна.
// Урьд нь URL-ийг мэдсэн хэн ч (curl, өөр сайт) AI-г дуудаж, үнэгүй квотыг дуусгах боломжтой байв.
//
// Тохиргоо (Settings → Variables and Secrets):
//   GOOGLE_CLIENT_SECRET (Secret) — Refresh token-д заавал. Google Cloud → Credentials → OAuth client
//   REFRESH_ENC_KEY      (Secret) — Refresh token шифрлэх 32 байт түлхүүр (base64)
//   EXTRA_CLIENT_IDS — өөр апп (жишээ нь Homebook)-ын Google OAuth client ID, таслалаар (/api/ai-д)
//   ALLOWED_SUBS     — зөвхөн эдгээр Google хэрэглэгч (sub) ашиглана, таслалаар. Хоосон бол аппаар нэвтэрсэн хэн ч.
//
// Refresh token (2026-10-07): /auth/exchange, /auth/refresh, /auth/revoke, /auth/status
//   Браузер нэг удаа popup-аар "код" авч Worker-т өгнө → Worker client_secret-ээр refresh token авна →
//   refresh token-ийг REFRESH_ENC_KEY-ээр шифрлэж браузерт буцаана (браузер задалж чадахгүй).
//   Дараа нь access token дуусах бүрт браузер шифрлэгдсэн хайрцгаа илгээж, шинэ token авна — popup-гүй.

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

function rateLimited(sub, limit = RATE_LIMIT) {
  const now = Date.now();
  const arr = (rateMap.get(sub) || []).filter(t => now - t < RATE_WINDOW_MS);
  if (arr.length >= limit) { rateMap.set(sub, arr); return true; }
  arr.push(now);
  rateMap.set(sub, arr);
  if (rateMap.size > 1000) rateMap.clear();
  return false;
}

// ── Refresh token шифрлэлт (AES-GCM 256) ─────────────────────
const b64u = {
  enc: (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
};
let _encKey = null, _encKeySrc = '';
async function encKey(env) {
  if (_encKey && _encKeySrc === env.REFRESH_ENC_KEY) return _encKey;
  const raw = Uint8Array.from(atob(env.REFRESH_ENC_KEY), c => c.charCodeAt(0));
  if (raw.length !== 32) throw new Error('REFRESH_ENC_KEY 32 байт байх ёстой');
  _encKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  _encKeySrc = env.REFRESH_ENC_KEY;
  return _encKey;
}
const AAD = new TextEncoder().encode('hsti-rt-v1:' + HSTI_CLIENT_ID);
async function sealRt(env, payload) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, await encKey(env),
    new TextEncoder().encode(JSON.stringify(payload))));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
  return 'v1.' + b64u.enc(out);
}
async function openRt(env, blob) {
  if (typeof blob !== 'string' || !blob.startsWith('v1.') || blob.length > 4000) return null;
  try {
    const all = b64u.dec(blob.slice(3));
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: all.slice(0, 12), additionalData: AAD }, await encKey(env), all.slice(12));
    const p = JSON.parse(new TextDecoder().decode(pt));
    return (p && typeof p.rt === 'string') ? p : null;
  } catch (_) { return null; }
}
const refreshConfigured = (env) => !!(env.GOOGLE_CLIENT_SECRET && env.REFRESH_ENC_KEY);

// ── AI session token (N01) ───────────────────────────────────
// /api/ai-д Google (Drive/Calendar эрхтэй) token илгээхгүйн тулд Worker өөрийн богино хугацааны
// (1 цаг), ЗӨВХӨН AI-д хүчинтэй түлхүүр гаргана: "a1.<payload>.<HMAC-SHA256>". REFRESH_ENC_KEY-ээс
// тусдаа (domain-separated) HMAC түлхүүр гаргана. Тохируулаагүй бол хуучин Bearer арга ажилласаар.
const AI_TTL_SEC = 3600;
let _aiKey = null, _aiKeySrc = '';
async function aiKey(env) {
  if (_aiKey && _aiKeySrc === env.REFRESH_ENC_KEY) return _aiKey;
  const raw = Uint8Array.from(atob(env.REFRESH_ENC_KEY), c => c.charCodeAt(0));
  const tag = new TextEncoder().encode('hsti-ai-session-v1');
  const mat = new Uint8Array(tag.length + raw.length); mat.set(tag); mat.set(raw, tag.length);
  const derived = await crypto.subtle.digest('SHA-256', mat);
  _aiKey = await crypto.subtle.importKey('raw', derived, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  _aiKeySrc = env.REFRESH_ENC_KEY;
  return _aiKey;
}
async function issueAiToken(env, sub) {
  if (!env.REFRESH_ENC_KEY) return null;
  const payload = b64u.enc(new TextEncoder().encode(JSON.stringify({ sub, exp: Math.floor(Date.now() / 1000) + AI_TTL_SEC })));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await aiKey(env), new TextEncoder().encode('a1.' + payload)));
  return 'a1.' + payload + '.' + b64u.enc(sig);
}
async function verifyAiToken(env, tok) {
  if (!env.REFRESH_ENC_KEY || typeof tok !== 'string' || tok.length > 1000) return null;
  const parts = tok.split('.');
  if (parts.length !== 3 || parts[0] !== 'a1') return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await aiKey(env), b64u.dec(parts[2]), new TextEncoder().encode('a1.' + parts[1]));
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(b64u.dec(parts[1])));
    if (!p || typeof p.exp !== 'number' || p.exp * 1000 < Date.now()) return null;
    return { sub: String(p.sub || '') };
  } catch (_) { return null; }
}

async function googleToken(params) {
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  let data = {}; try { data = await r.json(); } catch (_) {}
  return { ok: r.ok, status: r.status, data };
}

async function handleAuth(path, request, env, json) {
  if (path === '/auth/status') return json({ refresh: refreshConfigured(env) });
  if (request.method !== 'POST') return json({ error: 'POST шаардлагатай' }, 405);
  if (path === '/auth/ai-session') {
    // Refresh token-гүй (popup) нэвтрэлтэд: Google token-оор НЭГ удаа AI түлхүүр авна
    if (request.headers.get('X-Requested-With') !== 'XmlHttpRequest') return json({ error: 'Буруу хүсэлт' }, 400);
    if (!env.REFRESH_ENC_KEY) return json({ error: 'AI session тохируулагдаагүй' }, 501);
    const auth = request.headers.get('Authorization') || '';
    const v = await verifyGoogleToken(auth.startsWith('Bearer ') ? auth.slice(7).trim() : '', env);
    if (!v.ok) return json({ error: v.error }, v.status);
    return json({ ai_token: await issueAiToken(env, v.sub), expires_in: AI_TTL_SEC });
  }
  if (!refreshConfigured(env)) return json({ error: 'Refresh token тохируулагдаагүй' }, 501);
  // Google-ийн зөвлөмж: код хүлээн авах endpoint-д X-Requested-With шалгах (CSRF)
  if (request.headers.get('X-Requested-With') !== 'XmlHttpRequest') return json({ error: 'Буруу хүсэлт' }, 400);
  const len = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (len > 8000) return json({ error: 'Хүсэлт хэт том' }, 413);
  let body; try { body = await request.json(); } catch (_) { return json({ error: 'JSON биш' }, 400); }
  const allowedSubs = csv(env.ALLOWED_SUBS);

  if (path === '/auth/exchange') {
    if (typeof body.code !== 'string' || !body.code || body.code.length > 2000) return json({ error: 'code шаардлагатай' }, 400);
    const t = await googleToken({
      code: body.code, client_id: HSTI_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: 'postmessage', grant_type: 'authorization_code',
    });
    if (!t.ok || !t.data.access_token) return json({ error: t.data.error || 'Код солилцож чадсангүй' }, 400);
    // Хэрэглэгчийг тодорхойлох (refresh token-ийг энэ хэрэглэгчтэй холбоно)
    const u = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', { headers: { Authorization: 'Bearer ' + t.data.access_token } });
    const sub = u.ok ? ((await u.json()).sub || '') : '';
    if (allowedSubs.length && !allowedSubs.includes(sub)) return json({ error: 'Энэ хэрэглэгчид зөвшөөрөлгүй' }, 403);
    const rt = t.data.refresh_token ? await sealRt(env, { rt: t.data.refresh_token, sub, iat: Date.now() }) : null;
    return json({ access_token: t.data.access_token, expires_in: t.data.expires_in || 3600, rt, ai_token: await issueAiToken(env, sub), ai_expires_in: AI_TTL_SEC });
  }

  const p = await openRt(env, body.rt);
  if (!p) return json({ error: 'invalid_rt' }, 401);

  if (path === '/auth/refresh') {
    if (allowedSubs.length && !allowedSubs.includes(p.sub)) return json({ error: 'Энэ хэрэглэгчид зөвшөөрөлгүй' }, 403);
    if (rateLimited('rt:' + (p.sub || 'anon'), 60)) return json({ error: 'Хэт олон хүсэлт' }, 429);
    const t = await googleToken({
      refresh_token: p.rt, client_id: HSTI_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, grant_type: 'refresh_token',
    });
    // invalid_grant = хэрэглэгч эрх цуцалсан / Testing горимд 7 хоног өнгөрсөн → браузер хайрцгаа устгана
    if (!t.ok || !t.data.access_token) return json({ error: t.data.error || 'refresh_failed' }, t.data.error === 'invalid_grant' ? 401 : 502);
    return json({ access_token: t.data.access_token, expires_in: t.data.expires_in || 3600, ai_token: await issueAiToken(env, p.sub), ai_expires_in: AI_TTL_SEC });
  }

  if (path === '/auth/revoke') {
    await fetch('https://oauth2.googleapis.com/revoke', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: p.rt }).toString(),
    }).catch(() => {});
    return json({ ok: true });
  }
  return json({ error: 'Олдсонгүй' }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const originOk = isAllowedOrigin(origin);

    const corsHeaders = {
      'Access-Control-Allow-Origin': originOk ? origin : 'https://darkhan-weather.github.io',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
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

    if (url.pathname.startsWith('/auth/')) {
      if (!originOk) return json({ error: 'Зөвшөөрөгдөөгүй эх сурвалж' }, 403);
      try { return await handleAuth(url.pathname, request, env, json); }
      catch (e) { console.error('auth', e); return json({ error: 'Нэвтрэлтийн алдаа' }, 500); }
    }

    if (url.pathname === '/api/ai' && request.method === 'POST') {
      // 1. Зөвхөн зөвшөөрөгдсөн сайтаас (браузер Origin-ийг хуурамчаар илгээж чадахгүй)
      if (!originOk) return json({ error: 'Зөвшөөрөгдөөгүй эх сурвалж' }, 403);

      // 2. Нэвтрэлт: AI session token (зөвлөмж) эсвэл Google token (хуучин хувилбарт нийцтэй)
      const auth = request.headers.get('Authorization') || '';
      let v;
      if (auth.startsWith('AI ')) {
        const s = await verifyAiToken(env, auth.slice(3).trim());
        if (!s) return json({ error: 'AI түлхүүр хүчингүй эсвэл хугацаа дууссан' }, 401);
        const allowedSubs = csv(env.ALLOWED_SUBS);
        if (allowedSubs.length && !allowedSubs.includes(s.sub)) return json({ error: 'Энэ хэрэглэгчид зөвшөөрөлгүй' }, 403);
        v = { ok: true, sub: s.sub };
      } else {
        const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
        try { v = await verifyGoogleToken(token, env); }
        catch (e) { console.error('verify', e); return json({ error: 'Нэвтрэлт шалгаж чадсангүй' }, 502); }
        if (!v.ok) return json({ error: v.error }, v.status);
      }

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

    return json({ status: 'ok', refresh: refreshConfigured(env), available: ['/api/ai (POST, Authorization: Bearer <Google token>)', '/auth/status', '/auth/ai-session', '/auth/exchange', '/auth/refresh', '/auth/revoke'] });
  },
};
