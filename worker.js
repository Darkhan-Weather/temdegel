const ALLOWED_ORIGINS = [
  'https://darkhan-weather.github.io',
  'http://localhost',
  'http://127.0.0.1',
];

const SECURITY_HEADERS = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const isAllowed = ALLOWED_ORIGINS.some(o => origin.startsWith(o));
    const corsOrigin = isAllowed ? origin : ALLOWED_ORIGINS[0];

    const corsHeaders = {
      'Access-Control-Allow-Origin': corsOrigin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: { ...corsHeaders, ...SECURITY_HEADERS },
      });
    }

    if (url.pathname === '/api/ai' && request.method === 'POST') {
      try {
        if (!env.AI) {
          return new Response(JSON.stringify({ error: 'Workers AI binding олдсонгүй' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders, ...SECURITY_HEADERS },
          });
        }

        const body = await request.json();
        if (!body.prompt || typeof body.prompt !== 'string') {
          return new Response(JSON.stringify({ error: 'prompt талбар шаардлагатай' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders, ...SECURITY_HEADERS },
          });
        }

        const prompt = body.prompt.slice(0, 1000);
        const systemPrompt = body.system ||
          `Та Монгол хэлний мэргэжлийн туслах.
Ажлын тайлангийн ноорог бичихэд тусалдаг.
Дүрэм:
- Монгол хэлээр бич
- Товч, албан ёсны хэлбэрээр бич (2-4 өгүүлбэр)
- Мэргэжлийн, тайлан хэлбэрт тохирсон`;

        // llama-3.1-8b 2026-05-30-д deprecated → llama-3.3-70b-instruct-fp8-fast
        const response = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: prompt },
          ],
          max_tokens: 300,
          temperature: 0.7,
        });

        return new Response(JSON.stringify({
          result: response.response,
          model: 'llama-3.3-70b-instruct-fp8-fast',
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders, ...SECURITY_HEADERS },
        });

      } catch (err) {
        return new Response(JSON.stringify({
          error: 'AI хүсэлт боловсруулахад алдаа',
          detail: err.message,
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...corsHeaders, ...SECURITY_HEADERS },
        });
      }
    }

    return new Response(JSON.stringify({
      status: 'ok',
      available: ['/api/ai (POST)'],
      ai_binding: env.AI ? 'connected' : 'MISSING',
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders, ...SECURITY_HEADERS },
    });
  },
};
