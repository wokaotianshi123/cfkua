// 极速融合版：非豆瓣请求 = 原生速度 | 豆瓣请求 = 专用高速代理
const DOUBAN_HOST = 'doubanio.com';

// cfkua 原有固定配置（提前编译，不重复创建）
const UNSAFE_HEADERS = new Set([
  "content-security-policy","x-frame-options","x-xss-protection","x-content-type-options"
]);
const STRIP_HEADERS = new Set([
  "cf-connecting-ip","x-forwarded-for","x-real-ip","client-ip","via","forwarded"
]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.slice(1);

    // ========== 1. 根路径 极速返回 ==========
    if (url.pathname === '/') {
      return new Response(getRootHtml(), { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    // ========== 2. 极速解析目标URL（只做1次！） ==========
    let target;
    try {
      target = new URL(decodeURIComponent(path) + url.search + url.hash);
    } catch {
      return new Response(null, { status: 400 });
    }

    // ========== 3. 极速判断：豆瓣域名 → 直接走高速代理 ==========
    if (target.hostname.endsWith(DOUBAN_HOST)) {
      return handleDouban(target.href, request, ctx);
    }

    // ========== 4. 非豆瓣：直接进入原生cfkua逻辑（无任何多余判断！） ==========
    return handleNormal(target, request);
  }
};

// ==========================
// 豆瓣专用极速代理（无冗余、无解析、无重写）
// ==========================
async function handleDouban(url, request, ctx) {
  const cache = caches.default;
  let res = await cache.match(request);
  
  if (!res) {
    res = await fetch(url, {
      headers: {
        'Referer': 'https://movie.douban.com/',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      },
      method: 'GET'
    });

    const headers = new Headers(res.headers);
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Cache-Control', 'public, s-maxage=31536000, max-age=86400');
    headers.delete('Set-Cookie');

    res = new Response(res.body, { status: res.status, headers });
    ctx.waitUntil(cache.put(request, res.clone()));
  }
  
  return res;
}

// ==========================
// 非豆瓣：原生cfkua逻辑（无任何修改、无额外开销）
// ==========================
async function handleNormal(targetUrl, request) {
  const reqURL = new URL(request.url);

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS,PATCH",
        "Access-Control-Allow-Headers": "*"
      }
    });
  }

  const newHeaders = new Headers();
  for (const [k, v] of request.headers) {
    const lk = k.toLowerCase();
    if (lk.startsWith('cf-') || lk.startsWith('sec-') || lk === 'cookie' || STRIP_HEADERS.has(lk)) continue;
    newHeaders.set(k, v);
  }
  if (!newHeaders.has('User-Agent')) newHeaders.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36');
  newHeaders.set('Host', targetUrl.hostname);

  const ref = request.headers.get('Referer');
  if (ref && ref.startsWith(reqURL.origin)) {
    try {
      const p = new URL(decodeURIComponent(ref.slice(reqURL.origin.length + 1)));
      newHeaders.set('Referer', p.href);
    } catch {}
  }

  let res = await fetch(targetUrl.href, {
    method: request.method,
    headers: newHeaders,
    body: request.body,
    redirect: 'manual'
  });

  const respHeaders = new Headers(res.headers);
  UNSAFE_HEADERS.forEach(h => respHeaders.delete(h));
  respHeaders.set('Access-Control-Allow-Origin', '*');
  respHeaders.set('Access-Control-Allow-Credentials', 'true');

  const loc = respHeaders.get('Location');
  if (loc) {
    try { respHeaders.set('Location', reqURL.origin + '/' + encodeURIComponent(new URL(loc, targetUrl).href)); } catch {}
  }

  const ct = respHeaders.get('Content-Type') || '';

  // M3U8
  if (ct.includes('mpegurl') || targetUrl.pathname.endsWith('.m3u8')) {
    const t = await res.text();
    const base = targetUrl.href.substring(0, targetUrl.href.lastIndexOf('/') + 1);
    return new Response(t.replace(/^(?!#)(.+)$/gm, m => {
      try { return reqURL.origin + '/' + (m.startsWith('http') ? m : new URL(m, base).href); } catch { return m; }
    }), { status: res.status, headers: respHeaders });
  }

  // HTML
  if (ct.includes('text/html')) {
    return new HTMLRewriter()
      .on('head', { element(e) { e.append(`<script>((P,B)=>(W=u=>u&&!u.startsWith(P)&&!/^data|blob|javascript:/.test(u)?P+'/'+new URL(u,B).href:u)&&(history.pushState=history.replaceState=function(){arguments[2]&&(arguments[2]=W(arguments[2]));return this.apply(history,arguments)},XMLHttpRequest.prototype.open=function(m,u,...a){return this.open(m,W(u),...a)},window.fetch=(i,n)=>fetch(W(i),n)))('${reqURL.origin}','${targetUrl.href}')</script>`, { html: true }); }})
      .on('a,img,link,script,iframe,video,audio,source,form,object,base', new AttrRewriter(reqURL.origin, targetUrl.href))
      .on('meta', new MetaRewriter(reqURL.origin, targetUrl.href))
      .transform(new Response(res.body, { status: res.status, headers: respHeaders }));
  }

  return new Response(res.body, { status: res.status, headers: respHeaders });
}

// 工具类（极简）
class AttrRewriter {
  constructor(p, t) { this.p = p; this.t = t; }
  element(e) {
    const a = e.tagName === 'A' || e.tagName === 'LINK' ? 'href' : 'src';
    const v = e.getAttribute(a);
    if (v && !/^(data|#|javascript):/.test(v)) e.setAttribute(a, this.p + '/' + new URL(v, this.t).href);
  }
}
class MetaRewriter {
  constructor(p, t) { this.p = p; this.t = t; }
  element(e) {
    if (e.getAttribute('http-equiv')?.toLowerCase() === 'refresh') {
      const c = e.getAttribute('content');
      const m = c.match(/url\s*=\s*['"]?([^'";]+)/i);
      if (m) e.setAttribute('content', c.replace(m[1], this.p + '/' + new URL(m[1], this.t).href));
    }
  }
}

// 首页HTML
function getRootHtml() {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>Proxy</title>
<style>body{margin:0;padding:2rem;display:grid;place-items:center;font-family:system-ui}input{width:100%;max-width:420px;padding:12px;margin:1rem 0}button{padding:12px 24px;background:#0070f3;color:white;border:none;border-radius:6px}</style>
</head>
<body>
<input id="u" placeholder="URL" type="url">
<button onclick="window.open(location.origin+'/'+encodeURIComponent(document.getElementById('u').value))">GO</button>
</body>
</html>`;
}
