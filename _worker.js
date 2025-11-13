// _worker.js
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request);
  }
};

async function handleRequest(request) {
  try {
    const url = new URL(request.url);

    // ---------- 1. 首页 ----------
    if (url.pathname === '/') {
      return new Response(getRootHtml(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // ---------- 2. Base64 短跳 ----------
    if (url.pathname.startsWith('/b64/')) {
      const b64 = url.pathname.replace('/b64/', '').replace(/\/.*/, ''); // 取第一段
      try {
        const target = atob(b64);               // 解码
        const withSearch = target + url.search; // 保留 query
        return Response.redirect(withSearch, 302);
      } catch {
        return jsonResponse({ error: 'Invalid Base64' }, 400);
      }
    }

    // ---------- 3. 原有代理逻辑 ----------
    let actualUrlStr = decodeURIComponent(url.pathname.slice(1));
    actualUrlStr = ensureProtocol(actualUrlStr, url.protocol);
    actualUrlStr += url.search;

    const newHeaders = filterHeaders(request.headers, n => !n.startsWith('cf-'));
    const modifiedRequest = new Request(actualUrlStr, {
      headers: newHeaders,
      method: request.method,
      body: request.body,
      redirect: 'manual'
    });

    const response = await fetch(modifiedRequest);
    let body = response.body;

    if ([301,302,303,307,308].includes(response.status)) {
      return handleRedirect(response, body);
    }
    if (response.headers.get('Content-Type')?.includes('text/html')) {
      body = await handleHtmlContent(response, url.protocol, url.host, actualUrlStr);
    }

    const res = new Response(body, response);
    setNoCacheHeaders(res.headers);
    setCorsHeaders(res.headers);
    return res;

  } catch (e) {
    return jsonResponse({ error: e.message }, 500);
  }
}

/* ------------ 工具函数（保持原样） ------------ */
function ensureProtocol(u, def) {
  return /^https?:\/\//.test(u) ? u : def + '//' + u;
}
function handleRedirect(r, b) {
  const loc = new URL(r.headers.get('location'));
  return new Response(b, {
    status: r.status,
    statusText: r.statusText,
    headers: { ...r.headers, 'Location': `/${encodeURIComponent(loc)}` }
  });
}
async function handleHtmlContent(r, proto, host, actual) {
  const text = await r.text();
  return text.replace(
    /((href|src|action)=["'])\/(?!\/)/g,
    `$1${proto}//${host}/${new URL(actual).origin}/`
  );
}
function jsonResponse(d, s) {
  return new Response(JSON.stringify(d), {
    status: s,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}
function filterHeaders(h, f) {
  return new Headers([...h].filter(([n]) => f(n)));
}
function setNoCacheHeaders(h) {
  h.set('Cache-Control', 'no-store');
}
function setCorsHeaders(h) {
  h.set('Access-Control-Allow-Origin', '*');
  h.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  h.set('Access-Control-Allow-Headers', '*');
}
function getRootHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>Proxy Everything – Base64 版</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://s4.zstatic.net/ajax/libs/materialize/1.0.0/css/materialize.min.css" rel="stylesheet">
  <style>
    body{display:flex;height:100vh;align-items:center;justify-content:center;background:#f5f5f5}
    .card{width:100%;max-width:420px}
  </style>
</head>
<body>
  <div class="card">
    <div class="card-content">
      <span class="card-title center-align">Proxy Everything</span>
      <form id="form">
        <div class="input-field">
          <input id="target" type="text" placeholder="https://example.com" required>
          <label for="target">目标地址</label>
        </div>
        <button type="submit" class="btn waves-effect waves-light teal darken-2 full-width">跳转</button>
      </form>
    </div>
  </div>
  <script>
    document.getElementById('form').onsubmit = e => {
      e.preventDefault();
      const target = document.getElementById('target').value.trim();
      if (!target) return;
      const b64 = btoa(target);                      // 编码
      const url = window.location.origin + '/b64/' + b64;
      window.open(url, '_blank');
    };
  </script>
</body>
</html>`;
}
