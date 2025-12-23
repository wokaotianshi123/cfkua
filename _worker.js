
/**
 * Cloudflare Worker Proxy Everything
 * 功能：
 * 1. CORS 跨域代理
 * 2. M3U8 视频流路径重写 (支持相对/绝对路径)
 * 3. HTML 内容动态注入劫持代码，重写资源链接
 * 4. IP 地址伪装：随机生成 X-Forwarded-For 等头部
 */

// 想要移除的响应头 (解决 CSP, Frame 限制等问题)
const UNSAFE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-xss-protection",
  "x-content-type-options"
]);

// 生成随机 IP 地址的函数
function generateRandomIp() {
  return Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join('.');
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. 访问根目录，返回 UI
    if (url.pathname === "/") {
      return new Response(getRootHtml(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // 2. 解析目标 URL
    let path = url.pathname.slice(1);
    try {
      path = decodeURIComponent(path);
    } catch (e) {}

    let actualUrlStr = path + url.search + url.hash;

    // 2.1 修正协议格式
    if (actualUrlStr.startsWith("http") && !actualUrlStr.startsWith("http://") && !actualUrlStr.startsWith("https://")) {
      actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    // 2.2 处理相对路径请求 (通过 Referer 恢复)
    if (!actualUrlStr.startsWith("http")) {
      const referer = request.headers.get("Referer");
      if (referer) {
        try {
          const refererObj = new URL(referer);
          if (refererObj.origin === url.origin) {
            let refererPath = refererObj.pathname.slice(1);
            try { refererPath = decodeURIComponent(refererPath); } catch (e) {}

            let refererTargetStr = refererPath + refererObj.search;
            if (refererTargetStr.startsWith("http") && !refererTargetStr.startsWith("http://") && !refererTargetStr.startsWith("https://")) {
              refererTargetStr = refererTargetStr.replace(/^(https?):\/+/, "$1://");
            }

            if (refererTargetStr.startsWith("http")) {
              const targetBase = new URL(refererTargetStr);
              actualUrlStr = new URL(url.pathname + url.search + url.hash, targetBase.href).href;
            }
          }
        } catch (e) {}
      }
    }

    // 3. 处理 OPTIONS 预检请求
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
          "Access-Control-Allow-Headers": "*"
        }
      });
    }

    // 4. 准备代理请求
    let targetUrl;
    try {
      if (!actualUrlStr.startsWith("http")) {
        return new Response("Invalid URL (No Protocol): " + actualUrlStr, { status: 400 });
      }
      targetUrl = new URL(actualUrlStr);
    } catch (e) {
      return new Response("Invalid URL Parse Error: " + actualUrlStr, { status: 400 });
    }

    const newHeaders = new Headers();
    const isSafeMethod = ["GET", "HEAD", "OPTIONS"].includes(request.method);

    // 复制原请求头，过滤特定头部
    for (const [key, value] of request.headers) {
      const lowerKey = key.toLowerCase();
      if (lowerKey.startsWith("cf-") ||
        lowerKey.startsWith("sec-") ||
        lowerKey === "cookie") {
        continue;
      }
      newHeaders.set(key, value);
    }

    // 设置默认 User-Agent
    if (!newHeaders.has("User-Agent")) {
      newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36");
    }

    // --- 核心修改：IP 地址更换/伪装 ---
    const randomIp = generateRandomIp();
    newHeaders.set("X-Forwarded-For", randomIp);
    newHeaders.set("X-Real-IP", randomIp);
    newHeaders.set("True-Client-IP", randomIp);
    newHeaders.set("Client-IP", randomIp);
    // ---------------------------------

    newHeaders.set("Host", targetUrl.host);
    if (!isSafeMethod) {
      newHeaders.set("Origin", targetUrl.origin);
    }

    // 智能 Referer 处理
    const clientReferer = request.headers.get("Referer");
    if (clientReferer && clientReferer.startsWith(url.origin)) {
      const realRefererPart = clientReferer.slice(url.origin.length + 1);
      let decodedReferer = realRefererPart;
      try { decodedReferer = decodeURIComponent(realRefererPart); } catch (e) {}
      if (decodedReferer.startsWith("http")) {
        newHeaders.set("Referer", decodedReferer);
      }
    }

    // 5. 发起请求
    let response;
    try {
      response = await fetch(actualUrlStr, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: "manual"
      });
    } catch (e) {
      return new Response("Proxy Fetch Error: " + e.message, { status: 502 });
    }

    // 6. 处理响应头
    const responseHeaders = new Headers(response.headers);
    UNSAFE_HEADERS.forEach(h => responseHeaders.delete(h));

    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Credentials", "true");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

    // 重写 Location
    const location = responseHeaders.get("Location");
    if (location) {
      try {
        const absoluteLocation = new URL(location, targetUrl.href).href;
        responseHeaders.set("Location", url.origin + "/" + encodeURIComponent(absoluteLocation));
      } catch (e) {}
    }

    const contentType = responseHeaders.get("Content-Type") || "";

    // 7. 内容处理
    // A. M3U8 视频流处理
    if (contentType.includes("application/vnd.apple.mpegurl") ||
      contentType.includes("application/x-mpegurl") ||
      actualUrlStr.endsWith(".m3u8")) {

      let text = await response.text();
      const baseUrl = actualUrlStr.substring(0, actualUrlStr.lastIndexOf("/") + 1);

      text = text.replace(/^(?!#)(?!\s)(.+)$/gm, (match) => {
        match = match.trim();
        if (match === "") return match;
        try {
          const absoluteUrl = match.startsWith("http") ? match : new URL(match, baseUrl).href;
          return url.origin + "/" + absoluteUrl;
        } catch (e) {
          return match;
        }
      });

      return new Response(text, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      });
    }

    // B. HTML 内容重写
    if (contentType.includes("text/html")) {
      const rewriter = new HTMLRewriter()
        .on("head", {
          element(element) {
            element.append(`
            <script>
              (function() {
                const PROXY_ORIGIN = window.location.origin;
                const REAL_BASE_URL = '${targetUrl.href}';
                function wrapUrl(u) {
                    if (!u || u.startsWith(PROXY_ORIGIN) || /^(data:|blob:|javascript:)/.test(u)) return u;
                    try {
                        return PROXY_ORIGIN + '/' + new URL(u, REAL_BASE_URL).href;
                    } catch(e) { return u; }
                }
                const oldPushState = history.pushState;
                const oldReplaceState = history.replaceState;
                history.pushState = function(...args) {
                    if (args[2]) args[2] = wrapUrl(args[2]);
                    return oldPushState.apply(this, args);
                };
                history.replaceState = function(...args) {
                    if (args[2]) args[2] = wrapUrl(args[2]);
                    return oldReplaceState.apply(this, args);
                };
                const oldFetch = window.fetch;
                window.fetch = function(input, init) {
                    if (typeof input === 'string') input = wrapUrl(input);
                    return oldFetch(input, init);
                };
                const oldOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(m, u, ...a) {
                    return oldOpen.call(this, m, wrapUrl(u), ...a);
                };
              })();
            </script>`, { html: true });
          }
        })
        .on("a", new AttributeRewriter("href", url.origin, targetUrl.href))
        .on("img", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("link", new AttributeRewriter("href", url.origin, targetUrl.href))
        .on("script", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("form", new AttributeRewriter("action", url.origin, targetUrl.href))
        .on("iframe", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("video", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("audio", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("source", new AttributeRewriter("src", url.origin, targetUrl.href))
        .on("object", new AttributeRewriter("data", url.origin, targetUrl.href))
        .on("base", new AttributeRewriter("href", url.origin, targetUrl.href));

      return rewriter.transform(new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      }));
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  }
};

class AttributeRewriter {
  constructor(attributeName, proxyOrigin, currentTargetUrl) {
    this.attributeName = attributeName;
    this.proxyOrigin = proxyOrigin;
    this.currentTargetUrl = currentTargetUrl;
  }
  element(element) {
    const value = element.getAttribute(this.attributeName);
    if (value && !/^(data:|#|javascript:)/.test(value)) {
      try {
        const resolvedUrl = new URL(value, this.currentTargetUrl).href;
        element.setAttribute(this.attributeName, this.proxyOrigin + "/" + resolvedUrl);
      } catch (e) {}
    }
    if (element.tagName === "img" && element.hasAttribute("srcset")) {
      const srcset = element.getAttribute("srcset");
      const newSrcset = srcset.split(",").map(part => {
        const [u, d] = part.trim().split(/\s+/);
        try {
          return this.proxyOrigin + "/" + new URL(u, this.currentTargetUrl).href + (d ? " " + d : "");
        } catch (e) { return part; }
      }).join(", ");
      element.setAttribute("srcset", newSrcset);
    }
  }
}

function getRootHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <link href="https://s4.zstatic.net/ajax/libs/materialize/1.0.0/css/materialize.min.css" rel="stylesheet">
  <title>Proxy Everything (IP Randomized)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
      body { background-color: #f5f5f5; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
      .card { width: 100%; max-width: 500px; padding: 20px; border-radius: 12px; }
      @media (prefers-color-scheme: dark) {
          body { background-color: #121212; color: white; }
          .card { background-color: #1e1e1e; color: white; }
          input { color: white !important; }
      }
  </style>
</head>
<body>
  <div class="card z-depth-3">
      <h5 class="center-align">Proxy Everything</h5>
      <p class="center-align grey-text" style="font-size: 0.9rem;">CORS Bypass + M3U8 Rewrite + Random IP</p>
      <div class="input-field">
          <input type="text" id="targetUrl" placeholder="https://example.com" required>
          <label for="targetUrl">目标 URL</label>
      </div>
      <button onclick="go()" class="btn waves-effect waves-light teal darken-2 full-width" style="width:100%">立即访问</button>
  </div>
  <script>
      function go() {
          const url = document.getElementById('targetUrl').value.trim();
          if(!url) return;
          window.open(window.location.origin + '/' + encodeURIComponent(url), '_blank');
      }
      document.getElementById('targetUrl').addEventListener('keypress', (e) => { if(e.key === 'Enter') go(); });
  </script>
</body>
</html>`;
}
